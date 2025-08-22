use argh::FromArgs;
use shared::{
	client_api::Api,
	id::Uid,
	mpc_math, password_lock,
	salt::Salt,
	serialize,
	share::{Bundle, NonceComm, Part, SignFinal, SignReq, SignupReq, SignupRes},
	tokio, Scalar, Verifier, VerifyingKey,
};

use std::{fs, str::FromStr};

const DKG_T: u32 = 2;
const DKG_N: u32 = 2;

#[derive(Debug)]
pub enum Error {
	Io(String),
	BadShare,
	BadComm,
	Protocol { ctx: String },
	WrongPass,
	BadBundle,
	NoSuchId(String),
	BadSig,
	Unauthorized,
}

#[derive(FromArgs, Debug)]
/// wallet cli
struct Args {
	/// password to encrypt the secret seed at signup, or decrypt it when signing data/deleting
	#[argh(option, short = 'p')]
	pass: String,

	/// action to perform
	#[argh(subcommand)]
	mode: Mode,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum Mode {
	Init(Init),
	Sign(Sign),
	Delete(Delete),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "init")]
/// create a signing key
struct Init {}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "sign")]
/// sign provided data
struct Sign {
	/// key id to use
	#[argh(option, short = 'k')]
	key: String,

	/// message to sign
	#[argh(option, short = 'm')]
	message: String,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "delete")]
/// delete local state
struct Delete {
	/// key id to delete
	#[argh(option, short = 'k')]
	key: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
	let args: Args = argh::from_env();

	let port = 8081;
	let api = Api::new("http://localhost", port);

	match &args.mode {
		Mode::Init(_) => {
			_ = init(api, &args.pass).await;
		}
		Mode::Sign(Sign { key, message }) => {
			_ = sign(api, &args.pass, &key, &message).await;
		}
		Mode::Delete(Delete { key }) => {
			_ = delete(api, &args.pass, key).await;
		}
	}

	Ok(())
}

async fn init(api: Api, pass: &str) -> Result<(), Error> {
	let (comms, mut shares) = mpc_math::dkg_gen(DKG_N as usize, DKG_T as usize);
	let outgoing_share = shares.pop().ok_or(Error::Protocol {
		ctx: "no share to send found".to_string(),
	})?;

	// the client always assings himself and index of 1 for the purpose of this demo
	let res: SignupRes = api
		.signup(SignupReq {
			t: DKG_T,
			n: DKG_N,
			// client -> server
			share: Part {
				sender_idx: 1,
				secret_share: outgoing_share.into(),
				commitments: comms.clone().into_iter().map(|c| c.into()).collect(),
			},
		})
		.await
		.map_err(|_| Error::Io("api failed".to_string()))?;

	let my_share = shares.pop().ok_or(Error::Protocol {
		ctx: "no local share found".to_string(),
	})?;

	let incoming_share =
		mpc_math::SecretShare::try_from(res.share.secret_share).map_err(|_| Error::BadShare)?;
	let server_comms = res
		.share
		.commitments
		.into_iter()
		.map(mpc_math::PolyComm::try_from)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|_| Error::BadComm)?;

	if !mpc_math::verify_share(&incoming_share, &server_comms) {
		Err(Error::BadShare)
	} else {
		let priv_share = mpc_math::combine_shares(&[my_share, incoming_share]);
		let group_pk = mpc_math::compute_group_pk(&[comms, server_comms]);
		let bundle = Bundle::new(DKG_T, DKG_N, 1, priv_share, group_pk, res.acl_token);

		save_bundle(&res.id, pass, bundle.clone())?;

		println!("generated key:\n{}", res.id);

		Ok(())
	}
}

async fn sign(api: Api, pass: &str, key_id: &str, msg: &str) -> Result<(), Error> {
	let key_id = Uid::from_str(key_id).map_err(|_| Error::NoSuchId(key_id.to_string()))?;
	let bundle = load_bundle(&key_id, pass)?;
	let scalar =
		Option::from(Scalar::from_canonical_bytes(bundle.scalar)).ok_or(Error::Protocol {
			ctx: "bad scalar".to_string(),
		})?;
	let pk = mpc_math::GroupPubKey::try_from(&bundle.pub_key).map_err(|_| Error::Protocol {
		ctx: "bad group pk".to_string(),
	})?;

	// generate nonce and commitments
	let nonce = mpc_math::nonces_with_params(&scalar, msg.as_bytes(), Salt::gen().as_bytes());
	let comm = NonceComm::from(nonce.clone());

	let resp = api
		.sign_commit(SignReq {
			key_id,
			msg: msg.as_bytes().to_vec(),
			comm: comm.clone(),
		})
		.await
		.map_err(|_| Error::Io("api failed".to_string()))?;

	// aggregate commitments; client is always 1, server is always 2 in this demo
	let idcs = [1u32, 2u32];
	let commits = vec![comm, resp.comm]
		.into_iter()
		.map(mpc_math::NonceComm::try_from)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|_| Error::BadComm)?;
	let (betas, g_comm) = mpc_math::binding_and_group_comm(&idcs, &commits);
	let c = mpc_math::challenge(&g_comm, &pk, msg.as_bytes());

	// client’s partial
	let lam = mpc_math::lagrange_at_zero(1, &idcs);
	let z_client = mpc_math::partial_z(&nonce, betas[0], c, lam, scalar);

	// send to server
	let presp = api
		.sign_final(SignFinal {
			sid: resp.sid,
			key_id,
			// msg: msg.to_string(),
			client_partial: z_client.to_bytes(),
			c: c.to_bytes(),
			g_comm: g_comm.compress().to_bytes(),
		})
		.await
		.map_err(|_| Error::Io("api failed".to_string()))?;

	let z_server = Option::from(Scalar::from_canonical_bytes(presp.server_partial)).ok_or(
		Error::Protocol {
			ctx: "bad server z".to_string(),
		},
	)?;

	let sig = mpc_math::combine_sig(g_comm, &[z_client, z_server]);
	let vk = VerifyingKey::from_bytes(&bundle.pub_key).unwrap();

	// ensure the process went as expected
	vk.verify(msg.as_bytes(), &sig).map_err(|_| Error::BadSig)?;
	println!(
		"sig verified OK\n\nmsg:\n{}\n\nsig:\n{}",
		msg,
		serialize::to_base64(&sig.to_bytes().to_vec()).unwrap()
	);

	Ok(())
}

async fn delete(api: Api, pass: &str, key_id: &str) -> Result<(), Error> {
	let id = Uid::from_str(key_id).map_err(|_| Error::NoSuchId(key_id.to_string()))?;
	// authenticate locally with a pass
	let bundle = load_bundle(&id, pass)?;

	// and with a teoken remotely
	api.delete_share(&id, &bundle.acl_token)
		.await
		.map_err(|_| Error::Unauthorized)?;

	delete_bundle(&id)?;

	println!("deleted key:\n{key_id}");

	Ok(())
}

fn save_bundle(id: &Uid, pass: &str, bundle: Bundle) -> Result<(), Error> {
	let lock = password_lock::lock(&bundle, pass).unwrap();

	fs::write(&id.to_string(), &serialize::to_vec(&lock).unwrap())
		.map_err(|e| Error::Io(e.to_string()))?;

	Ok(())
}

fn load_bundle(id: &Uid, pass: &str) -> Result<Bundle, Error> {
	let loaded = fs::read(&id.to_string()).map_err(|e| Error::Io(e.to_string()))?;
	let lock = serialize::from_slice(&loaded).map_err(|_| Error::BadBundle)?;
	let restored = password_lock::unlock(&lock, pass).map_err(|_| Error::WrongPass)?;

	Ok(serialize::from_slice(&restored).map_err(|_| Error::BadBundle)?)
}

fn delete_bundle(id: &Uid) -> Result<(), Error> {
	fs::remove_file(&id.to_string()).map_err(|e| Error::Io(e.to_string()))
}
