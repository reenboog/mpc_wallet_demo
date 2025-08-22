use argh::FromArgs;
use shared::{
	client_api::Api,
	mpc_math, password_lock, serialize,
	share::{Bundle, Part, SignupReq, SignupRes},
	tokio,
};

const DKG_T: u32 = 2;
const DKG_N: u32 = 2;

#[derive(Debug)]
pub enum Error {
	Io(String),
	BadShare,
	BadComm,
	Protocol { ctx: String },
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
			init(api, &args.pass).await;
		}
		Mode::Sign(Sign { key, message }) => {
			sign(api, &args.pass, &key, &message).await;
		}
		Mode::Delete(Delete { key }) => {
			delete(api, &args.pass, key).await;
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

		let bundle = Bundle::new(DKG_T, DKG_N, 1, priv_share, group_pk);
		let lock = password_lock::lock(&bundle, pass).unwrap();

		//

		use std::fs;
		use std::path::PathBuf;

		let filename = format!("{}", res.id.to_string());
		fs::write(&filename, &serialize::to_vec(&lock).unwrap())
			.map_err(|e| Error::Io(e.to_string()))?;

		println!("generated key id {}", res.id);

		Ok(())
	}
}

async fn sign(api: Api, pass: &str, key_id: &str, msg: &str) -> Result<(), Error> {
	println!("signing: {msg} with {key_id}");

	Ok(())
}

async fn delete(api: Api, pass: &str, key_id: &str) -> Result<(), Error> {
	println!("deleting {key_id}");

	Ok(())
}
