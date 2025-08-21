use argh::FromArgs;
use shared::{
	auth::{SignupReq, SignupRes},
	tokio,
};

use crate::{api::Api, error::Error};

mod api;
mod error;

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
	println!("init {pass}");

	// example call you already had
	let res: SignupRes = api.signup(SignupReq { id: pass.into() }).await?;

	println!("rcvd: {:?}", res);

	Ok(())
}

async fn sign(api: Api, pass: &str, key_id: &str, msg: &str) -> Result<(), Error> {
	println!("signing: {msg} with {key_id}");

	Ok(())
}

async fn delete(api: Api, pass: &str, key_id: &str) -> Result<(), Error> {
	println!("deleting {key_id}");

	Ok(())
}
