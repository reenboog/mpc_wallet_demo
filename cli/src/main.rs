use shared::{
	auth::{SignupReq, SignupRes},
	tokio,
};

use crate::{api::Api, error::Error};

mod api;
mod error;

#[tokio::main]
async fn main() -> Result<(), Error> {
	println!("sending");

	let port = 8081;
	let api = Api::new(&format!("http://localhost"), port);

	let res: SignupRes = api
		.signup(SignupReq {
			id: "kakakakaak0".to_string(),
		})
		.await?;

	println!("rcvd: {:?}", res);

	Ok(())
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_ok() {
		assert!(true);
	}
}
