use shared::{
	auth::{SignupReq, SignupRes},
	reqwest::Client,
	serde::{Serialize, de::DeserializeOwned},
};

use crate::error::Error;

pub struct Api {
	client: Client,
	host: String,
}

impl Api {
	pub fn new(host: &str, port: u32) -> Self {
		Self {
			client: Client::new(),
			host: format!("{host}:{port}"),
		}
	}

	async fn post<T, B>(self, endpoint: &str, body: B) -> Result<T, Error>
	where
		T: DeserializeOwned,
		B: Serialize,
	{
		let url = format!(
			"{}/{}",
			self.host.trim_end_matches('/'),
			endpoint.trim_start_matches('/')
		);

		let res = self
			.client
			.post(url)
			.json(&body)
			.send()
			.await
			.map_err(|e| Error::Io(e.to_string()))?
			.error_for_status()
			.map_err(|e| Error::Io(e.to_string()))?
			.json::<T>()
			.await
			.map_err(|e| Error::Io(e.to_string()))?;

		Ok(res)
	}

	pub async fn signup(self, req: SignupReq) -> Result<SignupRes, Error> {
		self.post("signup", req).await
	}
}
