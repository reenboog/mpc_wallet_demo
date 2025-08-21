use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupReq {
	pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupRes {
	pub id: String,
}
