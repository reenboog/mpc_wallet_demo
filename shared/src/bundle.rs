use serde::{Deserialize, Serialize};

use crate::mpc_math;

#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
	// SecretShare::rcvr_idx
	peer_idx: u32,
	// SecretShare::scalar
	secret_share: [u8; mpc_math::SCALAR_LEN],
}

impl Bundle {
	// pub fn gen() -> Self {
	// 	Self { seed: Salt::gen() }
	// }

	// pub fn with_entropy(entr: &[u8]) -> Self {
	// 	Self {
	// 		seed: Salt::with_entropy(entr),
	// 	}
	// }
}
