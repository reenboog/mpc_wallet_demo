use crate::{hkdf, hmac, rnd};
use serde::{Deserialize, Serialize};

const SALT_SIZE: usize = hmac::Key::SIZE;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Salt {
	pub(crate) bytes: [u8; Self::SIZE],
}

impl Salt {
	pub const SIZE: usize = SALT_SIZE;

	pub fn gen() -> Self {
		let mut bytes = [0u8; Self::SIZE];
		rnd::fill_bytes(&mut bytes);

		Self { bytes }
	}

	pub fn with_entropy(entr: &[u8]) -> Self {
		let bytes = hkdf::Hkdf::from_ikm(entr).expand_no_info::<{ Self::SIZE }>();

		Self { bytes }
	}
}
