use crate::{rnd, serialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

#[derive(Debug)]
pub struct Error(String);

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uid(u64);

const SIZE: usize = 8;

impl Uid {
	pub fn new(val: u64) -> Self {
		Self(val)
	}

	pub fn gen() -> Self {
		Self(rnd::gen())
	}

	pub fn from_bytes(bytes: &[u8]) -> Self {
		Self(u64::from_be_bytes(
			Sha256::digest(bytes).to_vec()[..8].try_into().unwrap(),
		))
	}

	pub fn as_bytes(&self) -> [u8; SIZE] {
		self.0.to_be_bytes()
	}
}

impl fmt::Display for Uid {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&serialize::to_base64(self).unwrap())
	}
}

impl FromStr for Uid {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		serialize::from_base64::<Self>(s).map_err(|e| Error(e.to_string()))
	}
}

impl PartialEq<u64> for Uid {
	fn eq(&self, other: &u64) -> bool {
		&self.0 == other
	}
}

impl PartialEq<Uid> for u64 {
	fn eq(&self, other: &Uid) -> bool {
		self == &other.0
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use super::Uid;
	use crate::serialize::{self, from_slice};

	#[test]
	fn test_serialize_deserialize() {
		let id = Uid::gen();
		let serialized = serialize::to_vec(&id).unwrap();
		let deserialized = from_slice::<Uid>(&serialized).unwrap();

		assert_eq!(id, deserialized);
	}

	#[test]
	fn test_to_from_string() {
		let id = Uid::gen();
		let to_str = id.to_string();
		let from_str = Uid::from_str(&to_str);

		assert_eq!(from_str.ok(), Some(id));
	}
}
