use chacha20poly1305::{aead::Aead as ChaAead, ChaCha20Poly1305, Key as ChaKey, KeyInit, Nonce};

use serde::{Deserialize, Serialize};

use crate::{hkdf, rnd, salt::Salt};

pub const KEY_SIZE: usize = 32;
pub const IV_SIZE: usize = 12;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Encrypted {
	pub ct: Vec<u8>,
	pub salt: Salt,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Key {
	pub bytes: [u8; Self::SIZE],
}

impl Key {
	pub const SIZE: usize = KEY_SIZE;

	pub fn gen() -> Self {
		let mut key = [0u8; Self::SIZE];
		rnd::fill_bytes(&mut key);
		Self { bytes: key }
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.bytes
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct Iv {
	pub bytes: [u8; Self::SIZE],
}

impl Iv {
	pub const SIZE: usize = IV_SIZE;

	pub fn gen() -> Self {
		let mut iv = [0u8; Self::SIZE];
		rnd::fill_bytes(&mut iv);
		Self { bytes: iv }
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.bytes
	}
}

#[derive(Debug, PartialEq)]
pub enum Error {
	WrongKeyMaterial,
	WrongKeyIvSize,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Aead {
	pub key: Key,
	pub iv: Iv,
}

impl Aead {
	pub fn gen() -> Self {
		Self::new_with_key_iv(Key::gen(), Iv::gen())
	}

	pub fn with_key(key: Key) -> Self {
		Self::new_with_key_iv(key, Iv::gen())
	}

	pub fn expand_from(bytes: &[u8]) -> Self {
		let key_iv = hkdf::Hkdf::from_ikm(bytes).expand_no_info::<{ Key::SIZE + Iv::SIZE }>();

		Self::from(&key_iv)
	}

	pub fn new_with_key_iv(key: Key, iv: Iv) -> Self {
		Self { key, iv }
	}

	pub fn encrypt(&self, pt: &[u8]) -> Vec<u8> {
		let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(self.key.as_bytes()));
		let nonce = Nonce::from_slice(self.iv.as_bytes());

		cipher.encrypt(nonce, pt).unwrap()
	}

	pub fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
		let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(self.key.as_bytes()));
		let nonce = Nonce::from_slice(self.iv.as_bytes());

		cipher
			.decrypt(nonce, ct)
			.map_err(|_| Error::WrongKeyMaterial)
	}

	fn key_for_chunk_idx(&self, idx: u32) -> Self {
		let chunk_key = hkdf::Hkdf::from_ikm(&self.as_bytes())
			.expand::<{ Key::SIZE + Iv::SIZE }>(&idx.to_be_bytes());

		Aead::from(&chunk_key)
	}

	pub fn chunk_encrypt(&self, idx: u32, pt: &[u8]) -> Vec<u8> {
		let aead = self.key_for_chunk_idx(idx);

		aead.encrypt(pt)
	}

	pub fn chunk_decrypt(&self, idx: u32, ct: &[u8]) -> Result<Vec<u8>, Error> {
		let aead = self.key_for_chunk_idx(idx);

		aead.decrypt(ct)
	}

	pub fn as_bytes(&self) -> [u8; Key::SIZE + Iv::SIZE] {
		[
			self.key.as_bytes().as_slice(),
			self.iv.as_bytes().as_slice(),
		]
		.concat()
		.try_into()
		.unwrap()
	}
}

impl TryFrom<&[u8]> for Aead {
	type Error = Error;

	fn try_from(val: &[u8]) -> Result<Self, Self::Error> {
		if val.len() != Key::SIZE + Iv::SIZE {
			Err(Error::WrongKeyIvSize)
		} else {
			Ok(Self::new_with_key_iv(
				Key {
					bytes: val[..Key::SIZE].try_into().unwrap(),
				},
				Iv {
					bytes: val[Key::SIZE..].try_into().unwrap(),
				},
			))
		}
	}
}

impl From<&[u8; Key::SIZE + Iv::SIZE]> for Aead {
	fn from(val: &[u8; Key::SIZE + Iv::SIZE]) -> Self {
		Self::new_with_key_iv(
			Key {
				bytes: val[..Key::SIZE].try_into().unwrap(),
			},
			Iv {
				bytes: val[Key::SIZE..].try_into().unwrap(),
			},
		)
	}
}
