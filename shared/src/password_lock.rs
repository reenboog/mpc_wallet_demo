// specific bundle + pass -> encrypted
// any data + eph_pass -> encrypted

use argon2::{Config, Variant, Version};
use serde::{Deserialize, Serialize};

use crate::{
	aead::{self, Encrypted},
	hkdf, hmac,
	salt::Salt,
	serialize,
};

#[derive(Debug)]
pub enum Error {
	Argon2Failed,
	WrongKey,
	BadEncoding,
}

// for the purposes of the demo wek parameters are used
const DEFAULT_CONFIG: Config = Config {
	variant: Variant::Argon2id,
	hash_length: hmac::Digest::SIZE as u32,
	time_cost: 1,
	lanes: 1,
	mem_cost: 8,

	ad: &[],
	secret: &[],
	version: Version::Version13,
};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Lock {
	// pt encrypted with master_key
	pub(crate) ct: Vec<u8>,
	// master_key encrypted with pass
	pub(crate) master_key: Encrypted,
}

pub fn lock<T>(pt: &T, pass: &str) -> Result<Lock, Error>
where
	T: Serialize,
{
	let master_key = aead::Aead::gen();

	lock_with_master_key(master_key, pt, pass)
}

fn lock_with_params(
	pt: &[u8],
	pass: &str,
	salt: Salt,
	master_key: aead::Aead,
	config: &Config,
) -> Result<Lock, Error> {
	let ct = master_key.encrypt(&pt);
	let pass_aead = aead_from_params(pass, &salt, config)?;
	let master_key_ct = pass_aead.encrypt(&master_key.as_bytes());

	Ok(Lock {
		ct,
		master_key: Encrypted {
			ct: master_key_ct,
			salt,
		},
	})
}

pub fn unlock(lock: &Lock, pass: &str) -> Result<Vec<u8>, Error> {
	unlock_with_params(lock, pass, &DEFAULT_CONFIG)
}

pub fn lock_with_master_key<T>(master_key: aead::Aead, pt: &T, pass: &str) -> Result<Lock, Error>
where
	T: Serialize,
{
	lock_with_params(
		&serialize::to_vec(pt).unwrap(),
		pass,
		Salt::gen(),
		master_key,
		&DEFAULT_CONFIG,
	)
}

pub fn unlock_with_master_key(master_key: &aead::Aead, ct: &[u8]) -> Result<Vec<u8>, Error> {
	let pt = master_key.decrypt(&ct).map_err(|_| Error::WrongKey)?;

	Ok(pt)
}

pub fn decrypt_master_key(mk: &Encrypted, pass: &str) -> Result<aead::Aead, Error> {
	decrypt_master_key_with_params(mk, pass, &DEFAULT_CONFIG)
}

fn decrypt_master_key_with_params(
	mk: &Encrypted,
	pass: &str,
	config: &Config,
) -> Result<aead::Aead, Error> {
	let pass_aead = aead_from_params(pass, &mk.salt, config)?;
	let master_key = pass_aead.decrypt(&mk.ct).map_err(|_| Error::Argon2Failed)?;

	Ok(aead::Aead::try_from(master_key.as_slice()).map_err(|_| Error::BadEncoding)?)
}

fn unlock_with_params(lock: &Lock, pass: &str, config: &Config) -> Result<Vec<u8>, Error> {
	let master_key = decrypt_master_key_with_params(&lock.master_key, pass, config)?;

	unlock_with_master_key(&master_key, &lock.ct)
}

fn aead_from_params(pass: &str, salt: &Salt, config: &Config) -> Result<aead::Aead, Error> {
	let hash =
		argon2::hash_raw(pass.as_bytes(), &salt.bytes, config).map_err(|_| Error::Argon2Failed)?;
	let key_iv =
		hkdf::Hkdf::from_ikm(&hash).expand_no_info::<{ aead::Key::SIZE + aead::Iv::SIZE }>();

	Ok(aead::Aead::try_from(key_iv.as_slice()).unwrap())
}

#[cfg(test)]
mod tests {
	use super::{unlock, DEFAULT_CONFIG};
	use crate::{
		aead,
		password_lock::{lock_with_params, unlock_with_params},
		salt::Salt,
	};
	#[test]
	fn test_lock_unlock() {
		let msg = b"1234567890";
		let pass = "password123";
		let salt = Salt::gen();
		let master_key = aead::Aead::gen();
		let lock = lock_with_params(msg, pass, salt, master_key, &DEFAULT_CONFIG).unwrap();
		let unlocked = unlock_with_params(&lock, pass, &DEFAULT_CONFIG).unwrap();

		assert_eq!(msg.to_vec(), unlocked);
	}

	#[test]
	fn test_unlock_with_wrong_pass() {
		let msg = b"1234567890";
		let pass = "password123";
		let salt = Salt::gen();
		let master_key = aead::Aead::gen();
		let lock = lock_with_params(msg, pass, salt, master_key, &DEFAULT_CONFIG).unwrap();
		let unlocked = unlock(&lock, "wrong_pass");

		assert!(unlocked.is_err());
	}
}
