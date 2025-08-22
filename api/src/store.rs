use dashmap::DashMap;
use shared::{
	id::Uid,
	mpc_math::{self, GroupPubKey},
	salt::Salt,
	serialize, Scalar,
};

pub enum Error {
	AlreadyExists(Uid),
	NotFound(Uid),
}

// this should be asynchronous for prod, of course
pub struct Store {
	// dashmap is used to avoid locking for independent requests
	shares: DashMap<Uid, (Scalar, GroupPubKey, String)>,
	// my nonce, their comm
	nonces: DashMap<Uid, (mpc_math::SigNonces, mpc_math::NonceComm)>,
}

impl Store {
	pub fn new() -> Self {
		Self {
			shares: DashMap::new(),
			nonces: DashMap::new(),
		}
	}

	pub fn put_nonce(
		&self,
		id: Uid,
		nonce: mpc_math::SigNonces,
		comm: mpc_math::NonceComm,
	) -> Result<(), Error> {
		if self.nonces.contains_key(&id) {
			Err(Error::AlreadyExists(id))
		} else {
			self.nonces.insert(id, (nonce, comm));

			Ok(())
		}
	}

	pub fn take_nonce(
		&self,
		sid: Uid,
	) -> Result<(mpc_math::SigNonces, mpc_math::NonceComm), Error> {
		Ok(self
			.nonces
			.remove(&sid)
			.map(|(_, v)| v)
			.ok_or(Error::NotFound(sid))?)
	}

	pub fn put_share(&self, id: Uid, share: Scalar, pk: GroupPubKey) -> Result<String, Error> {
		if self.shares.contains_key(&id) {
			Err(Error::AlreadyExists(id))
		} else {
			let token = serialize::to_base64(&Salt::gen()).unwrap();
			self.shares.insert(id, (share, pk, token.clone()));

			Ok(token)
		}
	}

	pub fn remove_share(&self, id: Uid, acl_token: &str) -> Result<(), Error> {
		// do not leak any information, whether the token was correct or not – just "not found" instead
		_ = self
			.shares
			.remove_if(&id, |_, (_, _, token)| acl_token == token)
			.ok_or(Error::NotFound(id))?;

		Ok(())
	}

	pub fn get_share(&self, id: &Uid) -> Option<(Scalar, GroupPubKey)> {
		self.shares
			.get(id)
			.as_deref()
			.cloned()
			.map(|(s, pk, _)| (s, pk))
	}
}
