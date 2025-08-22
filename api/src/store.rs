use dashmap::DashMap;
use shared::{
	id::Uid,
	mpc_math::{self, GroupPubKey},
	Scalar,
};

pub enum Error {
	AlreadyExists(Uid),
	NotFound(Uid),
}

// this should be asynchronous for prod, of course
pub struct Store {
	// dashmap is used to avoid locking for independent requests
	shares: DashMap<Uid, (Scalar, GroupPubKey)>,
}

impl Store {
	pub fn new() -> Self {
		Self {
			shares: DashMap::new(),
		}
	}

	pub fn put(&self, id: Uid, share: Scalar, pk: GroupPubKey) -> Result<(), Error> {
		if self.shares.contains_key(&id) {
			Err(Error::AlreadyExists(id))
		} else {
			self.shares.insert(id, (share, pk));

			Ok(())
		}
	}

	pub fn remove(&self, id: Uid) -> Result<(), Error> {
		_ = self.shares.remove(&id).ok_or(Error::NotFound(id))?;

		Ok(())
	}

	pub fn get(&self, id: Uid) -> Option<(Scalar, GroupPubKey)> {
		self.shares.get(&id).as_deref().cloned()
	}
}
