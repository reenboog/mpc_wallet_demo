use std::sync::Arc;

use crate::store::Store;

#[derive(Clone)]
pub struct State {
	// a hashmap for key parts and sign requests lives here
	pub store: Arc<Store>,
}

impl State {
	pub fn new(store: Store) -> Self {
		Self {
			store: Arc::new(store),
		}
	}
}
