use rand::distributions::uniform::{SampleRange, SampleUniform};
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};

// a module to quickly inject whatever source of entropy is required for the given context

pub fn fill_bytes(dest: &mut [u8]) {
	OsRng.fill_bytes(dest);
}

pub fn gen<T>() -> T
where
	Standard: Distribution<T>,
{
	OsRng.gen()
}

pub fn gen_range<T, R>(range: R) -> T
where
	T: SampleUniform,
	R: SampleRange<T>,
{
	OsRng.gen_range(range)
}

pub fn rng() -> OsRng {
	OsRng
}
