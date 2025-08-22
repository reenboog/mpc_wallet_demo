use curve25519_dalek::Scalar;
use serde::{Deserialize, Serialize};

use crate::{id::Uid, mpc_math};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupReq {
	pub t: u32,
	pub n: u32,
	pub share: Part,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Part {
	pub sender_idx: u32,
	// since it's a 1-1 setup (t = 2, n = 2), we can rely on tls to encrypt this secret share
	// in real life, it should be encrypted to the recipient's public key, of course
	pub secret_share: Share,
	pub commitments: Vec<PolyComm>,
}

// wraps mpc_math::SecretShare
#[derive(Debug, Serialize, Deserialize)]
pub struct Share {
	pub rcvr_idx: u32,
	pub scalar_bytes: [u8; 32],
}

impl From<mpc_math::SecretShare> for Share {
	fn from(value: mpc_math::SecretShare) -> Self {
		Self {
			rcvr_idx: value.rcvr_idx,
			scalar_bytes: value.scalar.to_bytes(),
		}
	}
}

impl TryFrom<Share> for mpc_math::SecretShare {
	type Error = ();

	fn try_from(value: Share) -> Result<Self, Self::Error> {
		Ok(Self {
			rcvr_idx: value.rcvr_idx,
			scalar: Option::from(curve25519_dalek::scalar::Scalar::from_canonical_bytes(
				value.scalar_bytes,
			))
			.ok_or(())?,
		})
	}
}

// wraps mpc_math::PolyComm
#[derive(Debug, Serialize, Deserialize)]
pub struct PolyComm {
	bytes: [u8; mpc_math::POINT_LEN],
}

impl From<mpc_math::PolyComm> for PolyComm {
	fn from(value: mpc_math::PolyComm) -> Self {
		Self {
			bytes: value.0.compress().as_bytes().clone(),
		}
	}
}

impl TryFrom<PolyComm> for mpc_math::PolyComm {
	type Error = ();

	fn try_from(value: PolyComm) -> Result<Self, Self::Error> {
		Ok(mpc_math::PolyComm(
			curve25519_dalek::edwards::CompressedEdwardsY(value.bytes)
				.decompress()
				.ok_or(())?,
		))
	}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupRes {
	pub id: Uid,
	pub share: Part,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Bundle {
	pub n: u32,
	pub t: u32,
	pub peer_idx: u32,
	pub scalar: [u8; mpc_math::SCALAR_LEN],
	pub pub_key: [u8; mpc_math::POINT_LEN],
}

impl Bundle {
	pub fn new(t: u32, n: u32, peer_idx: u32, scalar: Scalar, pk: mpc_math::GroupPubKey) -> Self {
		Self {
			n,
			t,
			peer_idx,
			scalar: scalar.to_bytes(),
			pub_key: pk.as_bytes(),
		}
	}
}
