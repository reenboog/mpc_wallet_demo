use curve25519_dalek::{
	constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint, scalar::Scalar, traits::Identity,
};
use ed25519_dalek::Signature;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

// public dkg commitment to a polynomial coefficient (safe to broadcast)
#[derive(Clone, Debug)]
pub struct PolyComm(pub EdwardsPoint);

// private dkg share to a participant; TODO: encrypt
#[derive(Clone, Debug)]
pub struct SecretShare {
	pub rcvr_idx: u32,
	pub scalar: Scalar,
}

#[derive(Clone)]
pub struct GroupPubKey(pub EdwardsPoint);

// signing-time commitment (safe to broadcast)
#[derive(Clone, Copy, Debug)]
pub struct NonceComm {
	pub r1_pt: EdwardsPoint,
	pub r2_pt: EdwardsPoint,
}

// ephemeral signing nonces (private)
struct SigNonces {
	r1: Scalar,
	r2: Scalar,
	r1_pt: EdwardsPoint,
	r2_pt: EdwardsPoint,
}

impl SigNonces {
	fn from_scalars(r1: Scalar, r2: Scalar) -> Self {
		Self {
			r1,
			r2,
			r1_pt: r1 * ED25519_BASEPOINT_POINT,
			r2_pt: r2 * ED25519_BASEPOINT_POINT,
		}
	}
}

fn is_valid_point(p: &EdwardsPoint) -> bool {
	p.is_torsion_free()
}

// Feldman dkg
// returns t polynomial commitments + n shares
pub fn dkg_from_coeffs(coeffs: &[Scalar], n: usize) -> (Vec<PolyComm>, Vec<SecretShare>) {
	let comms: Vec<PolyComm> = coeffs
		.iter()
		.map(|c| PolyComm(c * ED25519_BASEPOINT_POINT))
		.collect();
	let mut shares = Vec::with_capacity(n);

	for rcvr_idx in 1..=n {
		let x = Scalar::from(rcvr_idx as u64);
		let mut val = Scalar::ZERO;
		let mut x_pow = Scalar::ONE;

		for coeff in coeffs {
			val += coeff * x_pow;
			x_pow *= x;
		}

		shares.push(SecretShare {
			rcvr_idx: rcvr_idx as u32,
			scalar: val,
		});
	}

	(comms, shares)
}

pub fn dkg_gen(n: usize, t: usize) -> (Vec<PolyComm>, Vec<SecretShare>) {
	assert!(t <= n && t >= 2);

	let mut coeffs: Vec<Scalar> = vec![Scalar::random(&mut OsRng)];

	for _ in 1..t {
		coeffs.push(Scalar::random(&mut OsRng));
	}

	dkg_from_coeffs(&coeffs, n)
}

fn nonces_with_params(secret_share: &Scalar, msg: &[u8], session_id: &[u8]) -> SigNonces {
	// hkdf 64 bytes from (share || msg || session_id)
	let mut h = Sha512::new();

	h.update(secret_share.as_bytes());
	h.update(msg);
	h.update(session_id);

	let out = h.finalize();

	// first 64 bytes -> r1
	let r1 = Scalar::from_bytes_mod_order_wide(&out[..64].try_into().unwrap());
	// hash again -> r2
	let mut h2 = Sha512::new();

	h2.update(&out);

	let r2 = Scalar::from_hash(h2);

	SigNonces::from_scalars(r1, r2)
}

// this only checks consistency, not bias; Feldman is fine, but TODO: consider Pedersen
pub fn verify_share(share: &SecretShare, comms: &[PolyComm]) -> bool {
	if comms.iter().any(|c| !is_valid_point(&c.0)) {
		return false;
	}

	let x = Scalar::from(share.rcvr_idx as u64);
	let mut expected = EdwardsPoint::identity();
	let mut x_pow = Scalar::ONE;

	for comm in comms {
		expected += x_pow * comm.0;
		x_pow *= x;
	}

	expected == share.scalar * ED25519_BASEPOINT_POINT
}

// get the final private share for the participant; TODO: introduce ids or alike?
pub fn combine_shares(shares: &[SecretShare]) -> Scalar {
	shares.iter().map(|s| s.scalar).sum()
}

pub fn compute_group_pk(comms: &[Vec<PolyComm>]) -> GroupPubKey {
	for cset in comms {
		for c in cset {
			assert!(is_valid_point(&c.0), "invalid subgroup point");
		}
	}

	let pk_point = comms
		.iter()
		.map(|c| c[0].0)
		.fold(EdwardsPoint::identity(), |acc, p| acc + p);

	GroupPubKey(pk_point)
}

fn binding_and_group_comm(
	subset_indices: &[u32],
	commits: &[NonceComm],
) -> (Vec<Scalar>, EdwardsPoint) {
	assert_eq!(subset_indices.len(), commits.len());

	let mut t = Sha512::new();

	for id in subset_indices {
		t.update(&id.to_le_bytes());
	}
	for c in commits {
		t.update(c.r1_pt.compress().as_bytes());
	}
	for c in commits {
		t.update(c.r2_pt.compress().as_bytes());
	}

	let t_bytes = t.finalize();
	let mut betas = Vec::with_capacity(commits.len());

	for (k, _) in commits.iter().enumerate() {
		let mut h = Sha512::new();
		h.update(&t_bytes);
		h.update(&(k as u32).to_le_bytes());
		betas.push(Scalar::from_hash(h));
	}

	let mut g_comm = EdwardsPoint::identity();

	for (i, c) in commits.iter().enumerate() {
		g_comm += c.r1_pt + betas[i] * c.r2_pt;
	}

	(betas, g_comm)
}

fn lagrange_at_zero(i: u32, signer_idcs: &[u32]) -> Scalar {
	let ii = Scalar::from(i as u64);
	let mut num = Scalar::ONE;
	let mut den = Scalar::ONE;

	for &j in signer_idcs {
		if j != i {
			let jj = Scalar::from(j as u64);
			num *= -jj;
			den *= ii - jj;
		}
	}
	den.invert() * num
}

fn challenge(g_comm: &EdwardsPoint, pk: &GroupPubKey, msg: &[u8]) -> Scalar {
	let mut h = Sha512::new();

	h.update(g_comm.compress().as_bytes());
	h.update(pk.0.compress().as_bytes());
	h.update(msg);

	Scalar::from_hash(h)
}

fn partial_z(nonces: &SigNonces, beta: Scalar, c: Scalar, lambda: Scalar, x_i: Scalar) -> Scalar {
	sign_share(x_i, lambda, nonces.r1, nonces.r2, beta, c)
}

fn combine_sig(g_comm: EdwardsPoint, partials: &[Scalar]) -> Signature {
	let s: Scalar = partials.iter().copied().sum();
	let mut sig = [0u8; 64];

	sig[..32].copy_from_slice(&g_comm.compress().to_bytes());
	sig[32..].copy_from_slice(s.as_bytes());

	Signature::from_bytes(&sig)
}

fn sign_share(
	x_i: Scalar,
	lambda_i: Scalar,
	r1: Scalar,
	r2: Scalar,
	beta: Scalar,
	c: Scalar,
) -> Scalar {
	r1 + beta * r2 + c * lambda_i * x_i
}

#[cfg(test)]
mod math_tests {
	use super::*;
	use ed25519_dalek::{Signature, Verifier, VerifyingKey};

	// emulate the normal protocol flow: gen, share over the network, etc
	fn setup_dkg(n: usize, t: usize) -> (Vec<Scalar>, GroupPubKey) {
		let mut all_commitments = Vec::new();
		let mut shares_for = vec![vec![]; n];
		for _dealer in 0..n {
			let (comms, shares) = dkg_gen(n, t);
			all_commitments.push(comms.clone());
			for sh in shares {
				shares_for[(sh.rcvr_idx - 1) as usize].push(sh);
			}
		}
		let mut x_final = Vec::new();
		for i in 0..n {
			for (dealer_idx, sh) in shares_for[i].iter().enumerate() {
				assert!(verify_share(sh, &all_commitments[dealer_idx]));
			}
			x_final.push(combine_shares(&shares_for[i]));
		}
		let group_pk = compute_group_pk(&all_commitments);
		(x_final, group_pk)
	}

	#[test]
	fn test_subgroup_tamper_in_commitment_rejected() {
		let (commitments, shares) = dkg_gen(3, 2);
		let mut bad_commitments = commitments.clone();

		bad_commitments[0] = PolyComm(EdwardsPoint::identity());

		assert!(!verify_share(&shares[0], &bad_commitments));
	}

	fn run_t_of_n_test(n: usize, t: usize, idcs: &[u32]) {
		// dkg
		let (x_final, group_pk) = setup_dkg(n, t);
		let pk_bytes = group_pk.0.compress().to_bytes();
		let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
		let msg = b"hello";
		let mut nonces = Vec::with_capacity(idcs.len());
		let mut comms = Vec::with_capacity(idcs.len());

		for &id in idcs {
			// participant's private share
			let x_i = x_final[(id - 1) as usize];
			// session ids should be random/unique, but this will do for the test
			let nonce = nonces_with_params(&x_i, msg, format!("sid-{}", id).as_bytes());

			comms.push(NonceComm {
				r1_pt: nonce.r1_pt,
				r2_pt: nonce.r2_pt,
			});
			nonces.push((id, x_i, nonce));
		}

		// aggregate commitments
		let (betas, g_comm) = binding_and_group_comm(idcs, &comms);
		let c = challenge(&g_comm, &group_pk, msg);

		// compute partial signatures by each peer
		let mut partials = Vec::with_capacity(idcs.len());
		for ((id, x_i, nonce), beta) in nonces.into_iter().zip(betas.into_iter()) {
			let lam = lagrange_at_zero(id, idcs);
			let z_i = partial_z(&nonce, beta, c, lam, x_i);
			partials.push(z_i);
		}

		// and finally combine into one signature
		let sig = combine_sig(g_comm, &partials);

		assert!(
			vk.verify(msg, &sig).is_ok(),
			"t-of-n signature verification failed"
		);
	}

	#[test]
	fn test_t_of_n_succeeds() {
		run_t_of_n_test(2, 2, &[1, 2]);
		run_t_of_n_test(3, 2, &[1, 3]);
		run_t_of_n_test(4, 3, &[1, 2, 4]);
	}

	#[test]
	fn test_tampered_partial_signature_fails() {
		let (x_final, group_pk) = setup_dkg(3, 2);
		let pk_bytes = group_pk.0.compress().to_bytes();
		let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();

		let msg = b"hello";
		let idcs = [1u32, 2u32];
		let x1 = x_final[(idcs[0] - 1) as usize];
		let x2 = x_final[(idcs[1] - 1) as usize];

		let n1 = nonces_with_params(&x1, msg, b"x1-sid");
		let n2 = nonces_with_params(&x2, msg, b"x2-sid");
		let commits = [
			NonceComm {
				r1_pt: n1.r1_pt,
				r2_pt: n1.r2_pt,
			},
			NonceComm {
				r1_pt: n2.r1_pt,
				r2_pt: n2.r2_pt,
			},
		];

		let (betas, g_comm) = binding_and_group_comm(&idcs, &commits);
		let c = challenge(&g_comm, &group_pk, msg);
		let lam1 = lagrange_at_zero(1, &idcs);
		let lam2 = lagrange_at_zero(2, &idcs);

		let mut z1 = partial_z(&n1, betas[0], c, lam1, x1);
		let z2 = partial_z(&n2, betas[1], c, lam2, x2);

		// tamper
		z1 += Scalar::ONE;

		let sig = combine_sig(g_comm, &[z1, z2]);

		assert!(vk.verify(msg, &sig).is_err());
	}

	#[test]
	fn test_too_few_signers_fails() {
		let (x_final, group_pk) = setup_dkg(3, 2);
		let pk_bytes = group_pk.0.compress().to_bytes();
		let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();

		let msg = b"hi";
		// only 1 signer
		let idcs = [1u32];
		let x1 = x_final[(idcs[0] - 1) as usize];
		let n1 = nonces_with_params(&x1, msg, b"x1-sid");

		let commits = [NonceComm {
			r1_pt: n1.r1_pt,
			r2_pt: n1.r2_pt,
		}];
		let (betas, g_comm) = binding_and_group_comm(&idcs, &commits);
		let c = challenge(&g_comm, &group_pk, msg);
		let lam1 = lagrange_at_zero(1, &idcs);

		let z1 = partial_z(&n1, betas[0], c, lam1, x1);
		let sig = combine_sig(g_comm, &[z1]);

		assert!(vk.verify(msg, &sig).is_err());
	}

	#[test]
	fn test_invalid_share_fails() {
		let (mut x_final, group_pk) = setup_dkg(3, 2);
		// Tamper with a share
		x_final[0] += Scalar::ONE;
		let pk_bytes = group_pk.0.compress().to_bytes();
		let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();

		let msg = b"bad";
		let idcs = [1u32, 2u32];
		let x1 = x_final[(idcs[0] - 1) as usize];
		let x2 = x_final[(idcs[1] - 1) as usize];

		let n1 = nonces_with_params(&x1, msg, b"x1-sid");
		let n2 = nonces_with_params(&x2, msg, b"x2-sid");

		let commits = [
			NonceComm {
				r1_pt: n1.r1_pt,
				r2_pt: n1.r2_pt,
			},
			NonceComm {
				r1_pt: n2.r1_pt,
				r2_pt: n2.r2_pt,
			},
		];
		let (betas, g_comm) = binding_and_group_comm(&idcs, &commits);
		let c = challenge(&g_comm, &group_pk, msg);
		let lam1 = lagrange_at_zero(1, &idcs);
		let lam2 = lagrange_at_zero(2, &idcs);

		let z1 = partial_z(&n1, betas[0], c, lam1, x1);
		let z2 = partial_z(&n2, betas[1], c, lam2, x2);

		let sig = combine_sig(g_comm, &[z1, z2]);

		assert!(vk.verify(msg, &sig).is_err());
	}

	#[test]
	fn test_nonce_reuse_leaks_secret() {
		let (x_final, group_pk) = setup_dkg(3, 2);
		let x1 = x_final[0];

		// Forcefully reuse the same nonce r across two messages
		let r = Scalar::random(&mut OsRng);

		let msg1 = b"msg1";
		let msg2 = b"msg2";

		let c1 = challenge(&(r * ED25519_BASEPOINT_POINT), &group_pk, msg1);
		let c2 = challenge(&(r * ED25519_BASEPOINT_POINT), &group_pk, msg2);

		let z1 = r + c1 * x1;
		let z2 = r + c2 * x1;

		let recovered = (z1 - z2) * (c1 - c2).invert();
		assert_eq!(x1, recovered);
	}
}

#[cfg(test)]
mod vector_tests {
	use curve25519_dalek::{EdwardsPoint, Scalar, edwards::CompressedEdwardsY, traits::Identity};
	use ed25519_dalek::{Signature, Verifier, VerifyingKey};
	use hex::FromHex;
	use serde::Deserialize;

	use crate::{GroupPubKey, challenge, combine_sig, lagrange_at_zero, sign_share};

	#[derive(Deserialize)]
	struct ParticipantShare {
		identifier: u32,
		participant_share: String,
	}

	#[derive(Deserialize)]
	struct RoundOneOutput {
		identifier: u32,
		hiding_nonce: String,
		binding_nonce: String,
		hiding_nonce_commitment: String,
		binding_nonce_commitment: String,
		binding_factor: String,
	}

	// #[derive(Deserialize)]
	// struct RoundTwoOutput {
	// 	identifier: u32,
	// 	sig_share: String,
	// }

	#[derive(Deserialize)]
	struct FrostVector {
		inputs: Inputs,
		round_one_outputs: Outputs<RoundOneOutput>,
		// round_two_outputs: Outputs<RoundTwoOutput>,
		final_output: FinalOutput,
	}

	#[derive(Deserialize)]
	struct Inputs {
		verifying_key_key: String,
		message: String,
		participant_shares: Vec<ParticipantShare>,
		participant_list: Vec<u32>,
	}

	#[derive(Deserialize)]
	struct Outputs<T> {
		outputs: Vec<T>,
	}

	#[derive(Deserialize)]
	struct FinalOutput {
		sig: String,
	}

	fn scalar_from_hex(s: &str) -> Scalar {
		let bytes = <[u8; 32]>::from_hex(s).unwrap();
		Scalar::from_bytes_mod_order(bytes)
	}

	fn point_from_hex(s: &str) -> EdwardsPoint {
		let bytes = <[u8; 32]>::from_hex(s).unwrap();

		CompressedEdwardsY(bytes).decompress().unwrap()
	}

	#[test]
	fn test_frost_vectors_holds() {
		let data = std::fs::read_to_string("frost_vec.json").unwrap();
		let v: FrostVector = serde_json::from_str(&data).unwrap();

		let group_pk_bytes = <[u8; 32]>::from_hex(&v.inputs.verifying_key_key).unwrap();
		let vk = VerifyingKey::from_bytes(&group_pk_bytes).unwrap();
		let pk = GroupPubKey(point_from_hex(&v.inputs.verifying_key_key));

		let msg = <Vec<u8>>::from_hex(&v.inputs.message).unwrap();

		let sig_bytes = <[u8; 64]>::from_hex(&v.final_output.sig).unwrap();
		let sig = Signature::from_bytes(&sig_bytes);

		// recompute R (aggregated nonce commitment)
		let mut g_comm = EdwardsPoint::identity();
		let mut betas = Vec::new();

		for o in &v.round_one_outputs.outputs {
			let hiding = point_from_hex(&o.hiding_nonce_commitment);
			let binding = point_from_hex(&o.binding_nonce_commitment);
			let beta = scalar_from_hex(&o.binding_factor);
			g_comm += hiding + beta * binding;
			betas.push((o.identifier, beta));
		}

		let c = challenge(&g_comm, &pk, &msg);
		let mut sig_shares = Vec::new();

		for (o, (_, beta)) in v.round_one_outputs.outputs.iter().zip(betas.iter()) {
			// parse participant secret share
			let x_i_hex = v
				.inputs
				.participant_shares
				.iter()
				.find(|s| s.identifier == o.identifier)
				.unwrap()
				.participant_share
				.clone();

			let x_i = scalar_from_hex(&x_i_hex);
			let lambda_i = lagrange_at_zero(o.identifier, &v.inputs.participant_list);

			let r1 = scalar_from_hex(&o.hiding_nonce);
			let r2 = scalar_from_hex(&o.binding_nonce);

			let z_i = sign_share(x_i, lambda_i, r1, r2, *beta, c);

			sig_shares.push(z_i);
		}

		let combined = combine_sig(g_comm, &sig_shares);

		assert_eq!(
			combined.to_bytes(),
			sig_bytes,
			"combined signature does not match test vector"
		);

		vk.verify(&msg, &sig).expect("signature should verify");
	}
}
