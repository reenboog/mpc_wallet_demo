use std::net::SocketAddr;

use axum::{extract, response::IntoResponse, routing::post, Json};
use http::{HeaderMap, StatusCode};
use shared::{
	self,
	id::Uid,
	mpc_math,
	salt::Salt,
	serialize,
	share::{self, Part, SignFinal, SignFinalRes, SignReq, SignRes, SignupReq, SignupRes},
	tokio, Scalar,
};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{self, Level};
use tracing_subscriber::{self, layer::SubscriberExt, util::SubscriberInitExt};

use crate::state::State;

mod state;
mod store;

enum Error {
	NotFound,
	AlreadyExists(Uid),
	BadShare,
	BadComm,
	Protocol,
}

impl IntoResponse for Error {
	fn into_response(self) -> axum::response::Response {
		match self {
			Error::NotFound => (StatusCode::NOT_FOUND, "not found"),
			Error::AlreadyExists(id) => (StatusCode::CONFLICT, "share already exists"),
			Error::BadShare => (StatusCode::BAD_REQUEST, "bad share"),
			Error::BadComm => (StatusCode::BAD_REQUEST, "bad commitment"),
			Error::Protocol => (StatusCode::INTERNAL_SERVER_ERROR, "mpc protocol failed"),
		}
		.into_response()
	}
}

async fn signup(
	extract::State(state): extract::State<State>,
	extract::Json(req): extract::Json<SignupReq>,
) -> Result<Json<SignupRes>, Error> {
	tracing::debug!("received {:?}", req);

	let incoming_share =
		mpc_math::SecretShare::try_from(req.share.secret_share).map_err(|_| Error::BadShare)?;
	let client_comms = req
		.share
		.commitments
		.into_iter()
		.map(mpc_math::PolyComm::try_from)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|_| Error::BadComm)?;

	if !mpc_math::verify_share(&incoming_share, &client_comms) {
		Err(Error::BadComm)
	} else {
		let (comms, mut shares) = mpc_math::dkg_gen(req.n as usize, req.t as usize);
		// server's share is 2
		let my_share = shares.pop().ok_or(Error::Protocol)?;
		// client share is 1
		let outgoing_share = shares.pop().ok_or(Error::Protocol)?;
		let priv_share = mpc_math::combine_shares(&[my_share, incoming_share]);
		let group_pk = mpc_math::compute_group_pk(&[client_comms, comms.clone()]);
		let id = Uid::gen();

		tracing::info!(
			"my share: {}\npublic key: {}\nid: {}",
			serialize::to_base64(priv_share.as_bytes()).unwrap(),
			serialize::to_base64(group_pk.0.compress().as_bytes()).unwrap(),
			id,
		);

		let acl_token = state
			.store
			.put_share(id, priv_share, group_pk)
			.map_err(|_| Error::AlreadyExists(id))?;

		Ok(Json(SignupRes {
			id,
			share: Part {
				sender_idx: 2,
				secret_share: outgoing_share.into(),
				commitments: comms.into_iter().map(share::PolyComm::from).collect(),
			},
			acl_token,
		}))
	}
}

async fn sign_commit(
	extract::State(state): extract::State<State>,
	extract::Json(req): extract::Json<SignReq>,
) -> Result<Json<SignRes>, Error> {
	tracing::debug!("received {:?}", req);

	let (priv_share, _) = state.store.get_share(&req.key_id).ok_or(Error::NotFound)?;
	let sig_req_id = Uid::gen();
	let nonce = mpc_math::nonces_with_params(&priv_share, &req.msg, Salt::gen().as_bytes());
	let comm = share::NonceComm::from(nonce.clone());

	// store my nonce (private) and their commitment (public)
	// used later to combine into a signature
	state
		.store
		.put_nonce(
			sig_req_id,
			nonce,
			req.comm.try_into().map_err(|_| Error::BadComm)?,
		)
		.map_err(|_| Error::AlreadyExists(sig_req_id))?;

	Ok(Json(SignRes {
		sid: sig_req_id,
		comm,
	}))
}

async fn sign_final(
	extract::State(state): extract::State<State>,
	extract::Json(req): extract::Json<SignFinal>,
) -> Result<Json<SignFinalRes>, Error> {
	// lookup private share
	let (priv_share, _) = state.store.get_share(&req.key_id).ok_or(Error::NotFound)?;
	// load and clear stored session
	let (nonce, client_comm) = state
		.store
		.take_nonce(req.sid)
		.map_err(|_| Error::NotFound)?;
	// rebuild my comm from stored nonce
	let server_comm = mpc_math::NonceComm {
		r1_pt: nonce.r1_pt,
		r2_pt: nonce.r2_pt,
	};
	// recompute betas; client is always 1, server is always 2 in our scheme
	let idcs = [1u32, 2u32];
	let comms = vec![client_comm, server_comm];
	let (betas, _g_comm_check) = mpc_math::binding_and_group_comm(&idcs, &comms);
	// parse challenge
	let c = Option::from(Scalar::from_canonical_bytes(req.c)).ok_or(Error::Protocol)?;
	// get server’s beta; server is always 2 in our current flow
	let beta_server = betas[1];
	// Lagrange coefficient
	let lam = mpc_math::lagrange_at_zero(2, &idcs);
	// server partial
	let z_server = mpc_math::partial_z(&nonce, beta_server, c, lam, priv_share);

	Ok(Json(SignFinalRes {
		server_partial: z_server.to_bytes(),
	}))
}

fn router(state: State) -> axum::Router {
	axum::Router::new()
		.route("/signup", post(signup))
		.route("/sign/commit", post(sign_commit))
		.route("/sign/final", post(sign_final))
		.layer(
			TraceLayer::new_for_http().make_span_with(
				DefaultMakeSpan::new()
					.level(Level::TRACE)
					.include_headers(true),
			),
		)
		.with_state(state)
}

#[tokio::main]
async fn main() {
	let crate_name = env!("CARGO_CRATE_NAME");
	tracing_subscriber::registry()
		.with(
			tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
				format!("{}=debug,tower_http=info,axum::rejection=trace", crate_name).into()
			}),
		)
		.with(tracing_subscriber::fmt::layer())
		.init();
	tracing::info!("starting {}...", crate_name);

	let state = State::new(store::Store::new());
	let router = router(state);
	let port = 8081;
	let addr = SocketAddr::from(([0, 0, 0, 0], port));
	let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

	axum::serve(
		listener,
		router.into_make_service_with_connect_info::<SocketAddr>(),
	)
	.await
	.unwrap();
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_ok() {
		assert!(true);
	}
}
