use std::net::SocketAddr;

use axum::{extract, response::IntoResponse, routing::post, Json};
use http::{HeaderMap, StatusCode};
use shared::{
	self,
	id::Uid,
	mpc_math, serialize,
	share::{self, Part, SignupReq, SignupRes},
	tokio,
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
	headers: HeaderMap,
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

		state
			.store
			.put(id, priv_share, group_pk)
			.map_err(|_| Error::NotFound)?;

		Ok(Json(SignupRes {
			id,
			share: Part {
				sender_idx: 2,
				secret_share: outgoing_share.into(),
				commitments: comms.into_iter().map(share::PolyComm::from).collect(),
			},
		}))
	}
}

fn router(state: State) -> axum::Router {
	axum::Router::new()
		.route("/signup", post(signup))
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
