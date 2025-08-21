use std::net::SocketAddr;

use axum::{Json, extract, response::IntoResponse, routing::post};
use http::{HeaderMap, StatusCode};
use shared::{
	self,
	auth::{SignupReq, SignupRes},
	tokio,
};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::{self, Level};
use tracing_subscriber::{self, layer::SubscriberExt, util::SubscriberInitExt};

use crate::state::State;

mod state;

enum Error {
	NotFound,
}

impl IntoResponse for Error {
	fn into_response(self) -> axum::response::Response {
		match self {
			Error::NotFound => (StatusCode::NOT_FOUND, ""),
		}
		.into_response()
	}
}

async fn signup(
	extract::State(state): extract::State<State>,
	headers: HeaderMap,
	extract::Json(req): extract::Json<SignupReq>,
) -> Result<Json<SignupRes>, Error> {
	tracing::debug!("received {}", req.id);

	Ok(Json(SignupRes { id: req.id }))
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

	let state = State {};
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
