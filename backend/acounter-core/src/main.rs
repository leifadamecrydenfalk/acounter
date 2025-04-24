// src/main.rs
use anyhow::{Context, Result}; // Keep for main's error handling
use axum::http::StatusCode as AxumStatusCode;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use thiserror::Error; // Keep for AppError
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

// Import the specific error type now
mod fortnox_client;
use fortnox_client::{
    run_fortnox_token_refresh,
    AuthCallbackParams,
    FortnoxClient,
    FortnoxConfig,
    FortnoxError, // Import FortnoxError
    DEFAULT_CACHE_DURATION_SECS,
};

// --- AppError Definition (Update Fortnox variant) ---
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    // Now directly holds the specific FortnoxError
    #[error("Fortnox API client error")]
    Fortnox(#[from] FortnoxError), // Use #[from] for automatic conversion via ?

                                   // Keep a general anyhow variant for other unexpected errors in main? Optional.
                                   // #[error("Internal Server Error: {0}")]
                                   // Internal(#[from] anyhow::Error),
}

// --- IntoResponse Implementation (Match on specific FortnoxError) ---
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // Log the full error details
        error!("Error occurred: {:?}", self); // Use Debug format

        let (status_code, error_message) = match &self {
            AppError::MissingEnvVar(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Server configuration error.",
            ),
            AppError::Io(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Server file I/O error.",
            ),
            AppError::TlsConfig(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Server TLS configuration error.",
            ),

            // Handle specific Fortnox errors for better HTTP responses
            AppError::Fortnox(fortnox_err) => match fortnox_err {
                FortnoxError::OAuthStateMismatch => (
                    AxumStatusCode::BAD_REQUEST,
                    "OAuth state validation failed.",
                ),
                FortnoxError::MissingAuthCode => (
                    AxumStatusCode::BAD_REQUEST,
                    "Authorization code missing in callback.",
                ),
                FortnoxError::MissingToken => (
                    AxumStatusCode::UNAUTHORIZED,
                    "Authentication token not available. Please authorize.",
                ),
                FortnoxError::TokenRefreshFailed { status, message } => {
                    error!(
                        "Token Refresh Failure: Status={:?}, Msg={}",
                        status, message
                    );
                    (
                        AxumStatusCode::UNAUTHORIZED,
                        "Token refresh failed. Please re-authorize.",
                    )
                }
                FortnoxError::RateLimitExceeded => (
                    AxumStatusCode::TOO_MANY_REQUESTS,
                    "Fortnox API rate limit exceeded. Please try again later.",
                ),
                FortnoxError::ApiError { status, message } => {
                    // Map Fortnox status code to Axum status code
                    let axum_status = AxumStatusCode::from_u16(status.as_u16())
                        .unwrap_or(AxumStatusCode::INTERNAL_SERVER_ERROR);
                    error!("Fortnox API Error: Status={}, Msg={}", status, message);
                    // Provide generic message for API errors unless specific handling is needed
                    (
                        axum_status,
                        "An error occurred while communicating with Fortnox API.",
                    )
                }
                FortnoxError::Request(e) => {
                    error!("Network request error to Fortnox: {}", e);
                    (
                        AxumStatusCode::BAD_GATEWAY,
                        "Failed to connect to Fortnox API.",
                    )
                }
                FortnoxError::Json(e) => {
                    error!("JSON processing error related to Fortnox: {}", e);
                    (
                        AxumStatusCode::INTERNAL_SERVER_ERROR,
                        "Internal error processing Fortnox data.",
                    )
                }
                FortnoxError::Io { source, context } => {
                    error!("I/O error related to Fortnox ({}) : {}", context, source);
                    (
                        AxumStatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error (Fortnox I/O).",
                    )
                }
                FortnoxError::UrlParse(e) => {
                    error!("URL parsing error related to Fortnox: {}", e);
                    (
                        AxumStatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error (Fortnox URL config).",
                    )
                }
                FortnoxError::TimeError(msg) => {
                    error!("System time error related to Fortnox: {}", msg);
                    (
                        AxumStatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error (Time).",
                    )
                }
                FortnoxError::LockError(msg) => {
                    error!("Concurrency lock error related to Fortnox: {}", msg);
                    (
                        AxumStatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error (Concurrency).",
                    )
                }
                FortnoxError::CacheError(msg) => {
                    error!("Cache error related to Fortnox: {}", msg);
                    (
                        AxumStatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error (Cache).",
                    )
                }
                FortnoxError::ConfigError(msg) => {
                    error!("Configuration error in Fortnox client: {}", msg);
                    (
                        AxumStatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error (Fortnox Config).",
                    )
                }
            },
            // Handle other AppError variants if they exist
            // AppError::Internal(e) => (AxumStatusCode::INTERNAL_SERVER_ERROR, "An unexpected internal server error occurred."),
        };

        (
            status_code,
            Html(format!("<h1>Error</h1><p>{}</p>", error_message)),
        )
            .into_response()
    }
}

// --- General App Configuration (remains the same) ---
#[derive(Debug, Clone)]
struct AppConfig {
    cert_path: String,
    key_path: String,
}

// --- Application State (remains the same) ---
#[derive(Clone)]
pub struct AppState {
    pub fortnox_client: Arc<FortnoxClient>,
}

// --- Main Function (Adjust error mapping) ---
#[tokio::main]
async fn main() -> Result<()> {
    // Use anyhow::Result for top-level reporting
    // --- Setup (remains the same) ---
    dotenv::dotenv().ok();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Setting tracing subscriber failed")?;
    info!("Tracing subscriber initialized.");

    // --- Load Configurations (use AppError for specific load errors) ---
    let app_config = load_app_config()?; // Returns Result<_, AppError>
    info!("App configuration loaded.");
    let fortnox_config = load_fortnox_config()?; // Returns Result<_, AppError>
    info!("Fortnox configuration loaded.");

    // --- Create Fortnox Client (new returns Result<_, FortnoxError>) ---
    // Use ? which automatically converts FortnoxError -> AppError::Fortnox via #[from]
    let fortnox_client = FortnoxClient::new(fortnox_config)?;
    let fortnox_client = Arc::new(fortnox_client);
    info!("Fortnox Client initialized.");

    // --- Start background token refresh task (remains the same) ---
    let refresh_client = fortnox_client.clone();
    tokio::spawn(run_fortnox_token_refresh(refresh_client));

    // --- Create Shared App State (remains the same) ---
    let state = AppState { fortnox_client };
    info!("Application state initialized.");

    // --- Define Routes (remains the same) ---
    let fortnox_routes = Router::new()
        .route("/auth", get(handle_api_fortnox_auth))
        .route("/auth/callback", get(handle_api_fortnox_auth_callback));
    let api_routes = Router::new().nest("/fortnox", fortnox_routes);
    let app = Router::new()
        .nest("/api", api_routes)
        .route("/status", get(handle_status))
        .with_state(state);

    // --- Configure TLS (load_tls_config returns Result<_, AppError>) ---
    let tls_config = load_tls_config(&app_config).await?;
    info!("TLS configuration loaded.");

    // --- Run Web Server (remains the same) ---
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Starting server on https://{}", addr);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("HTTPS server failed")?; // Add context for anyhow

    Ok(())
}

// --- Helper Functions for Configuration Loading (return AppError) ---
fn load_app_config() -> Result<AppConfig, AppError> {
    Ok(AppConfig {
        cert_path: env::var("CERT_PATH")
            .map_err(|_| AppError::MissingEnvVar("CERT_PATH".to_string()))?,
        key_path: env::var("KEY_PATH")
            .map_err(|_| AppError::MissingEnvVar("KEY_PATH".to_string()))?,
    })
}

fn load_fortnox_config() -> Result<FortnoxConfig, AppError> {
    // These could potentially return FortnoxError::ConfigError if desired,
    // but AppError::MissingEnvVar is fine for application setup.
    Ok(FortnoxConfig {
        client_id: env::var("FORTNOX_CLIENT_ID")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_CLIENT_ID".to_string()))?,
        client_secret: env::var("FORTNOX_CLIENT_SECRET")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_CLIENT_SECRET".to_string()))?,
        redirect_uri: env::var("FORTNOX_REDIRECT_URI")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_REDIRECT_URI".to_string()))?,
        scopes: env::var("FORTNOX_SCOPES")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_SCOPES".to_string()))?,
        token_file_path: env::var("TOKEN_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("fortnox_token.json")), // Consistent default
        cache_dir: PathBuf::from(
            env::var("CACHE_DIR").unwrap_or_else(|_| "./fortnox_cache".to_string()),
        ),
        cache_duration_secs: env::var("CACHE_DURATION_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_CACHE_DURATION_SECS),
    })
}

async fn load_tls_config(config: &AppConfig) -> Result<RustlsConfig, AppError> {
    RustlsConfig::from_pem_file(&config.cert_path, &config.key_path)
        .await
        .map_err(|e| AppError::TlsConfig(format!("Failed to load TLS cert/key: {}", e)))
}

// --- Route Handlers (use ? with automatic FortnoxError -> AppError conversion) ---
async fn handle_api_fortnox_auth(State(state): State<AppState>) -> Result<Redirect, AppError> {
    info!("Handling /api/fortnox/auth request...");
    // generate_auth_url returns FortnoxError, ? converts to AppError::Fortnox
    let auth_url = state.fortnox_client.generate_auth_url().await?;
    Ok(Redirect::temporary(&auth_url))
}

async fn handle_api_fortnox_auth_callback(
    State(state): State<AppState>,
    Query(params): Query<AuthCallbackParams>,
) -> Result<Html<String>, AppError> {
    info!("Handling /api/fortnox/auth/callback...");
    // handle_auth_callback returns FortnoxError, ? converts to AppError::Fortnox
    state.fortnox_client.handle_auth_callback(params).await?;
    info!("Successfully handled Fortnox auth callback.");
    Ok(Html(
        "<h1>Success!</h1><p>Authentication successful. Token data saved.</p>".to_string(),
    ))
}

async fn handle_status(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    info!("Handling /status request...");
    // get_token_status returns FortnoxError, ? converts to AppError::Fortnox
    let status = state.fortnox_client.get_token_status().await?;

    let status_message = format!(
        "Token Status: has_token={}, is_valid={}, is_expired={}, expires_in={}s, expires_at={}",
        status.has_token,
        status.is_valid,
        status.is_expired,
        status.expires_in_secs,
        status.expires_at
    );

    let html_body = format!(
        "<h1>Server Status</h1><p>Current Time (Server): {}</p><p>{}</p><hr><p><a href='/api/fortnox/auth'>Re-authorize with Fortnox</a></p>",
        chrono::Local::now().to_rfc3339(),
        status_message
    );
    Ok(Html(html_body))
}
