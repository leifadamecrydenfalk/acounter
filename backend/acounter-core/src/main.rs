// src/main.rs
use axum::http::StatusCode as AxumStatusCode;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, Method, RequestBuilder, StatusCode as ReqwestStatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::{
    env,
    fs::{self, File},
    io::Write, // Removed BufReader (not used), kept Write
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::sleep; // For example task delay
use tracing::{error, info, warn, Level}; // Added warn
use tracing_subscriber::FmtSubscriber;
use url::Url;

use axum_server::tls_rustls::RustlsConfig;

mod fortnox;
pub use fortnox::*;

mod time_validation;
pub use time_validation::*;

mod time_validation_tests;
pub use time_validation_tests::*;

// --- Configuration & Constants ---

const INFO_CACHE_FILE_NAME: &str = "fortnox_info_cache.json";
const INFO_CACHE_DURATION_SECS: u64 = 24 * 60 * 60;
const TOKEN_FILE_NAME: &str = "fortnox_token.json";

// --- !! SECURITY WARNING !! ---
// Storing tokens in a plain text file is NOT recommended for production.
// Use environment variables, a secure vault, database with encryption,
// or OS-level secure storage. Ensure file permissions are restrictive.
// --- !! SECURITY WARNING !! ---

// --- Error Handling (Mostly Unchanged, added FortnoxServiceError variant) ---

// --- Fortnox Specific Error Payload Parsing ---
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")] // Assuming PascalCase based on the example
pub struct FortnoxErrorInformation {
    pub error: Option<serde_json::Value>, // Use Value for flexibility (could be int or string)
    pub message: Option<String>,
    pub code: Option<serde_json::Value>, // Use Value for flexibility
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")] // Assuming root is PascalCase
pub struct FortnoxErrorPayload {
    #[serde(rename = "ErrorInformation")]
    pub error_information: FortnoxErrorInformation,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),
    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("URL parsing failed: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("JSON serialization/deserialization failed: {0}")]
    SerdeJson(#[from] serde_json::Error), // Correct type
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OAuth state mismatch")]
    OAuthStateMismatch,

    // Enhanced Fortnox API Error
    #[error("Fortnox API Error: Status={status}, Parsed={parsed_error:?}, Raw={raw_message:?}")]
    FortnoxApiError {
        status: ReqwestStatusCode,
        parsed_error: Option<FortnoxErrorPayload>, // Store parsed structure
        raw_message: Option<String>,               // Keep raw as fallback
    },
    #[error("Fortnox API rate limit exceeded (Status 429)")]
    FortnoxRateLimited, // Specific variant for rate limiting

    #[error("Failed to acquire lock")]
    LockError,
    #[error("Authorization code not received")]
    MissingAuthCode,
    #[error("Access token not available or refresh failed")]
    MissingOrInvalidToken,
    #[error("System time error: {0}")]
    SystemTimeError(String),
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
    #[error("Fortnox Service Error: {0}")]
    FortnoxServiceError(String),
    // Added variant for specific deserialization issue on success response
    #[error("Failed to deserialize successful response body: {0}")]
    SuccessfulResponseDeserialization(reqwest::Error),
}

// Map AppError to Axum's IntoResponse
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        error!("Error occurred: {}", self); // Log the original error

        let (status_code, error_message) = match self {
            // Handling for the new variant
            AppError::SuccessfulResponseDeserialization(ref _e) =>
                (
                    AxumStatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error (Unexpected response format from Fortnox). Check logs.".to_string(),
                ),

            // Ensure all existing mappings are correct
            AppError::MissingEnvVar(ref _var) =>
                (AxumStatusCode::INTERNAL_SERVER_ERROR, "Configuration error.".to_string()),
            AppError::Reqwest(ref _e) =>
                (AxumStatusCode::BAD_GATEWAY, "External request failed.".to_string()),
            AppError::UrlParse(_) =>
                (
                    AxumStatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error (URL parsing).".to_string(),
                ),
            AppError::SerdeJson(_) =>
                (
                    AxumStatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error (JSON processing).".to_string(),
                ),
            AppError::Io(_) =>
                (
                    AxumStatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error (File I/O). Check logs.".to_string(),
                ),
            AppError::OAuthStateMismatch =>
                (AxumStatusCode::BAD_REQUEST, "OAuth state validation failed.".to_string()),
            AppError::FortnoxApiError { status, .. } => {
                // Simplified match arm
                let axum_status = AxumStatusCode::from_u16(status.as_u16()).unwrap_or(
                    AxumStatusCode::INTERNAL_SERVER_ERROR
                );

                let user_message = format!(
                    "Failed to communicate with Fortnox API (Status {}). Details logged.",
                    status.as_u16()
                );
                (axum_status, user_message)
            }
            AppError::FortnoxRateLimited =>
                (
                    AxumStatusCode::TOO_MANY_REQUESTS,
                    "Fortnox API rate limit exceeded. Please try again later.".to_string(),
                ),
            AppError::LockError =>
                (
                    AxumStatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error (Concurrency).".to_string(),
                ),
            AppError::MissingAuthCode =>
                (
                    AxumStatusCode::BAD_REQUEST,
                    "Authorization code missing in callback.".to_string(),
                ),
            AppError::MissingOrInvalidToken =>
                (
                    AxumStatusCode::UNAUTHORIZED,
                    "Authentication token not available, expired, or refresh failed. Please try authenticating again via /api/fortnox/auth".to_string(),
                ),
            AppError::SystemTimeError(ref msg) =>
                (
                    AxumStatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal Server Error (Time Calculation: {})", msg),
                ),
            AppError::TlsConfig(ref msg) =>
                (
                    AxumStatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal server error (TLS Setup: {}). Check logs.", msg),
                ),
            AppError::FortnoxServiceError(ref msg) =>
                (
                    AxumStatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal Fortnox Service Error: {}", msg),
                ),
        };

        (
            status_code,
            Html(format!("<h1>Error</h1><p>{}</p>", error_message)),
        )
            .into_response()
    }
}

// --- General App Configuration ---
#[derive(Debug, Clone)]
struct AppConfig {
    cert_path: String,
    key_path: String,
    // Add other non-Fortnox config here if needed
}
#[tokio::main]
async fn main() -> Result<(), AppError> {
    // --- Setup ---
    dotenv::dotenv().ok();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // --- Load General App Configuration ---
    let app_config = AppConfig {
        cert_path: env::var("CERT_PATH")
            .map_err(|_| AppError::MissingEnvVar("CERT_PATH".into()))?,
        key_path: env::var("KEY_PATH").map_err(|_| AppError::MissingEnvVar("KEY_PATH".into()))?,
    };
    info!("App configuration loaded.");

    // --- Load Fortnox Configuration using the new FortnoxConfig struct ---
    let fortnox_config = FortnoxConfig {
        client_id: env::var("FORTNOX_CLIENT_ID")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_CLIENT_ID".into()))?,
        client_secret: env::var("FORTNOX_CLIENT_SECRET")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_CLIENT_SECRET".into()))?,
        redirect_uri: env::var("FORTNOX_REDIRECT_URI")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_REDIRECT_URI".into()))?,
        scopes: env::var("FORTNOX_SCOPES")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_SCOPES".into()))?,
        token_file_path: env::var("TOKEN_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(TOKEN_FILE_NAME)),
        cache_dir: PathBuf::from("./fortnox_cache"),
        cache_duration_secs: DEFAULT_CACHE_DURATION_SECS,
    };
    info!("Fortnox configuration loaded.");

    // --- Create Fortnox Client from the new module ---
    let fortnox_client = match FortnoxClient::new(fortnox_config) {
        Ok(client) => Arc::new(client),
        Err(e) => {
            error!("Failed to initialize FortnoxClient: {}", e);
            return Err(convert_fortnox_error(e));
        }
    };
    info!("Fortnox Client initialized.");

    // --- Start background token refresh task ---
    let refresh_client = fortnox_client.clone();
    tokio::spawn(async move {
        // Create a span for the background task
        let span = tracing::info_span!(
            "token_refresh_task",
            component = "Background task: Refresh token"
        );
        let _enter = span.enter();

        info!("Starting background token refresh task");
        const CHECK_INTERVAL_SECS_DEFAULT: u64 = 300; // 5 minutes
        let mut check_interval_secs = CHECK_INTERVAL_SECS_DEFAULT;

        loop {
            // Check token status
            match refresh_client.get_token_status().await {
                Ok(status) => {
                    if status.has_token {
                        // If token exists
                        if !status.is_valid || status.expires_in_secs < 600 {
                            // Token is invalid or expires in less than 10 minutes
                            info!(
                                "Token is invalid or expires soon (in {} seconds). Attempting refresh...",
                                status.expires_in_secs
                            );

                            // Attempt to get a valid token, which triggers refresh if needed
                            match refresh_client.get_valid_access_token().await {
                                Ok(_) => info!("Token refreshed successfully"),
                                Err(e) => {
                                    error!("Failed to refresh token: {}", convert_fortnox_error(e));
                                    // Reset check interval to default when refresh fails
                                    check_interval_secs = CHECK_INTERVAL_SECS_DEFAULT;
                                }
                            }
                        } else {
                            // Check again after the token has expired
                            check_interval_secs = status.expires_in_secs + 10;
                            info!("Token is valid for {} more seconds", status.expires_in_secs);
                        }
                    } else {
                        info!("No token available. Waiting for user authentication.");
                    }
                }
                Err(e) => {
                    error!("Failed to check token status: {}", e);
                    // Also reset interval on token status check failure
                    check_interval_secs = CHECK_INTERVAL_SECS_DEFAULT;
                }
            }

            // Sleep before next check
            sleep(Duration::from_secs(check_interval_secs)).await;
        }
    });

    let time_validation_service = Arc::new(Mutex::new(TimeValidationService::new()));

    // --- Create Shared App State with FortnoxClient ---
    let state = AppState {
        fortnox_client: fortnox_client.clone(),
        time_validation_service: time_validation_service.clone(),
    };
    info!("Application state initialized.");

    // --- Define Routes ---
    let fortnox_routes = Router::new()
        .route("/auth", get(handle_api_fortnox_auth))
        .route("/auth/callback", get(handle_api_fortnox_auth_callback));

    let api_routes = Router::new().nest("/fortnox", fortnox_routes);

    let app = Router::new()
        .nest("/api", api_routes)
        .route("/status", get(handle_status))
        .with_state(state.clone());

    // --- Configure TLS ---
    let tls_config = match RustlsConfig::from_pem_file(
        PathBuf::from(&app_config.cert_path),
        PathBuf::from(&app_config.key_path),
    )
    .await
    {
        Ok(config) => config,
        Err(e) => {
            let err_msg = format!("Failed to load TLS cert/key: {}", e);
            error!("{}", err_msg);
            return Err(AppError::TlsConfig(err_msg));
        }
    };
    info!(
        "TLS configuration loaded successfully from {} and {}",
        app_config.cert_path, app_config.key_path
    );

    // --- Run Web Server ---
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Starting server on https://{}", addr);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

// Helper function to convert FortnoxError to AppError
fn convert_fortnox_error(e: FortnoxError) -> AppError {
    match e {
        FortnoxError::RequestFailed(req_err) => AppError::Reqwest(req_err),
        FortnoxError::JsonError(json_err) => AppError::SerdeJson(json_err),
        FortnoxError::IoError(io_err) => AppError::Io(io_err),
        FortnoxError::UrlParseError(url_err) => AppError::UrlParse(url_err),
        FortnoxError::OAuthStateMismatch => AppError::OAuthStateMismatch,
        FortnoxError::MissingAuthCode => AppError::MissingAuthCode,
        FortnoxError::MissingToken => AppError::MissingOrInvalidToken,
        FortnoxError::TokenRefreshFailed => AppError::MissingOrInvalidToken,
        FortnoxError::RateLimitExceeded => AppError::FortnoxRateLimited,
        FortnoxError::ApiError { status, message } => AppError::FortnoxApiError {
            status: reqwest::StatusCode::from_u16(status.as_u16())
                .unwrap_or(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            parsed_error: None,
            raw_message: Some(message),
        },
        FortnoxError::TimeError(msg) => AppError::SystemTimeError(msg),
        FortnoxError::LockError => AppError::LockError,
        FortnoxError::CacheError(msg) => AppError::FortnoxServiceError(msg),
    }
}

// Updated AppState to use FortnoxClient
#[derive(Clone)]
struct AppState {
    fortnox_client: Arc<FortnoxClient>,
    time_validation_service: Arc<Mutex<TimeValidationService>>,
}

// Updated route handlers to use FortnoxClient
async fn handle_api_fortnox_auth(State(state): State<AppState>) -> Result<Redirect, AppError> {
    info!("Handling /api/fortnox/auth request, initiating OAuth flow...");

    let auth_url = state
        .fortnox_client
        .generate_auth_url()
        .await
        .map_err(convert_fortnox_error)?;

    Ok(Redirect::temporary(&auth_url))
}

async fn handle_api_fortnox_auth_callback(
    State(state): State<AppState>,
    Query(params): Query<AuthCallbackParams>,
) -> Result<Html<String>, AppError> {
    info!("Handling /api/fortnox/auth/callback, processing OAuth callback...");

    match state.fortnox_client.handle_auth_callback(params).await {
        Ok(_) => {
            info!("Successfully handled Fortnox auth callback.");

            Ok(
                Html(
                    "<h1>Success!</h1><p>Authentication successful. Token data saved.</p><p>Server is now authorized with Fortnox API.</p><p>You can close this window.</p>".to_string()
                )
            )
        }
        Err(e) => {
            error!("Failed to handle Fortnox auth callback: {}", e);
            Err(convert_fortnox_error(e))
        }
    }
}

async fn handle_status(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    info!("Handling /status request...");

    let token_status = match state.fortnox_client.get_token_status().await {
        Ok(status) => format!(
            "Token Status: has_token={}, is_valid={}, expires_in={}s, expires_at={}",
            status.has_token, status.is_valid, status.expires_in_secs, status.expires_at
        ),
        Err(e) => {
            error!("Failed to get token status: {}", e);
            format!("Failed to get token status: {}", e)
        }
    };

    let html_body = format!(
        "<h1>Server Status</h1><p>Current Time (Server): {}</p><p>{}</p><p><a href='/api/fortnox/auth'>Authorize with Fortnox</a></p>",
        chrono::Local::now().to_rfc3339(),
        token_status
    );

    Ok(Html(html_body))
}
