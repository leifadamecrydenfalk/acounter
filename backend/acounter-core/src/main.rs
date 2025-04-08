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
use reqwest::{Client, Method, RequestBuilder};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

mod fortnox_info;
pub use fortnox_info::*;

// --- Configuration & Constants ---

const INFO_CACHE_FILE_NAME: &str = "fortnox_info_cache.json";
const INFO_CACHE_DURATION_SECS: u64 = 24 * 60 * 60; 

// Moved Fortnox URLs into FortnoxService as associated constants
const TOKEN_FILE_NAME: &str = "fortnox_token.json"; // Just the filename

// --- !! SECURITY WARNING !! ---
// Storing tokens in a plain text file is NOT recommended for production.
// Use environment variables, a secure vault, database with encryption,
// or OS-level secure storage. Ensure file permissions are restrictive.
// --- !! SECURITY WARNING !! ---

// --- Error Handling (Mostly Unchanged, added FortnoxServiceError variant) ---

#[derive(Error, Debug)]
enum AppError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),
    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("URL parsing failed: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("JSON serialization/deserialization failed: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OAuth state mismatch")]
    OAuthStateMismatch,
    #[error("Fortnox API returned an error: {status} - {message:?}")]
    FortnoxApiError {
        status: reqwest::StatusCode,
        message: Option<String>,
    },
    #[error("Failed to acquire lock")]
    LockError, // Potentially removable if Mutex contention isn't expected
    #[error("Authorization code not received")]
    MissingAuthCode,
    #[error("Access token not available or refresh failed")]
    MissingOrInvalidToken, // Renamed for clarity
    #[error("System time error: {0}")]
    SystemTimeError(String), // Added for time errors
    #[error("TLS configuration error: {0}")] // Added for TLS errors
    TlsConfig(String),
    #[error("Fortnox Service Error: {0}")] // Wrapper for internal service errors
    FortnoxServiceError(String), // Can wrap specific internal errors if needed
}

// Map AppError to Axum's IntoResponse
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        error!("Error occurred: {}", self); // Log the original error

        let (status_code, error_message) = match self {
            AppError::MissingEnvVar(ref _var) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                format!("Configuration error."),
            ),
            AppError::Reqwest(ref _e) => (
                AxumStatusCode::BAD_GATEWAY,
                format!("External request failed."),
            ),
            AppError::UrlParse(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error (URL parsing)."),
            ),
            AppError::SerdeJson(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error (JSON processing)."),
            ),
            AppError::Io(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error (File I/O). Check logs."),
            ),
            AppError::OAuthStateMismatch => (
                AxumStatusCode::BAD_REQUEST,
                "OAuth state validation failed.".to_string(),
            ),
            AppError::FortnoxApiError { status, ref message } => {
                let axum_status = AxumStatusCode::from_u16(status.as_u16())
                    .unwrap_or(AxumStatusCode::INTERNAL_SERVER_ERROR);
                let user_message = format!(
                    "Failed to communicate with Fortnox API (Status {}). Details logged.",
                    status.as_u16()
                );
                error!("Fortnox API Error Details: Status: {}, Message: {:?}", status, message);
                (axum_status, user_message)
            }
            AppError::LockError => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error (Concurrency).".to_string(),
            ),
            AppError::MissingAuthCode => (
                AxumStatusCode::BAD_REQUEST,
                "Authorization code missing in callback.".to_string(),
            ),
            AppError::MissingOrInvalidToken => (
                (AxumStatusCode::UNAUTHORIZED,
                "Authentication token not available, expired, or refresh failed. Please try authenticating again via /".to_string())
            ),
             AppError::SystemTimeError(ref msg) => (
                 AxumStatusCode::INTERNAL_SERVER_ERROR,
                 format!("Internal Server Error (Time Calculation: {})", msg)
             ),
             AppError::TlsConfig(ref msg) => ( // Added TLS error handling
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error (TLS Setup: {}). Check logs.", msg)
            ),
            AppError::FortnoxServiceError(ref msg) => ( // Added Fortnox Service Error
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal Fortnox Service Error: {}", msg) // Keep internal details generic for user
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

// --- Fortnox Specific Data Structures ---

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FortnoxConfig {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: String,           // Moved scopes here
    token_file_path: PathBuf, // Store the full path
    info_cache_path: PathBuf,
}

// Raw response from Fortnox token endpoint (Unchanged)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    token_type: String,
    scope: String,
}

// Structure for storing token data persistently (Unchanged)
#[derive(Serialize, Deserialize, Debug, Clone)]
struct StoredTokenData {
    access_token: String,
    refresh_token: String,
    expires_at_unix_secs: u64,
    scope: String,
    token_type: String,
}

impl StoredTokenData {
    /// Checks if the access token is expired or will expire within the buffer time.
    fn is_expired(&self, buffer_secs: u64) -> Result<bool, AppError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::SystemTimeError(e.to_string()))?
            .as_secs();
        Ok(now_unix >= self.expires_at_unix_secs.saturating_sub(buffer_secs))
    }
}

// --- Fortnox API Response Structures (Unchanged) ---
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct Project {
    #[serde(rename = "@url")]
    url: Option<String>,
    project_number: String,
    description: String,
    status: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    customer_number: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
struct ProjectResponse {
    projects: Vec<Project>, // Assuming "Projects" based on potential Fortnox response
    #[serde(rename = "@TotalResources")]
    total_resources: Option<i32>,
    #[serde(rename = "@TotalPages")]
    total_pages: Option<i32>,
    #[serde(rename = "@CurrentPage")]
    current_page: Option<i32>,
}

// --- Fortnox API Client (Simplified) ---
// Now created by FortnoxService with a valid token
#[derive(Clone)]
struct FortnoxApiClient {
    http_client: Client,
    access_token: String, // Holds the *valid* access token
    base_url: String,
    client_secret: String, // Still needed for headers on some endpoints? Keep for now.
}

impl FortnoxApiClient {
    // Constructor now takes the components directly
    pub fn new(
        http_client: Client,
        access_token: String,
        base_url: &str,
        client_secret: String,
    ) -> Self {
        FortnoxApiClient {
            http_client,
            access_token,
            base_url: base_url.to_string(),
            client_secret,
        }
    }

    // build_request uses the provided token and secret
    fn build_request(&self, method: Method, endpoint: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, endpoint);
        self.http_client
            .request(method, url)
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            // Note: Fortnox documentation is a bit inconsistent. Sometimes Access-Token/Client-Secret
            // headers are mentioned, sometimes just Bearer. Sticking with Bearer + headers for now.
            // If you find Bearer alone works, you can remove these extra headers and the client_secret field.
            .header("Client-Secret", self.client_secret.clone())
            .header("Access-Token", self.access_token.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
    }

    // send_and_deserialize remains the same
    async fn send_and_deserialize<T: DeserializeOwned>(
        &self,
        request_builder: RequestBuilder,
    ) -> Result<T, AppError> {
        let response = request_builder.send().await?;
        let status = response.status();
        if status.is_success() {
            response.json::<T>().await.map_err(AppError::from)
        } else {
            let error_text = response.text().await.ok();
            error!(
                "Fortnox API request failed. Status: {}, Body: {:?}",
                status, error_text
            );
            Err(AppError::FortnoxApiError {
                status,
                message: error_text,
            })
        }
    }

    // get remains the same
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> Result<T, AppError> {
        let request = self.build_request(Method::GET, endpoint);
        self.send_and_deserialize(request).await
    }

    // Specific API calls remain the same
    pub async fn fetch_projects(&self) -> Result<ProjectResponse, AppError> {
        info!("Fetching projects via API client...");
        self.get::<ProjectResponse>("/projects").await
    }

        // Fetches all employees
        pub async fn fetch_employees(&self) -> Result<EmployeeResponse, AppError> {
            info!("Fetching employees via API client...");
            // Note: Fortnox might paginate. For simplicity, this fetches the first page.
            // Implement pagination handling if you have many employees.
            self.get::<EmployeeResponse>("/employees").await
        }
    
        // Fetches Salary Codes (often used for time/absence registration)
        pub async fn fetch_salary_codes(&self) -> Result<SalaryCodeResponse, AppError> {
            info!("Fetching salary codes via API client...");
            // Note: Check Fortnox docs for endpoint name and potential filters
            // (e.g., ?filter=salarycodetype&salarycodetype=ARBETTID or FRÅNVARO)
            self.get::<SalaryCodeResponse>("/salarycodes").await
        }
}

// --- Fortnox Service ---
// Encapsulates all Fortnox-related state and logic

#[derive(Clone)] // Clone is needed for AppState
struct FortnoxService {
    config: Arc<FortnoxConfig>, // Use Arc for cheap cloning in state
    http_client: Client,
    oauth_state: Arc<Mutex<Option<String>>>,
    token_data: Arc<Mutex<Option<StoredTokenData>>>,
}

impl FortnoxService {
    // Associated constants for Fortnox URLs
    const AUTH_URL: &'static str = "https://apps.fortnox.se/oauth-v1/auth";
    const TOKEN_URL: &'static str = "https://apps.fortnox.se/oauth-v1/token";
    const API_BASE_URL: &'static str = "https://api.fortnox.se/3";

    /// Creates a new FortnoxService instance.
    /// Loads existing token data from the file specified in the config.
    pub fn new(config: FortnoxConfig, http_client: Client) -> Result<Self, AppError> {
        let initial_token_data = match Self::load_token_data(&config.token_file_path) {
            Ok(Some(data)) => {
                match data.is_expired(300) {
                    // Check if expired now or within 5 mins
                    Ok(true) => {
                        info!("Loaded token from {} is expired or nearing expiry. Will need refresh on first use.", config.token_file_path.display());
                        Some(data)
                    }
                    Ok(false) => {
                        info!(
                            "Loaded valid token from storage: {}",
                            config.token_file_path.display()
                        );
                        Some(data)
                    }
                    Err(e) => {
                        error!(
                            "Failed to check expiry of loaded token: {}. Assuming expired.",
                            e
                        );
                        Some(data) // Keep data for refresh token
                    }
                }
            }
            Ok(None) => {
                info!(
                    "No stored token data found in {}. Need initial authorization via /",
                    config.token_file_path.display()
                );
                None
            }
            Err(e) => {
                error!(
                    "Failed to load token data from {}: {}. Assuming no token.",
                    config.token_file_path.display(),
                    e
                );
                None // Treat loading error as needing new auth
            }
        };

        Ok(Self {
            config: Arc::new(config),
            http_client,
            oauth_state: Arc::new(Mutex::new(None)),
            token_data: Arc::new(Mutex::new(initial_token_data)),
        })
    }

    // --- Token Storage ---

    /// Saves the token data to the configured file path.
    fn save_token_data(&self, token_response: &TokenResponse) -> Result<StoredTokenData, AppError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::SystemTimeError(e.to_string()))?
            .as_secs();
        let expires_at = now_unix + token_response.expires_in;

        let stored_data = StoredTokenData {
            access_token: token_response.access_token.clone(),
            refresh_token: token_response.refresh_token.clone(),
            expires_at_unix_secs: expires_at,
            scope: token_response.scope.clone(),
            token_type: token_response.token_type.clone(),
        };
        let json_string = serde_json::to_string_pretty(&stored_data)?;

        // --- SECURITY --- (Reminder from original code)
        let mut file = File::create(&self.config.token_file_path)?;
        file.write_all(json_string.as_bytes())?;
        info!(
            "Token data saved to {}",
            self.config.token_file_path.display()
        );
        Ok(stored_data)
    }

    /// Loads token data from the specified file path.
    fn load_token_data(path: &Path) -> Result<Option<StoredTokenData>, AppError> {
        if !path.exists() {
            info!("Token file {} not found.", path.display());
            return Ok(None);
        }
        // --- SECURITY --- (Reminder from original code)
        let json_string = fs::read_to_string(path)?;
        let stored_data: StoredTokenData = serde_json::from_str(&json_string)?;
        info!("Token data loaded from {}", path.display());
        Ok(Some(stored_data))
    }

    /// Updates the in-memory and persistent token storage.
    async fn update_token_state(&self, token_response: &TokenResponse) -> Result<(), AppError> {
        match self.save_token_data(token_response) {
            Ok(new_stored_data) => {
                *self.token_data.lock().await = Some(new_stored_data);
                info!("Token data saved and in-memory state updated.");
                Ok(())
            }
            Err(e) => {
                error!("CRITICAL: Failed to save token data: {}", e);
                // Still update in-memory state but warn heavily? Or return error?
                warn!("Proceeding with in-memory token despite save failure.");
                let now_unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|se| AppError::SystemTimeError(se.to_string()))?
                    .as_secs();
                let expires_at = now_unix + token_response.expires_in;
                let temp_stored_data = StoredTokenData {
                    access_token: token_response.access_token.clone(),
                    refresh_token: token_response.refresh_token.clone(),
                    expires_at_unix_secs: expires_at,
                    scope: token_response.scope.clone(),
                    token_type: token_response.token_type.clone(),
                };
                *self.token_data.lock().await = Some(temp_stored_data);
                // Return the error so the caller knows saving failed
                Err(e)
            }
        }
    }

    // --- Token Refresh Logic ---

    /// Attempts to refresh the access token using the stored refresh token.
    /// Updates the stored token file and the in-memory state on success.
    async fn refresh_access_token(&self) -> Result<StoredTokenData, AppError> {
        info!("Attempting to refresh access token...");
        let stored_token_opt = self.token_data.lock().await.clone();

        let refresh_token = match stored_token_opt {
            Some(ref data) => data.refresh_token.clone(),
            None => {
                error!("Cannot refresh: No token data found in state.");
                return Err(AppError::MissingOrInvalidToken);
            }
        };

        let credentials = format!("{}:{}", self.config.client_id, self.config.client_secret);
        let encoded_credentials = BASE64_STANDARD.encode(credentials);
        let auth_header_value = format!("Basic {}", encoded_credentials);

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
        ];

        let response = self
            .http_client
            .post(Self::TOKEN_URL) // Use associated const
            .header(AUTHORIZATION, auth_header_value)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if response.status().is_success() {
            let token_response: TokenResponse = response.json().await?;
            info!("Successfully refreshed access token.");

            // Save and update state using the helper method
            match self.save_token_data(&token_response) {
                Ok(new_data) => {
                    *self.token_data.lock().await = Some(new_data.clone()); // Update state
                    Ok(new_data) // Return the new data
                }
                Err(e) => {
                    error!("CRITICAL: Failed to save refreshed token data: {}", e);
                    // If saving fails, return error. Don't update state with potentially unsaved token.
                    // The old (likely expired) token remains in memory until next attempt.
                    Err(e)
                }
            }
        } else {
            let status = response.status();
            let error_text = response.text().await.ok();
            error!(
                "Failed to refresh token. Status: {}, Body: {:?}",
                status, error_text
            );
            warn!("Clearing stored token data due to refresh failure.");
            *self.token_data.lock().await = None;
            match fs::remove_file(&self.config.token_file_path) {
                Ok(_) => info!(
                    "Removed potentially invalid token file: {}",
                    self.config.token_file_path.display()
                ),
                Err(e) => error!(
                    "Failed to remove token file {}: {}",
                    self.config.token_file_path.display(),
                    e
                ),
            }
            Err(AppError::MissingOrInvalidToken)
        }
    }

    /// Ensures a valid access token is available, refreshing if necessary.
    /// Returns a valid access token string.
    pub async fn get_valid_access_token(&self) -> Result<String, AppError> {
        let mut token_data_guard = self.token_data.lock().await;

        let needs_refresh = match *token_data_guard {
            Some(ref data) => data.is_expired(60)?, // 60s buffer
            None => true, // No token means we need one (implies refresh or initial auth)
        };

        if needs_refresh {
            info!("Token is invalid, missing, or nearing expiry. Attempting refresh...");
            // Drop the lock *before* calling refresh_access_token
            drop(token_data_guard);

            match self.refresh_access_token().await {
                Ok(new_data) => {
                    info!("Token refresh successful.");
                    Ok(new_data.access_token)
                }
                Err(e) => {
                    error!("Token refresh failed: {}", e);
                    Err(e) // Propagate the error
                }
            }
        } else {
            // Token is valid, clone the access token. Lock is still held.
            info!("Current token is valid.");
            Ok(token_data_guard.as_ref().unwrap().access_token.clone())
        }
        // Lock is automatically dropped here
    }

    /// Exchanges the authorization code for tokens (initial exchange).
    async fn exchange_code_for_token(&self, code: &str) -> Result<TokenResponse, AppError> {
        info!("Exchanging authorization code for tokens...");
        let credentials = format!("{}:{}", self.config.client_id, self.config.client_secret);
        let encoded_credentials = BASE64_STANDARD.encode(credentials);
        let auth_header_value = format!("Basic {}", encoded_credentials);

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
        ];

        let response = self
            .http_client
            .post(Self::TOKEN_URL) // Use associated const
            .header(AUTHORIZATION, auth_header_value)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;

        if response.status().is_success() {
            response
                .json::<TokenResponse>()
                .await
                .map_err(AppError::from)
        } else {
            let status = response.status();
            let error_text = response.text().await.ok();
            error!(
                "Failed to exchange code for token. Status: {}, Body: {:?}",
                status, error_text
            );
            Err(AppError::FortnoxApiError {
                status,
                message: error_text,
            })
        }
    }

    // --- OAuth Flow Methods ---

    /// Generates the Fortnox authorization URL and stores the state.
    pub async fn generate_auth_redirect(&self) -> Result<Redirect, AppError> {
        let random_state: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        *self.oauth_state.lock().await = Some(random_state.clone());
        info!("Generated OAuth state: {}", random_state);

        let mut auth_url = Url::parse(Self::AUTH_URL)?; // Use associated const
        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scopes)
            .append_pair("state", &random_state)
            .append_pair("access_type", "offline")
            .append_pair("response_type", "code");

        info!("Redirecting user to Fortnox: {}", auth_url);
        Ok(Redirect::temporary(auth_url.as_str()))
    }

    /// Handles the callback from Fortnox, validates state, exchanges code, and updates token state.
    pub async fn handle_auth_callback(&self, params: AuthCallbackParams) -> Result<(), AppError> {
        info!("FortnoxService handling callback with params: {:?}", params);

        // 1. Check for OAuth errors from Fortnox
        if let Some(error) = params.error {
            let description = params.error_description.unwrap_or_default();
            error!(
                "OAuth failed on Fortnox side. Error: '{}', Description: '{}'",
                error, description
            );
            // Return a specific error or message? For now, map to a generic service error.
            return Err(AppError::FortnoxServiceError(format!(
                "Fortnox OAuth Error: {} ({})",
                error, description
            )));
        }

        // 2. Verify OAuth state
        let expected_state_opt = self.oauth_state.lock().await.take();
        match (expected_state_opt.clone(), params.state.clone()) {
            (Some(expected), Some(received)) if expected == received => {
                info!("OAuth state verified successfully.");
            }
            _ => {
                error!(
                    "OAuth state mismatch. Expected: {:?}, Received: {:?}",
                    expected_state_opt, params.state
                );
                *self.token_data.lock().await = None; // Clear token on mismatch
                return Err(AppError::OAuthStateMismatch);
            }
        }

        // 3. Get authorization code
        let code = params.code.ok_or(AppError::MissingAuthCode)?;
        info!("Received authorization code.");

        // 4. Exchange code for tokens
        let token_response = self.exchange_code_for_token(&code).await?;
        info!(
            "Successfully obtained initial tokens. Access token expires in {} seconds.",
            token_response.expires_in
        );

        // 5. Save the received token data and update in-memory state
        // update_token_state handles saving and updating the mutex, returns Err on save failure
        self.update_token_state(&token_response).await?;
        info!("Initial token processing complete.");

        Ok(())
    }

    // --- API Client Creation ---

    /// Creates a `FortnoxApiClient` instance with a guaranteed valid access token.
    pub async fn get_api_client(&self) -> Result<FortnoxApiClient, AppError> {
        let access_token = self.get_valid_access_token().await?;
        Ok(FortnoxApiClient::new(
            self.http_client.clone(),
            access_token,
            Self::API_BASE_URL,                // Use associated const
            self.config.client_secret.clone(), // Pass secret to client
        ))
    }

    // --- Status Reporting ---
    pub async fn get_status(&self) -> String {
        let token_lock = self.token_data.lock().await;
        match &*token_lock {
             Some(token) => {
                 match token.is_expired(60) {
                     Ok(true) => format!("Token present but expired or needs refresh soon (Refresh Token: ...{}). Stored in: {}",
                                          &token.refresh_token.chars().take(8).collect::<String>(),
                                          self.config.token_file_path.display()),
                     Ok(false) => format!("Token present and valid until approx Unix timestamp {}. (Access Token: ...{}). Stored in: {}",
                                          token.expires_at_unix_secs,
                                          &token.access_token.chars().take(8).collect::<String>(),
                                          self.config.token_file_path.display()),
                     Err(e) => format!("Token present but failed to check expiry: {}. Stored in: {}", e, self.config.token_file_path.display()),
                 }
             }
             None => format!("No token present in memory. Needs authorization via /. Token file path: {}", self.config.token_file_path.display()),
         }
    }

    /// Fetches personnel (employees) and constructs time registration information.
    /// Uses a file cache to avoid frequent API calls.
    pub async fn get_personnel_and_time_info(&self)
        -> Result<(Vec<Employee>, TimeRegistrationInfo), AppError>
    {
        info!("Attempting to get personnel and time registration info...");

        // 1. Try loading from cache
        match self.load_info_cache() {
            Ok(Some(cached_data)) => {
                // 2. Check if cache is stale
                match cached_data.is_stale(INFO_CACHE_DURATION_SECS) {
                    Ok(false) => {
                        info!("Valid info cache found. Returning cached data.");
                        return Ok((cached_data.employees, cached_data.time_info));
                    }
                    Ok(true) => {
                        info!("Info cache found but is stale (older than {} seconds). Refetching.", INFO_CACHE_DURATION_SECS);
                        // Proceed to fetch fresh data
                    }
                    Err(e) => {
                        warn!("Failed to check cache staleness: {}. Refetching.", e);
                        // Proceed to fetch fresh data
                    }
                }
            }
            Ok(None) => {
                info!("No info cache found. Fetching fresh data.");
                // Proceed to fetch fresh data
            }
            Err(e) => {
                // Error loading cache (I/O or parse error handled inside load_info_cache)
                warn!("Failed to load or parse info cache: {}. Refetching.", e);
                 // Proceed to fetch fresh data
            }
        }

        // 3. Fetch fresh data from API if cache miss or stale
        info!("Fetching fresh personnel and time info from Fortnox API...");
        let api_client = self.get_api_client().await?;

        // Fetch Employees
        let employee_response = api_client.fetch_employees().await?;
        let employees = employee_response.employees;
        info!("Fetched {} employees.", employees.len());

        // Fetch Salary Codes
        let salary_code_response = api_client.fetch_salary_codes().await?;
        let salary_codes = salary_code_response.salary_codes;
        info!("Fetched {} salary codes.", salary_codes.len());

        // Construct the TimeRegistrationInfo (same as before)
        let time_info = TimeRegistrationInfo {
             mandatory_for_worked_time: vec![
                "Date".to_string(), "Client (Customer)".to_string(), "Project".to_string(),
                "Service".to_string(), "Registration Code (Salary Code)".to_string(),
                "Hours Worked".to_string(), "(Note only for foreign public holidays)".to_string(),
            ],
            mandatory_for_absence: vec![
                "Date".to_string(), "Registration Code (Salary Code)".to_string(),
                "Number of hours OR Check box for full day".to_string(),
            ],
            other_notes: "Fields like cost center, invoice text, and note generally do not need to be filled in – but it's okay if they are used.".to_string(),
            available_salary_codes: salary_codes,
        };

        // 4. Try to save the fresh data to the cache
        match self.save_info_cache(&employees, &time_info) {
            Ok(_) => info!("Successfully updated info cache file."),
            Err(e) => {
                // Log error but don't fail the request - return the fresh data anyway
                error!("Failed to save updated info cache: {}", e);
            }
        }

        // 5. Return the freshly fetched data
        Ok((employees, time_info))
    }


    /// Loads cached info data from the configured file path.
    fn load_info_cache(&self) -> Result<Option<CachedInfo>, AppError> {
        let path = &self.config.info_cache_path;
        if !path.exists() {
            info!("Info cache file {} not found.", path.display());
            return Ok(None);
        }
        // --- SECURITY --- Consider file permissions if sensitive data were stored
        match fs::read_to_string(path) {
            Ok(json_string) => {
                match serde_json::from_str::<CachedInfo>(&json_string) {
                    Ok(data) => {
                        info!("Info cache loaded successfully from {}", path.display());
                        Ok(Some(data))
                    }
                    Err(e) => {
                        // File exists but is corrupt/malformed
                        error!("Failed to parse info cache file {}: {}. Will attempt refetch.", path.display(), e);
                        // Optionally delete the corrupt file?
                        // fs::remove_file(path).ok();
                        Err(AppError::SerdeJson(e)) // Propagate error, but maybe just return Ok(None) to force refetch? Let's return Ok(None).
                        // Ok(None) // Treat parse error as cache miss
                    }
                }
            }
            Err(e) => {
                // File exists but couldn't be read
                 error!("Failed to read info cache file {}: {}. Will attempt refetch.", path.display(), e);
                 Err(AppError::Io(e)) // Propagate I/O error, but maybe just return Ok(None) to force refetch? Let's return Ok(None).
                 // Ok(None) // Treat read error as cache miss
            }
        }
    }

    /// Saves the combined info data to the configured cache file path.
    fn save_info_cache(&self, employees: &[Employee], time_info: &TimeRegistrationInfo) -> Result<(), AppError> {
        let path = &self.config.info_cache_path;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::SystemTimeError(e.to_string()))?
            .as_secs();

        let cache_data = CachedInfo {
            employees: employees.to_vec(), // Clone data into the cache struct
            time_info: time_info.clone(),  // Clone data
            last_updated_unix_secs: now_unix,
        };

        let json_string = serde_json::to_string_pretty(&cache_data)?;

        // --- SECURITY --- Consider file permissions
        let mut file = File::create(path)?; // Overwrites existing file
        file.write_all(json_string.as_bytes())?;
        info!("Info cache data saved to {}", path.display());
        Ok(())
    }
}

// --- Shared Application State ---
#[derive(Clone)]
struct AppState {
    fortnox_service: Arc<FortnoxService>, // Holds the Fortnox logic
                                          // http_client: Client, // http_client is now owned by FortnoxService
                                          // Can add other shared services here later
}

// --- Auth Callback Parameters (Unchanged) ---
#[derive(Deserialize, Debug)]
struct AuthCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

// --- Main Application Logic ---

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

    // --- Load Fortnox Configuration ---
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
        // Set the cache path, defaulting to current directory
        info_cache_path: env::var("INFO_CACHE_PATH") // Optional env var override
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(INFO_CACHE_FILE_NAME)), // Default filename
    };
    info!(
        "Fortnox configuration loaded. Token file: {}, Info cache file: {}",
        fortnox_config.token_file_path.display(),
        fortnox_config.info_cache_path.display() 
    );

    // --- Create HTTP Client (shared potentially, but FortnoxService needs one) ---
    let http_client = Client::builder().timeout(Duration::from_secs(30)).build()?;

    // --- Create Fortnox Service (loads token) ---
    let fortnox_service = Arc::new(FortnoxService::new(fortnox_config, http_client)?);
    info!("Fortnox Service initialized.");

    // --- Create Shared App State ---
    let state = AppState {
        fortnox_service: fortnox_service.clone(), // Clone Arc for state
    };
    info!("Application state initialized.");

    // --- Define Routes ---
    let fortnox_routes = Router::new()
        .route("/auth/callback", get(handle_callback))
        .route("/auth", get(handle_fortnox_auth))
        .route("/info", get(handle_get_info));
    let api_routes = Router::new().nest("/fortnox", fortnox_routes);

    let app = Router::new()
        .nest("/api", api_routes)
        .route("/status", get(handle_status))
        .with_state(state.clone()); // Clone state for the web server

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

    // --- Example Background Task Spawn ---
    let task_state = state.clone();
    tokio::spawn(async move {
        info!("Example background task started.");
        sleep(Duration::from_secs(10)).await;
        run_example_api_call(task_state).await; // Pass the whole AppState
    });

    // --- Run Web Server ---
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Starting server on https://{}", addr);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

// --- Web Handlers (Updated to use FortnoxService) ---
async fn handle_fortnox_auth(State(state): State<AppState>) -> Result<Redirect, AppError> {
    info!("Handling / request, initiating OAuth flow via FortnoxService...");
    state.fortnox_service.generate_auth_redirect().await
}

// Handles the OAuth callback via FortnoxService
async fn handle_callback(
    State(state): State<AppState>,
    Query(params): Query<AuthCallbackParams>,
) -> Result<Html<String>, AppError> {
    info!("Handling /fortnox/auth/callback, delegating to FortnoxService...");

    match state.fortnox_service.handle_auth_callback(params).await {
        Ok(_) => {
            info!("FortnoxService handled callback successfully. Attempting test API call...");
            // Optional: Make an immediate API call to verify
            match state.fortnox_service.get_api_client().await {
                Ok(api_client) => {
                    match api_client.fetch_projects().await {
                        Ok(project_response) => {
                            info!(
                                "Successfully fetched {} projects immediately after auth.",
                                project_response.projects.len()
                            );
                            println!("\n--- Fetched Fortnox Project Names (Post-Callback) ---");
                            if project_response.projects.is_empty() {
                                println!("No projects found.");
                            } else {
                                for project in &project_response.projects {
                                    println!(
                                        " - {} ({})",
                                        project.description, project.project_number
                                    );
                                }
                            }
                            println!("-----------------------------------------------------\n");
                            Ok(Html(format!(
                                 "<h1>Success!</h1><p>Authentication successful. Fetched {} projects.</p><p>Token data saved. Server is now authorized.</p><p>Check console for project names.</p><p>You can close this window.</p>",
                                 project_response.projects.len()
                             )))
                        }
                        Err(e) => {
                            error!("Callback: API call failed even after getting token via service: {}", e);
                            Err(e) // Propagate API error
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Callback: Failed to get API client after successful callback: {}",
                        e
                    );
                    // This implies token refresh/validation failed immediately after exchange
                    Err(e)
                }
            }
        }
        Err(e) => {
            error!("FortnoxService failed to handle callback: {}", e);
            // Enhance error reporting based on the specific AppError type if needed
            // For now, just propagate the error for the generic handler
            Err(e)
        }
    }
}


/// Handler to fetch and display personnel and time registration info
async fn handle_get_info(
    State(state): State<AppState>
) -> Result<Html<String>, AppError> {
    info!("Handling /api/fortnox/info request...");

    let (employees, time_info) = state.fortnox_service.get_personnel_and_time_info().await?;

    // --- Format Output ---
    let mut html = String::new();
    html.push_str("<h1>Fortnox Information</h1>");

    // Personnel Section
    html.push_str("<h2>Personnel (Employees)</h2>");
    if employees.is_empty() {
        html.push_str("<p>No employees found.</p>");
    } else {
        html.push_str("<ul>");
        for emp in employees {
            let name = emp.full_name.clone().unwrap_or_else(||
                format!("{} {}", emp.first_name.clone().unwrap_or_default(), emp.last_name.clone().unwrap_or_default())
            );
            let active_status = match emp.active {
                Some(true) => " (Active)",
                Some(false) => " (Inactive)",
                None => " (Activity Unknown)" // Handle if 'Active' field is missing
            };
            let end_date_status = match emp.end_date {
                 Some(ref date) if !date.is_empty() => format!(" (End Date: {})", date),
                 _ => "".to_string()
            };
             // Basic check for inactive based on flags
            let display_status = if emp.active == Some(false) || (!end_date_status.is_empty() && active_status == " (Activity Unknown)") {
                 format!("{} {}", active_status, end_date_status)
            } else {
                 active_status.to_string()
            };


            html.push_str(&format!(
                "<li>{}: {} {}</li>",
                emp.employee_id,
                name.trim(), // Handle potential empty first/last names
                display_status
            ));
        }
        html.push_str("</ul>");
    }

    // Time Registration Section
    html.push_str("<h2>Time Registration Information</h2>");
    html.push_str("<h3>Mandatory Information (Worked Time)</h3>");
    html.push_str("<ul>");
    for item in time_info.mandatory_for_worked_time {
        html.push_str(&format!("<li>{}</li>", item));
    }
    html.push_str("</ul>");

    html.push_str("<h3>Mandatory Information (Absence)</h3>");
    html.push_str("<ul>");
    for item in time_info.mandatory_for_absence {
        html.push_str(&format!("<li>{}</li>", item));
    }
    html.push_str("</ul>");

    html.push_str("<h3>Other Notes</h3>");
    html.push_str(&format!("<p>{}</p>", time_info.other_notes));

    html.push_str("<h3>Available Registration Codes (Salary Codes)</h3>");
    if time_info.available_salary_codes.is_empty() {
        html.push_str("<p>No salary codes found.</p>");
    } else {
        html.push_str("<ul>");
        // Maybe filter or group by type? For now, list all.
        for code in time_info.available_salary_codes {
            html.push_str(&format!("<li>{}: {} (Type: {})</li>",
                code.code, code.description, code.code_type));
        }
        html.push_str("</ul>");
        html.push_str("<p><i>Note: Filter these codes based on 'CodeType' (e.g., ARBETTID, FRÅNVARO) as needed for specific time/absence entry.</i></p>");
    }

    Ok(Html(html))
}

// Gets status from FortnoxService
async fn handle_status(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    info!("Handling /status request, getting status from FortnoxService...");
    let status_message = state.fortnox_service.get_status().await; // Await the async status method
    let html_body = format!(
        "<h1>Server Status</h1><p>Current Time (Server): {}</p><p>Fortnox Token Status: {}</p><p><a href='/'>Re-authorize with Fortnox</a></p>",
        chrono::Local::now().to_rfc3339(),
        status_message
    );
    Ok(Html(html_body))
}

// --- Example Background Task Logic (Updated) ---
async fn run_example_api_call(state: AppState) {
    // Pass AppState
    info!("Running example API call sequence using FortnoxService...");

    // Get the API client (handles token refresh internally)
    match state.fortnox_service.get_api_client().await {
        Ok(api_client) => {
            info!("Example Task: Successfully obtained Fortnox API client.");

            // Perform API calls using the obtained client
            match api_client.fetch_projects().await {
                Ok(projects) => {
                    info!(
                        "Example Task: Successfully fetched {} projects.",
                        projects.projects.len()
                    );
                    println!("\n--- Fetched Fortnox Project Names (Example Task) ---");
                    if projects.projects.is_empty() {
                        println!("No projects found.");
                    } else {
                        for project in projects.projects.iter().take(5) {
                            // Print first 5
                            println!(" - {} ({})", project.description, project.project_number);
                        }
                    }
                    println!("-----------------------------------------------------\n");
                }
                Err(e) => error!("Example Task: Failed to fetch projects: {}", e),
            }
            // ... Add other example API calls here using 'api_client' ...
        }
        Err(e) => {
            error!("Example Task: Failed to get Fortnox API client: {}", e);
            match e {
                // If it indicates re-auth is needed
                AppError::MissingOrInvalidToken => {
                    // Get server base URL from service config for the message
                    let server_base = state
                        .fortnox_service
                        .config
                        .redirect_uri
                        .split("/fortnox/auth/callback")
                        .next()
                        .unwrap(); 
                    warn!("Example Task: Fortnox authorization required. Please visit {}/ to authorize.", server_base);
                }
                _ => {
                    // Other errors might be temporary network issues etc.
                }
            }
        }
    }
    info!("Example API call sequence finished.");
}
