// src/fortnox_client.rs

use anyhow::{anyhow, bail, Context, Result as AnyhowResult}; // Keep anyhow for internal use if needed
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, Method, RequestBuilder, StatusCode};
use serde::de::Error;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error; // Use thiserror for our specific error type
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::log::{debug, error, info, warn}; // Use tracing consistently
use url::Url;

// Constants (remain the same)
pub const FORTNOX_AUTH_URL: &str = "https://apps.fortnox.se/oauth-v1/auth";
pub const FORTNOX_TOKEN_URL: &str = "https://apps.fortnox.se/oauth-v1/token";
pub const FORTNOX_API_BASE_URL: &str = "https://api.fortnox.se/3";
pub const FORTNOX_TIME_API_URL: &str = "https://api.fortnox.se/api/time";
pub const DEFAULT_CACHE_DIR: &str = "./fortnox_cache";
pub const DEFAULT_TOKEN_FILE: &str = "fortnox_token.json";
pub const DEFAULT_CACHE_DURATION_SECS: u64 = 24 * 60 * 60; // 24 hours

// --- Fortnox API Data Structures ---

// Time Registration API types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeRegCustomerInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeRegProjectInfo {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeRegServiceInfo {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeRegCodeInfo {
    pub code: String,
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailedRegistration {
    pub id: String,
    pub user_id: String,
    pub worked_date: String,
    pub worked_hours: f64,
    pub charge_hours: f64,
    pub start_time: Option<String>,
    pub stop_time: Option<String>,
    pub non_invoiceable: bool,
    pub note: Option<String>,
    pub invoice_text: Option<String>,
    pub customer: Option<TimeRegCustomerInfo>,
    pub project: Option<TimeRegProjectInfo>,
    pub service: Option<TimeRegServiceInfo>,
    pub registration_code: TimeRegCodeInfo,
    pub child_id: Option<String>,
    pub document_id: Option<i64>,
    pub document_type: Option<String>,
    pub invoice_basis_id: Option<i64>,
    pub unit_cost: Option<f64>,
    pub unit_price: Option<f64>,
}

// Schedule Time API types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ScheduleTime {
    pub employee_id: String,
    pub date: String,
    pub schedule_id: Option<String>,
    pub hours: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ScheduleTimeResponse {
    #[serde(rename = "ScheduleTime")]
    pub schedule_time: ScheduleTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EmployeeDatedSchedule {
    // Assuming 'Date' is the effective date for this schedule ID.
    // The exact field name might need to be verified from an actual API response if not 'Date'.
    pub date: String,
    #[serde(rename = "ScheduleId")] // Ensure casing matches API response
    pub schedule_id: String,
    // Add other fields if present in the actual API response for DatedSchedule
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EmployeeDatedWage {
    pub date: String,
    #[serde(rename = "MonthlySalary")]
    pub monthly_salary: Option<String>, // Using Option as they are "pairs"
    #[serde(rename = "HourlyPay")]
    pub hourly_pay: Option<String>,
    // Add other fields if present
}

// Employee API types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EmployeeListItem {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "EmployeeId")]
    pub employee_id: String,
    #[serde(rename = "PersonalIdentityNumber")]
    pub personal_identity_number: Option<String>,
    #[serde(rename = "FirstName")]
    pub first_name: Option<String>, // Docs say required, but using Option for robustness
    #[serde(rename = "LastName")]
    pub last_name: Option<String>, // Docs say required
    #[serde(rename = "FullName")]
    pub full_name: Option<String>,
    // email is marked as required in docs, make sure it aligns
    // If it's truly always present, make it `String` not `Option<String>`
    // For now, let's assume the provided struct was for a list where it might be optional
    // but for a single employee, it might be required.
    // The doc provided says "Email required string" for the list item.
    pub email: String, // Changed to String based on "required" in docs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EmployeeListResponse {
    pub employees: Vec<EmployeeListItem>,
}

// Customer API types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CustomerListItem {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "CustomerNumber")]
    pub customer_number: String,
    pub name: String,
    #[serde(rename = "OrganisationNumber")]
    pub organisation_number: Option<String>,
    #[serde(rename = "Address1")]
    pub address1: Option<String>,
    #[serde(rename = "ZipCode")]
    pub zip_code: Option<String>,
    pub city: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CustomerListResponse {
    pub customers: Vec<CustomerListItem>,
}

// Project API types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProjectListItem {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "ProjectNumber")]
    pub project_number: String,
    pub description: String,
    pub status: Option<String>,
    #[serde(rename = "StartDate")]
    pub start_date: Option<String>,
    #[serde(rename = "EndDate")]
    pub end_date: Option<String>,
    #[serde(rename = "ProjectLeader")]
    pub project_leader_id: Option<String>,
    #[serde(rename = "CustomerNumber")]
    pub customer_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProjectListResponse {
    pub projects: Vec<ProjectListItem>,
    #[serde(rename = "@TotalResources")]
    pub total_resources: Option<i32>,
    #[serde(rename = "@TotalPages")]
    pub total_pages: Option<i32>,
    #[serde(rename = "@CurrentPage")]
    pub current_page: Option<i32>,
}

// Article API types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ArticleListItem {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "ArticleNumber")]
    pub article_number: String,
    pub description: String,
    pub unit: Option<String>,
    #[serde(rename = "SalesPrice")]
    pub sales_price: Option<String>,
    #[serde(rename = "PurchasePrice")]
    pub purchase_price: Option<String>,
    #[serde(rename = "Active")]
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ArticleListResponse {
    pub articles: Vec<ArticleListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FortnoxMe {
    // Using Option<> for robustness, adjust if fields are guaranteed non-null
    pub email: Option<String>,
    /// The 'Id' field is the same as "userId"
    pub id: String,
    pub locale: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "SysAdmin")] // Ensure correct mapping if PascalCase doesn't suffice
    pub sys_admin: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FortnoxMeWrap {
    #[serde(rename = "MeInformation")] // Match the exact property name from the schema
    pub me_information: FortnoxMe,
}

// --- Define Specific Fortnox Error Type ---
#[derive(Error, Debug)]
pub enum FortnoxError {
    #[error("HTTP request failed")]
    Request(#[from] reqwest::Error),

    #[error("JSON processing error")]
    Json(#[from] serde_json::Error),

    #[error("File I/O error: {context}")]
    Io {
        #[source]
        source: std::io::Error,
        context: String,
    },

    #[error("URL parsing error")]
    UrlParse(#[from] url::ParseError),

    #[error("OAuth state mismatch")]
    OAuthStateMismatch,

    #[error("Missing authorization code in callback")]
    MissingAuthCode,

    #[error("Access token not available (token missing or could not be loaded)")]
    MissingToken,

    #[error("Token refresh failed: Status={status:?}, Message='{message}'")]
    TokenRefreshFailed {
        status: Option<StatusCode>,
        message: String,
    },

    #[error("Rate limit exceeded (Status 429)")]
    RateLimitExceeded,

    // Use this for non-429 API errors
    #[error("Fortnox API error: Status={status}, Message='{message}'")]
    ApiError { status: StatusCode, message: String },

    #[error("System time error: {0}")]
    TimeError(String),

    #[error("Lock acquisition failed: {0}")]
    LockError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
    // Optional: Catch-all for internal issues if needed, wraps anyhow
    // #[error("Internal client error")]
    // Internal(#[from] anyhow::Error),
}

// Helper to create context-aware IO errors
fn io_context<E: Into<std::io::Error>, S: Into<String>>(source: E, context: S) -> FortnoxError {
    FortnoxError::Io {
        source: source.into(),
        context: context.into(),
    }
}

// Configuration for the Fortnox client (remains the same)
#[derive(Clone, Debug)]
pub struct FortnoxConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub token_file_path: PathBuf,
    pub cache_dir: PathBuf,
    pub cache_duration_secs: u64,
}

impl Default for FortnoxConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scopes: String::new(),
            token_file_path: PathBuf::from(DEFAULT_TOKEN_FILE),
            cache_dir: PathBuf::from(DEFAULT_CACHE_DIR),
            cache_duration_secs: DEFAULT_CACHE_DURATION_SECS,
        }
    }
}

// OAuth token response from Fortnox (remains the same)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub scope: String,
}

// Structure for storing token data persistently (remains the same)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTokenData {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_unix_secs: u64,
    pub scope: String,
    pub token_type: String,
}

impl StoredTokenData {
    // Updated to return Result<_, FortnoxError>
    pub fn is_expired(&self, buffer_secs: u64) -> Result<bool, FortnoxError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                FortnoxError::TimeError(format!("Failed to get system time duration: {}", e))
            })?
            .as_secs();
        Ok(now_unix >= self.expires_at_unix_secs.saturating_sub(buffer_secs))
    }
}

// Cache metadata (remains the same)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
    last_updated_unix_secs: u64,
    resource_type: String,
    resource_id: Option<String>,
    query_params: Option<HashMap<String, String>>,
}

impl CacheMetadata {
    // Updated to return Result<_, FortnoxError>
    fn new(
        resource_type: String,
        resource_id: Option<String>,
        query_params: Option<HashMap<String, String>>,
    ) -> Result<Self, FortnoxError> {
        Ok(Self {
            last_updated_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    FortnoxError::TimeError(format!(
                        "Failed to get system time duration for cache: {}",
                        e
                    ))
                })?
                .as_secs(),
            resource_type,
            resource_id,
            query_params,
        })
    }

    // Updated to return Result<_, FortnoxError>
    fn is_stale(&self, max_age_secs: u64) -> Result<bool, FortnoxError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                FortnoxError::TimeError(format!(
                    "Failed to get system time duration for cache stale check: {}",
                    e
                ))
            })?
            .as_secs();
        let cache_age = now_unix.saturating_sub(self.last_updated_unix_secs);
        Ok(cache_age > max_age_secs)
    }
}

// Generic cache container (remains the same)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedData<T> {
    metadata: CacheMetadata,
    data: T,
}

// Auth callback parameters (remains the same)
#[derive(Debug, Deserialize)]
pub struct AuthCallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

// Fortnox API Client Implementation (remains the same)
#[derive(Clone)]
pub struct FortnoxClient {
    config: Arc<FortnoxConfig>,
    http_client: Client,
    token_data: Arc<Mutex<Option<StoredTokenData>>>,
    oauth_state: Arc<Mutex<Option<String>>>,
}

// --- API Data Structures (remain the same) ---
// ... (TimeRegCustomerInfo, DetailedRegistration, ScheduleTime, EmployeeListItem, etc.) ...
// --- Fortnox Error Response parsing (keep for parsing error bodies) ---
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FortnoxErrorInformation {
    pub error: Option<serde_json::Value>,
    pub message: Option<String>,
    pub code: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FortnoxErrorPayload {
    #[serde(rename = "ErrorInformation")]
    pub error_information: FortnoxErrorInformation,
}

// --- Implementation using FortnoxError ---

impl FortnoxClient {
    // Updated to return Result<_, FortnoxError>
    pub fn new(config: FortnoxConfig) -> Result<Self, FortnoxError> {
        // Create HTTP client - reqwest::Error maps via #[from]
        let http_client = Client::builder().timeout(Duration::from_secs(30)).build()?; // Maps to FortnoxError::Request

        // Create cache directory - io::Error maps via helper
        if !config.cache_dir.exists() {
            fs::create_dir_all(&config.cache_dir).map_err(|e| {
                io_context(
                    e,
                    format!("Failed to create cache directory: {:?}", config.cache_dir),
                )
            })?;
        }

        // Load existing token if available - Uses FortnoxError internally now
        let initial_token_data = Self::load_token_data(&config.token_file_path)?;

        Ok(Self {
            config: Arc::new(config),
            http_client,
            token_data: Arc::new(Mutex::new(initial_token_data)),
            oauth_state: Arc::new(Mutex::new(None)),
        })
    }

    // Updated to return Result<_, FortnoxError>
    pub fn load_token_data(path: &Path) -> Result<Option<StoredTokenData>, FortnoxError> {
        if !path.exists() {
            return Ok(None);
        }

        let json_string = fs::read_to_string(path)
            .map_err(|e| io_context(e, format!("Failed to read token file: {:?}", path)))?;
        // serde_json::Error maps via #[from]
        let stored_data: StoredTokenData = serde_json::from_str(&json_string)?;

        Ok(Some(stored_data))
    }

    // Updated to return Result<_, FortnoxError>
    pub fn save_token_data(
        &self,
        token_response: &TokenResponse,
    ) -> Result<StoredTokenData, FortnoxError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                FortnoxError::TimeError(format!("Failed to get system time for token save: {}", e))
            })?
            .as_secs();

        let expires_at = now_unix + token_response.expires_in;

        let stored_data = StoredTokenData {
            access_token: token_response.access_token.clone(),
            refresh_token: token_response.refresh_token.clone(),
            expires_at_unix_secs: expires_at,
            scope: token_response.scope.clone(),
            token_type: token_response.token_type.clone(),
        };

        // serde_json::Error maps via #[from]
        let json_string = serde_json::to_string_pretty(&stored_data)?;

        // Ensure parent directory exists
        if let Some(parent) = self.config.token_file_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                io_context(
                    e,
                    format!("Failed to create directory for token file: {:?}", parent),
                )
            })?;
        }

        let mut file = File::create(&self.config.token_file_path).map_err(|e| {
            io_context(
                e,
                format!(
                    "Failed to create token file: {:?}",
                    self.config.token_file_path
                ),
            )
        })?;
        file.write_all(json_string.as_bytes()).map_err(|e| {
            io_context(
                e,
                format!(
                    "Failed to write token data to file: {:?}",
                    self.config.token_file_path
                ),
            )
        })?;

        Ok(stored_data)
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn update_token_state(
        &self,
        token_response: &TokenResponse,
    ) -> Result<(), FortnoxError> {
        let new_stored_data = self.save_token_data(token_response)?;

        let mut token_guard = self.token_data.lock().await;
        // .map_err(|_| FortnoxError::LockError("Failed to acquire token lock for update".to_string()))?;
        *token_guard = Some(new_stored_data);

        Ok(())
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn generate_auth_url(&self) -> Result<String, FortnoxError> {
        let random_state: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        {
            // Scope for mutex guard
            let mut state_guard = self.oauth_state.lock().await;
            // .map_err(|_| FortnoxError::LockError("Failed to acquire state lock for generation".to_string()))?;
            *state_guard = Some(random_state.clone());
        } // Guard dropped here

        // url::ParseError maps via #[from]
        let mut auth_url = Url::parse(FORTNOX_AUTH_URL)?;
        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scopes)
            .append_pair("state", &random_state)
            .append_pair("access_type", "offline")
            .append_pair("response_type", "code")
            .append_pair("account_type", "service");

        Ok(auth_url.to_string())
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn handle_auth_callback(
        &self,
        params: AuthCallbackParams,
    ) -> Result<(), FortnoxError> {
        // Check for errors from Fortnox
        if let Some(error) = params.error {
            let description = params.error_description.unwrap_or_default();
            // Use ApiError for OAuth callback errors reported by Fortnox
            return Err(FortnoxError::ApiError {
                status: StatusCode::UNAUTHORIZED, // Assuming 401 is appropriate
                message: format!("OAuth callback error: {} ({})", error, description),
            });
        }

        // Verify OAuth state
        let expected_state;
        {
            // Scope for mutex guard
            let mut state_guard = self.oauth_state.lock().await;
            // .map_err(|_| FortnoxError::LockError("Failed to acquire state lock for verification".to_string()))?;
            expected_state = state_guard.take(); // Take removes the state
        } // Guard dropped here

        match (expected_state, params.state) {
            (Some(expected), Some(received)) if expected == received => {
                info!("OAuth state verified successfully.");
            }
            _ => {
                warn!("OAuth state mismatch occurred during callback.");
                return Err(FortnoxError::OAuthStateMismatch);
            }
        }

        // Get authorization code
        let code = params.code.ok_or(FortnoxError::MissingAuthCode)?;

        // Exchange code for tokens - uses FortnoxError internally now
        let token_response = self.exchange_code_for_token(&code).await?;

        // Save the token data - uses FortnoxError internally now
        self.update_token_state(&token_response).await?;

        info!("Successfully handled OAuth callback and obtained token.");
        Ok(())
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn exchange_code_for_token(&self, code: &str) -> Result<TokenResponse, FortnoxError> {
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
            .post(FORTNOX_TOKEN_URL)
            .header(AUTHORIZATION, auth_header_value)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await; // reqwest::Error maps via #[from]

        // Use helper to handle response status and body parsing
        self.handle_token_response(response).await
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn refresh_access_token(&self) -> Result<String, FortnoxError> {
        let refresh_token = {
            let token_guard = self.token_data.lock().await;
            // .map_err(|_| FortnoxError::LockError("Failed to acquire token lock for refresh".to_string()))?;
            match &*token_guard {
                Some(data) => data.refresh_token.clone(),
                // Use specific error if no token data exists at all
                None => return Err(FortnoxError::MissingToken),
            }
        }; // Guard dropped here

        let credentials = format!("{}:{}", self.config.client_id, self.config.client_secret);
        let encoded_credentials = BASE64_STANDARD.encode(credentials);
        let auth_header_value = format!("Basic {}", encoded_credentials);

        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
        ];

        let response_result = self
            .http_client
            .post(FORTNOX_TOKEN_URL)
            .header(AUTHORIZATION, auth_header_value)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await;

        match self.handle_token_response(response_result).await {
            Ok(token_response) => {
                // Update state on successful refresh
                self.update_token_state(&token_response).await?;
                Ok(token_response.access_token)
            }
            Err(e) => {
                error!("Token refresh failed: {}", e);
                // If refresh fails, clear token data as it's likely invalid
                {
                    let mut token_guard = self.token_data.lock().await;
                    // .map_err(|_| FortnoxError::LockError("Failed to acquire token lock for clearing".to_string()))?;
                    *token_guard = None;
                } // Guard dropped here

                // Try to remove the token file, log error if removal fails
                if self.config.token_file_path.exists() {
                    if let Err(remove_err) = fs::remove_file(&self.config.token_file_path) {
                        warn!(
                            "Failed to remove invalid token file {:?}: {}",
                            self.config.token_file_path, remove_err
                        );
                    }
                }
                // Return the original error that caused the refresh to fail
                Err(e)
            }
        }
    }

    // Helper for handling token endpoint responses
    async fn handle_token_response(
        &self,
        response_result: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<TokenResponse, FortnoxError> {
        let response = response_result?; // Maps reqwest::Error
        let status = response.status();

        if status.is_success() {
            // Deserialize success response - serde_json::Error maps via #[from]
            let token_response = response.json::<TokenResponse>().await?;
            Ok(token_response)
        } else {
            // Handle error response
            let error_body = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            let message = match serde_json::from_str::<FortnoxErrorPayload>(&error_body) {
                Ok(parsed) => parsed.error_information.message.unwrap_or(error_body),
                Err(_) => error_body, // Use raw body if parsing fails
            };

            // Distinguish between refresh failure and other API errors if needed,
            // but here we map based on status code from the token endpoint.
            // Let's create a specific TokenRefreshFailed error for clarity.
            Err(FortnoxError::TokenRefreshFailed {
                status: Some(status),
                message,
            })
        }
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn get_valid_access_token(&self) -> Result<String, FortnoxError> {
        let token_guard = self.token_data.lock().await;
        // .map_err(|_| FortnoxError::LockError("Failed to acquire token lock for validation".to_string()))?;

        let needs_refresh = match &*token_guard {
            // Check if expired within the next 60 seconds
            Some(data) => data.is_expired(60)?, // is_expired now returns FortnoxError
            None => true,                       // No token means we need one
        };

        let access_token = if !needs_refresh {
            let token = token_guard.as_ref().unwrap().access_token.clone();
            drop(token_guard); // Release lock
            token
        } else {
            drop(token_guard); // Release lock before calling refresh
                               // refresh_access_token now returns FortnoxError
            self.refresh_access_token().await?
        };

        Ok(access_token)
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn build_request(
        &self,
        method: Method,
        endpoint: &str,
        base_url: Option<&str>,
    ) -> Result<RequestBuilder, FortnoxError> {
        let access_token = self.get_valid_access_token().await?; // Returns FortnoxError

        let base = base_url.unwrap_or(FORTNOX_API_BASE_URL);
        let url = if endpoint.starts_with("http") {
            endpoint.to_string()
        } else if endpoint.starts_with('/') {
            format!("{}{}", base, endpoint)
        } else {
            format!("{}/{}", base, endpoint)
        };

        // Validate the final URL - url::ParseError maps via #[from]
        Url::parse(&url)?;

        Ok(self
            .http_client
            .request(method, &url)
            .header(AUTHORIZATION, format!("Bearer {}", access_token))
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json"))
    }

    pub async fn send_and_deserialize<T: DeserializeOwned + Serialize>(
        // Added Serialize bound here for caching, but not strictly needed for this debug
        &self,
        request_builder: RequestBuilder,
        context_msg: &str,
    ) -> Result<T, FortnoxError> {
        let request = match request_builder.build() {
            Ok(req) => req,
            Err(e) => {
                error!("Request build failed for '{}': {}", context_msg, e); // Log build error explicitly
                return Err(FortnoxError::Request(e));
            }
        };
        let request_url = request.url().to_string();
        debug!(
            "Sending request for '{}' to URL: {}",
            context_msg, request_url
        );

        let response_result = self.http_client.execute(request).await; // Execute returns Result

        match response_result {
            Ok(resp) => {
                let status = resp.status();
                info!(
                    "Received response for '{}' (URL: {}): Status={}",
                    context_msg, request_url, status
                );

                if status.is_success() {
                    let response_bytes_result = resp.bytes().await;
                    match response_bytes_result {
                        Ok(bytes) => {
                            // Attempt to log as text, handle non-UTF8
                            match std::str::from_utf8(&bytes) {
                                Ok(text) => {
                                    debug!(
                                        "Raw Success Response Body for '{}': {}",
                                        context_msg, text
                                    );
                                    // Now try to deserialize from the bytes
                                    match serde_json::from_slice::<T>(&bytes) {
                                        Ok(data) => {
                                            debug!(
                                                "Successfully deserialized success response for '{}'",
                                                context_msg
                                            );
                                            Ok(data)
                                        }
                                        Err(e) => {
                                            error!(
                                                "JSON deserialization failed for '{}' (URL: {}) from raw body: {}",
                                                context_msg, request_url, e
                                            );
                                            // Return specific JSON error
                                            Err(FortnoxError::Json(e))
                                        }
                                    }
                                }
                                Err(_) => {
                                    warn!(
                                        "Response body for '{}' is not valid UTF-8. Logging hex.",
                                        context_msg
                                    );
                                    debug!(
                                        "Raw Success Response Body (Hex) for '{}': {}",
                                        context_msg,
                                        hex::encode(&bytes)
                                    );
                                    // Still try to deserialize, might work if it's JSON despite non-UTF8 parts
                                    match serde_json::from_slice::<T>(&bytes) {
                                        Ok(data) => Ok(data), // Success despite non-UTF8? Unlikely but handle.
                                        Err(e) => {
                                            error!("JSON deserialization failed for '{}' (URL: {}) from non-UTF8 body: {}", context_msg, request_url, e);
                                            Err(FortnoxError::Json(e))
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "Failed to read response body bytes for '{}': {}",
                                context_msg, e
                            );
                            Err(FortnoxError::Request(e)) // Reading body failed
                        }
                    }
                } else {
                    // Handle non-success status codes
                    let error_body = resp
                        .text()
                        .await
                        .unwrap_or_else(|e| format!("Failed to read error body: {}", e)); // Include read error

                    // Log the raw error body for non-success status
                    error!(
                        "API Error Response: Status={}, Body='{}' for URL: {}",
                        status, error_body, request_url
                    );

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        warn!(
                            "Rate limit exceeded for '{}' (URL: {})",
                            context_msg, request_url
                        );
                        Err(FortnoxError::RateLimitExceeded)
                    } else {
                        // Try to parse as FortnoxErrorPayload for a better message
                        let message = match serde_json::from_str::<FortnoxErrorPayload>(&error_body)
                        {
                            Ok(parsed) => parsed
                                .error_information
                                .message
                                .unwrap_or(error_body.clone()), // Clone error_body
                            Err(_) => error_body, // Use raw body if parsing specific error fails
                        };
                        Err(FortnoxError::ApiError { status, message })
                    }
                }
            }
            Err(e) => {
                // This catches errors before even getting a response (network, DNS, timeout etc.)
                error!(
                    "HTTP execution failed before receiving response for '{}' (URL: {}): {}",
                    context_msg, request_url, e
                );
                Err(FortnoxError::Request(e)) // This mapping is correct
            }
        }
    }

    // Generic method to get data from an endpoint (no change needed)
    pub async fn get<T: DeserializeOwned + Serialize>(
        &self,
        endpoint: &str,
        base_url: Option<&str>,
        context_msg: &str,
    ) -> Result<T, FortnoxError> {
        let request = self.build_request(Method::GET, endpoint, base_url).await?;
        self.send_and_deserialize(request, context_msg).await
    }

    // Cache key generation (remains the same logic, no errors expected)
    pub fn generate_cache_key(
        &self,
        resource_type: &str,
        resource_id: Option<&str>,
        query_params: Option<&HashMap<String, String>>,
    ) -> String {
        // ... (same logic as before) ...
        let mut key = resource_type.replace(|c: char| !c.is_alphanumeric(), "_");

        if let Some(id) = resource_id {
            key.push_str("__ID_"); // Separator
            key.push_str(&id.replace(|c: char| !c.is_alphanumeric(), "_"));
        }

        if let Some(params) = query_params {
            if !params.is_empty() {
                key.push_str("__PARAMS_");
                let mut sorted_keys: Vec<_> = params.keys().collect();
                sorted_keys.sort();

                for k in sorted_keys {
                    if let Some(v) = params.get(k) {
                        // Basic sanitization
                        let safe_k = k.replace(|c: char| !c.is_alphanumeric(), "_");
                        let safe_v = v.replace(|c: char| !c.is_alphanumeric(), "_");
                        key.push_str(&safe_k);
                        key.push('_'); // Use underscore as separator
                        key.push_str(&safe_v);
                        key.push(';'); // Use semicolon between params
                    }
                }
            }
        }
        // Limit key length if necessary, potentially using a hash
        const MAX_KEY_LEN: usize = 100;
        if key.len() > MAX_KEY_LEN {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            let hash = hasher.finalize();
            key = format!("{}_{}", &key[..MAX_KEY_LEN / 2], hex::encode(&hash[..8]));
            // Keep prefix + hash
        }

        key
    }

    // Get cache file path (no errors expected)
    pub fn get_cache_file_path(&self, cache_key: &str) -> PathBuf {
        self.config.cache_dir.join(format!("{}.json", cache_key))
    }

    // Updated to return Result<_, FortnoxError>
    pub fn save_to_cache<T: Serialize>(
        &self,
        resource_type: &str,
        resource_id: Option<&str>,
        query_params: Option<&HashMap<String, String>>,
        data: &T,
    ) -> Result<(), FortnoxError> {
        let cache_key = self.generate_cache_key(resource_type, resource_id, query_params);
        let cache_path = self.get_cache_file_path(&cache_key);

        // Create parent directories if they don't exist
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                io_context(e, format!("Failed to create cache directory: {:?}", parent))
            })?;
        } else {
            warn!("Cache path {:?} has no parent directory", cache_path);
        }

        // `new` returns FortnoxError
        let metadata = CacheMetadata::new(
            resource_type.to_string(),
            resource_id.map(|s| s.to_string()),
            query_params.cloned(),
        )?;

        let cached_data = CachedData { metadata, data };

        // serde_json::Error maps via #[from]
        let json_string = serde_json::to_string_pretty(&cached_data)?;

        let mut file = File::create(&cache_path)
            .map_err(|e| io_context(e, format!("Failed to create cache file: {:?}", cache_path)))?;
        file.write_all(json_string.as_bytes()).map_err(|e| {
            io_context(
                e,
                format!("Failed to write to cache file: {:?}", cache_path),
            )
        })?;

        debug!("Saved data to cache for key: {}", cache_key);
        Ok(())
    }

    // Updated to return Result<_, FortnoxError>
    pub fn load_from_cache<T: DeserializeOwned>(
        &self,
        resource_type: &str,
        resource_id: Option<&str>,
        query_params: Option<&HashMap<String, String>>,
    ) -> Result<Option<T>, FortnoxError> {
        let cache_key = self.generate_cache_key(resource_type, resource_id, query_params);
        let cache_path = self.get_cache_file_path(&cache_key);

        if !cache_path.exists() {
            debug!("Cache miss (file not found) for key: {}", cache_key);
            return Ok(None);
        }

        let json_string = fs::read_to_string(&cache_path)
            .map_err(|e| io_context(e, format!("Failed to read cache file: {:?}", cache_path)))?;

        // Handle potentially corrupt cache file
        let cached_data: CachedData<T> = match serde_json::from_str(&json_string) {
            Ok(data) => data,
            Err(e) => {
                warn!(
                    "Failed to deserialize cache file {:?}: {}. Removing corrupt cache file.",
                    cache_path, e
                );
                if let Err(remove_err) = fs::remove_file(&cache_path) {
                    error!(
                        "Failed to remove corrupt cache file {:?}: {}",
                        cache_path, remove_err
                    );
                    // Map removal error to CacheError? Or just log? Let's log and treat as miss.
                }
                // Don't return error, treat as cache miss
                return Ok(None);
            }
        };

        // is_stale returns FortnoxError
        if cached_data
            .metadata
            .is_stale(self.config.cache_duration_secs)?
        {
            debug!("Cache stale for key: {}", cache_key);
            return Ok(None);
        }

        debug!("Cache hit for key: {}", cache_key);
        Ok(Some(cached_data.data))
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn get_with_cache<T: DeserializeOwned + Serialize>(
        &self,
        endpoint: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        query_params: Option<&HashMap<String, String>>,
        base_url: Option<&str>,
        context_msg: &str,
    ) -> Result<T, FortnoxError> {
        // Try to load from cache first - uses FortnoxError internally
        match self.load_from_cache(resource_type, resource_id, query_params) {
            Ok(Some(cached_data)) => return Ok(cached_data),
            Ok(None) => { /* Cache miss or stale, continue to fetch */ }
            Err(e) => {
                // Log cache load warning
                warn!(
                    "Failed to load from cache for {} ({}): {}. Attempting API fetch.",
                    resource_type, context_msg, e
                );
            }
        }

        // Fetch from API - uses FortnoxError internally
        let request_builder = self.build_request(Method::GET, endpoint, base_url).await?;

        let request_builder = if let Some(params) = query_params {
            request_builder.query(params)
        } else {
            request_builder
        };

        let response_data: T = self
            .send_and_deserialize(request_builder, context_msg)
            .await?;

        // Save to cache - uses FortnoxError internally
        if let Err(e) = self.save_to_cache(resource_type, resource_id, query_params, &response_data)
        {
            error!(
                "Failed to save to cache for {} ({}): {}",
                resource_type, context_msg, e
            );
            // Don't return error on cache save failure, just log it.
            // return Err(FortnoxError::CacheError(format!("Failed to save cache: {}", e)));
        }

        Ok(response_data)
    }

    // --- API Methods ---

    pub async fn get_time_registrations(
        &self,
        from_date: &str,
        to_date: &str,
        user_ids: Option<Vec<String>>,
        customer_ids: Option<Vec<String>>,
        project_ids: Option<Vec<String>>,
    ) -> Result<Vec<DetailedRegistration>, FortnoxError> {
        let mut query_vec: Vec<(String, String)> = vec![
            ("fromDate".to_string(), from_date.to_string()),
            ("toDate".to_string(), to_date.to_string()),
        ];
        if let Some(ids) = user_ids {
            ids.iter()
                .for_each(|id| query_vec.push(("userIds".to_string(), id.clone())));
        }
        if let Some(ids) = customer_ids {
            ids.iter()
                .for_each(|id| query_vec.push(("customerIds".to_string(), id.clone())));
        }
        if let Some(ids) = project_ids {
            ids.iter()
                .for_each(|id| query_vec.push(("projectIds".to_string(), id.clone())));
        }

        let mut cache_params = HashMap::new();
        for (k, v) in &query_vec {
            cache_params.insert(k.clone(), v.clone());
        } // Rebuild map for cache key

        // The base URL for the time API is https://api.fortnox.se/api/time
        // The specific endpoint path is /registrations-v2
        let endpoint = "/registrations-v2";
        let base_url = Some(FORTNOX_TIME_API_URL);

        // Use get_with_cache which now returns FortnoxError
        self.get_with_cache(
            endpoint,
            "time_registrations",
            None,
            Some(&cache_params),
            base_url,
            "Get Time Registrations V2", // Updated context
        )
        .await
    }

    /// Retrieves information about the currently authenticated user (based on the access token).
    /// The `Id` field in the returned `FortnoxMe` struct corresponds to the `userId`.
    pub async fn get_me(&self) -> Result<FortnoxMe, FortnoxError> {
        let endpoint = "/me"; // Endpoint relative to the base API URL

        // Fetch data using the generic get_with_cache method.
        // The API returns a wrapped response, so we deserialize into FortnoxMeWrap first.
        let response_wrapper: FortnoxMeWrap = self
            .get_with_cache(
                endpoint,
                "me_information", // A unique identifier for caching this resource type
                None,             // No specific resource ID for the /me endpoint
                None,             // No query parameters for this endpoint
                None,             // Use the default base URL (FORTNOX_API_BASE_URL)
                "Get Me Information", // Context message for logging/errors
            )
            .await?; // Propagates FortnoxError on failure

        // Extract the actual user information from the wrapper
        Ok(response_wrapper.me_information)
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn get_schedule_time(
        &self,
        employee_id: &str,
        date: &str,
    ) -> Result<ScheduleTimeResponse, FortnoxError> {
        let endpoint = format!("/scheduletimes/{}/{}", employee_id, date);
        let cache_params = HashMap::from([("date".to_string(), date.to_string())]);
        self.get_with_cache(
            &endpoint,
            "schedule_time",
            Some(employee_id),
            Some(&cache_params),
            None, // Uses FORTNOX_API_BASE_URL
            "Get Schedule Time",
        )
        .await
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn get_employees(&self) -> Result<EmployeeListResponse, FortnoxError> {
        self.get_with_cache("/employees", "employees", None, None, None, "Get Employees")
            .await
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn get_employee(&self, employee_id: &str) -> Result<EmployeeListItem, FortnoxError> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct SingleEmployeeResponse {
            #[serde(rename = "Employee")]
            employee: EmployeeListItem,
        }

        let endpoint = format!("/employees/{}", employee_id);
        let response: SingleEmployeeResponse = self
            .get_with_cache(
                &endpoint,
                "employee",
                Some(employee_id),
                None,
                None,
                "Get Employee by ID",
            )
            .await?;
        Ok(response.employee)
    }

    // Get all customers
    pub async fn get_customers(&self) -> Result<CustomerListResponse, FortnoxError> {
        self.get_with_cache("/customers", "customers", None, None, None, "Get Customers")
            .await
    }

    // Get customer by ID
    pub async fn get_customer(&self, customer_id: &str) -> Result<CustomerListItem, FortnoxError> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct SingleCustomerResponse {
            #[serde(rename = "Customer")]
            customer: CustomerListItem,
        }

        let endpoint = format!("/customers/{}", customer_id);
        let response: SingleCustomerResponse = self
            .get_with_cache(
                &endpoint,
                "customer",
                Some(customer_id),
                None,
                None,
                "Get Customer by ID",
            )
            .await?;
        Ok(response.customer)
    }

    // Get all projects
    pub async fn get_projects(&self) -> Result<ProjectListResponse, FortnoxError> {
        self.get_with_cache("/projects", "projects", None, None, None, "Get Projects")
            .await
    }

    // Get project by ID
    pub async fn get_project(&self, project_id: &str) -> Result<ProjectListItem, FortnoxError> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct SingleProjectResponse {
            #[serde(rename = "Project")]
            project: ProjectListItem,
        }

        let endpoint = format!("/projects/{}", project_id);
        let response: SingleProjectResponse = self
            .get_with_cache(
                &endpoint,
                "project",
                Some(project_id),
                None,
                None,
                "Get Project by ID",
            )
            .await?;
        Ok(response.project)
    }

    // Get all articles
    pub async fn get_articles(&self) -> Result<ArticleListResponse, FortnoxError> {
        self.get_with_cache("/articles", "articles", None, None, None, "Get Articles")
            .await
    }

    // Get article by ID
    pub async fn get_article(&self, article_id: &str) -> Result<ArticleListItem, FortnoxError> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct SingleArticleResponse {
            #[serde(rename = "Article")]
            article: ArticleListItem,
        }

        let endpoint = format!("/articles/{}", article_id);
        let response: SingleArticleResponse = self
            .get_with_cache(
                &endpoint,
                "article",
                Some(article_id),
                None,
                None,
                "Get Article by ID",
            )
            .await?;
        Ok(response.article)
    }

    // Updated to return Result<_, FortnoxError>
    pub fn clear_cache(
        &self,
        resource_type: &str,
        resource_id: Option<&str>,
    ) -> Result<(), FortnoxError> {
        let cache_dir = &self.config.cache_dir;
        if !cache_dir.exists() {
            return Ok(()); // Nothing to clear
        }

        let file_prefix_to_match = self.generate_cache_key(resource_type, resource_id, None);

        let entries = fs::read_dir(cache_dir).map_err(|e| {
            io_context(
                e,
                format!("Failed to read cache directory: {:?}", cache_dir),
            )
        })?;

        for entry_result in entries {
            let entry =
                entry_result.map_err(|e| io_context(e, "Failed to read directory entry"))?;
            let path = entry.path();

            if path.is_file() {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with(&file_prefix_to_match) && file_name.ends_with(".json")
                    {
                        info!("Clearing cache file: {:?}", path);
                        fs::remove_file(&path).map_err(|e| {
                            io_context(e, format!("Failed to remove cache file: {:?}", path))
                        })?;
                    }
                }
            }
        }
        Ok(())
    }

    // Updated to return Result<_, FortnoxError>
    pub fn clear_all_cache(&self) -> Result<(), FortnoxError> {
        let cache_dir = &self.config.cache_dir;

        if cache_dir.exists() {
            info!("Clearing all cache files in directory: {:?}", cache_dir);
            let entries = fs::read_dir(cache_dir).map_err(|e| {
                io_context(
                    e,
                    format!("Failed to read cache directory: {:?}", cache_dir),
                )
            })?;

            for entry_result in entries {
                let entry =
                    entry_result.map_err(|e| io_context(e, "Failed to read directory entry"))?;
                let path = entry.path();

                if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                    fs::remove_file(&path).map_err(|e| {
                        io_context(e, format!("Failed to remove cache file: {:?}", path))
                    })?;
                }
            }
        } else {
            info!(
                "Cache directory {:?} does not exist, nothing to clear.",
                cache_dir
            );
        }
        Ok(())
    }

    // Updated to return Result<_, FortnoxError>
    pub async fn get_token_status(&self) -> Result<TokenStatus, FortnoxError> {
        let token_guard = self.token_data.lock().await;
        // .map_err(|_| FortnoxError::LockError("Failed to acquire token lock for status check".to_string()))?;

        match &*token_guard {
            Some(data) => {
                // is_expired returns FortnoxError
                let is_expired = data.is_expired(0)?;
                let is_valid_soon = !data.is_expired(60)?;

                let now = SystemTime::now();
                let expires_at_systemtime =
                    UNIX_EPOCH + Duration::from_secs(data.expires_at_unix_secs);

                let expires_in_secs = expires_at_systemtime
                    .duration_since(now)
                    .unwrap_or_default()
                    .as_secs();
                let expires_at_datetime = DateTime::<Utc>::from(expires_at_systemtime);

                Ok(TokenStatus {
                    has_token: true,
                    is_valid: is_valid_soon,
                    is_expired,
                    expires_in_secs,
                    expires_at: expires_at_datetime.to_rfc3339(),
                })
            }
            None => Ok(TokenStatus {
                has_token: false,
                is_valid: false,
                is_expired: true,
                expires_in_secs: 0,
                expires_at: "".to_string(),
            }),
        }
    }
}

// TokenStatus struct (remains the same)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatus {
    pub has_token: bool,
    pub is_valid: bool,
    pub is_expired: bool,
    pub expires_in_secs: u64,
    pub expires_at: String,
}

// --- Background Task (Adjust error handling) ---
pub async fn run_fortnox_token_refresh(refresh_client: Arc<FortnoxClient>) {
    info!("Starting background token refresh task");
    const REFRESH_THRESHOLD_SECS: u64 = 600;
    let sleep_duration = Duration::from_secs(REFRESH_THRESHOLD_SECS);

    loop {
        match refresh_client.get_token_status().await {
            Ok(status) => {
                if status.has_token {
                    if status.is_expired || status.expires_in_secs < REFRESH_THRESHOLD_SECS {
                        info!(
                            "Token is expired or expires soon (in {} seconds). Attempting refresh...",
                            status.expires_in_secs
                        );
                        // get_valid_access_token returns FortnoxError
                        match refresh_client.get_valid_access_token().await {
                            Ok(_) => {
                                info!("Background token refresh successful");
                                // Recalculate sleep based on new status
                                if let Ok(new_status) = refresh_client.get_token_status().await {
                                    info!(
                                        "Next token check/refresh scheduled in approx {} seconds",
                                        sleep_duration.as_secs()
                                    );
                                } else {
                                    error!("Failed to get token status after successful refresh, using default interval.");
                                }
                            }
                            Err(e) => {
                                // Log the specific FortnoxError
                                error!("Background token refresh failed: {}", e);
                                // Check if it's a recoverable error type, potentially adjust retry logic
                            }
                        }
                    } else {
                        info!(
                            "Token is valid for {} more seconds. Next check in approx {} seconds",
                            status.expires_in_secs,
                            sleep_duration.as_secs()
                        );
                    }
                } else {
                    info!(
                        "No token available. Checking again in {} seconds.",
                        sleep_duration.as_secs()
                    );
                }
            }
            Err(e) => {
                // Log specific FortnoxError from status check
                error!("Failed to check token status in background task: {}", e);
            }
        }
        sleep(sleep_duration).await;
    }
}
