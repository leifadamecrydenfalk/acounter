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
struct FortnoxErrorInformation {
    error: Option<serde_json::Value>, // Use Value for flexibility (could be int or string)
    message: Option<String>,
    code: Option<serde_json::Value>, // Use Value for flexibility
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")] // Assuming root is PascalCase
struct FortnoxErrorPayload {
    #[serde(rename = "ErrorInformation")]
    error_information: FortnoxErrorInformation,
}

#[derive(Error, Debug)]
enum AppError {
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
        raw_message: Option<String>,             // Keep raw as fallback
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
            AppError::SuccessfulResponseDeserialization(ref _e) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error (Unexpected response format from Fortnox). Check logs.".to_string()
            ),

            // Ensure all existing mappings are correct
             AppError::MissingEnvVar(ref _var) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Configuration error.".to_string(),
            ),
            AppError::Reqwest(ref _e) => (
                AxumStatusCode::BAD_GATEWAY,
                "External request failed.".to_string(),
            ),
            AppError::UrlParse(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error (URL parsing).".to_string(),
            ),
            AppError::SerdeJson(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error (JSON processing).".to_string(),
            ),
            AppError::Io(_) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error (File I/O). Check logs.".to_string(),
            ),
            AppError::OAuthStateMismatch => (
                AxumStatusCode::BAD_REQUEST,
                "OAuth state validation failed.".to_string(),
            ),
            AppError::FortnoxApiError { status, .. } => { // Simplified match arm
                let axum_status = AxumStatusCode::from_u16(status.as_u16())
                    .unwrap_or(AxumStatusCode::INTERNAL_SERVER_ERROR);

                let user_message = format!(
                    "Failed to communicate with Fortnox API (Status {}). Details logged.",
                    status.as_u16()
                );
                 (axum_status, user_message)
            },
            AppError::FortnoxRateLimited => (
                AxumStatusCode::TOO_MANY_REQUESTS,
                "Fortnox API rate limit exceeded. Please try again later.".to_string(),
            ),
            AppError::LockError => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error (Concurrency).".to_string(),
            ),
            AppError::MissingAuthCode => (
                AxumStatusCode::BAD_REQUEST,
                "Authorization code missing in callback.".to_string(),
            ),
            AppError::MissingOrInvalidToken => (
                AxumStatusCode::UNAUTHORIZED,
                "Authentication token not available, expired, or refresh failed. Please try authenticating again via /api/fortnox/auth".to_string()
            ),
            AppError::SystemTimeError(ref msg) => (
                 AxumStatusCode::INTERNAL_SERVER_ERROR,
                 format!("Internal Server Error (Time Calculation: {})", msg)
             ),
            AppError::TlsConfig(ref msg) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error (TLS Setup: {}). Check logs.", msg)
            ),
            AppError::FortnoxServiceError(ref msg) => (
                AxumStatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal Fortnox Service Error: {}", msg)
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

// --- Fortnox API Response Structures ---

// Structures for GET /3/employees
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EmployeeListItem {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "EmployeeId")]
    pub employee_id: String, // Key identifier
    #[serde(rename = "PersonalIdentityNumber")]
    pub personal_identity_number: Option<String>,
    #[serde(rename = "FirstName")]
    pub first_name: Option<String>,
    #[serde(rename = "LastName")]
    pub last_name: Option<String>,
    #[serde(rename = "FullName")]
    pub full_name: Option<String>,
    pub email: Option<String>,
    // Add other fields if needed later
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EmployeeListResponse {
    pub employees: Vec<EmployeeListItem>,
}

// Structures for GET /3/customers
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct CustomerListItem {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "CustomerNumber")]
    pub customer_number: String, // Key identifier
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
    // Add other fields if needed later
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct CustomerListResponse {
    pub customers: Vec<CustomerListItem>,
}

// Structures for GET /3/projects (Updated to match response schema)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ProjectListItem {
    // Renamed from Project to avoid conflict and match list nature
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "ProjectNumber")]
    pub project_number: String, // Key identifier
    pub description: String,    // Project Name/Description
    pub status: Option<String>, // (enum: NOTSTARTED, ONGOING, COMPLETED)
    #[serde(rename = "StartDate")]
    pub start_date: Option<String>, // (date)
    #[serde(rename = "EndDate")]
    pub end_date: Option<String>, // (date)
    #[serde(rename = "ProjectLeader")]
    pub project_leader_id: Option<String>, // Assuming this is an ID, adjust if it's name
    #[serde(rename = "CustomerNumber")]
    // Add CustomerNumber as it exists in the original Project struct context
    pub customer_number: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ProjectListResponse {
    // Renamed from ProjectResponse
    pub projects: Vec<ProjectListItem>,
    #[serde(rename = "@TotalResources")]
    pub total_resources: Option<i32>,
    #[serde(rename = "@TotalPages")]
    pub total_pages: Option<i32>,
    #[serde(rename = "@CurrentPage")]
    pub current_page: Option<i32>,
}

// Structures for GET /3/articles (Services)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ArticleListItem {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "ArticleNumber")]
    pub article_number: String, // Key identifier (e.g., "16", "52")
    pub description: String,  // Service/Article Name
    pub unit: Option<String>, // e.g., "tim" (hours)
    #[serde(rename = "SalesPrice")]
    pub sales_price: Option<String>, // Price as a string
    #[serde(rename = "PurchasePrice")]
    pub purchase_price: Option<String>, // Cost as a string
    #[serde(rename = "Active")]
    pub active: Option<bool>,
    // Add other fields if needed later
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ArticleListResponse {
    pub articles: Vec<ArticleListItem>,
}

// Structures for GET /3/scheduletimes/{EmployeeId}/{Date}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ScheduleTime {
    #[serde(rename = "EmployeeId")]
    pub employee_id: String,
    #[serde(rename = "Date")]
    pub date: String, // (date)
    #[serde(rename = "ScheduleId")]
    pub schedule_id: Option<String>, // ID of the schedule template used
    pub hours: String, // Scheduled hours for the day (e.g., "8.00") - Keep as String due to source format
                       // Other fields (IWH1-5) exist but less relevant
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ScheduleTimeResponse {
    #[serde(rename = "ScheduleTime")]
    pub schedule_time: ScheduleTime,
}

// Structures for GET /api/time/registrations-v2
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")] // Note: This API uses camelCase
pub struct TimeRegCustomerInfo {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TimeRegProjectInfo {
    pub id: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TimeRegServiceInfo {
    pub id: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TimeRegCodeInfo {
    pub code: String, // e.g., "TID", "FLX", "SEM"
    pub name: String,
    #[serde(rename = "type")] // Use rename for reserved keyword
    pub type_: String, // (enum: WORK, ABSENCE) - use type_ or rename
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DetailedRegistration {
    pub id: String, // (uuid)
    #[serde(rename = "userId")]
    pub user_id: String, // Fortnox User ID
    pub worked_date: String, // (date)
    pub worked_hours: f64, // Use f64 for hours
    pub charge_hours: f64,
    pub start_time: Option<String>, // (date-time) ISO 8601 format (e.g., "2023-10-27T08:00:00Z")
    pub stop_time: Option<String>,  // (date-time)
    pub non_invoiceable: bool,
    pub note: Option<String>,
    pub invoice_text: Option<String>,
    pub customer: Option<TimeRegCustomerInfo>, // Optional because absence might not have customer
    pub project: Option<TimeRegProjectInfo>,   // Optional
    pub service: Option<TimeRegServiceInfo>,   // Optional (e.g., for absence)
    pub registration_code: TimeRegCodeInfo,
    pub child_id: Option<String>,      // (uuid)
    pub document_id: Option<i64>,      // (int64)
    pub document_type: Option<String>, // (enum: order, invoice)
    pub invoice_basis_id: Option<i64>, // (int64)
    pub unit_cost: Option<f64>,        // Use f64 for currency/cost/price
    pub unit_price: Option<f64>,
    // Other fields omitted for brevity: created, createdBy, modified, modifiedBy, version
}

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

// --- Structure for Cached Data ---
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CachedInfo {
    pub last_updated_unix_secs: u64,
}

impl CachedInfo {
    /// Checks if the cache is older than the specified duration.
    pub fn is_stale(&self, max_age_secs: u64) -> Result<bool, AppError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::SystemTimeError(e.to_string()))?
            .as_secs();
        let cache_age = now_unix.saturating_sub(self.last_updated_unix_secs);
        Ok(cache_age > max_age_secs)
    }

    /// Creates a new CachedInfo with the current time.
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {
            last_updated_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| AppError::SystemTimeError(e.to_string()))?
                .as_secs(),
        })
    }
}

/// Structure containing all the data fetched for the info page cache.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FortnoxInfoCacheData {
    pub info: CachedInfo,
    pub employees: Vec<EmployeeListItem>,
    pub customers: Vec<CustomerListItem>,
    pub projects: Vec<ProjectListItem>,
    pub articles: Vec<ArticleListItem>,
    // Add other lists here if needed in the future (e.g., registration codes)
}

// --- Fortnox API Client ---
// FortnoxService with a valid token
#[derive(Clone)]
struct FortnoxApiClient {
    http_client: Client,
    access_token: String, // Holds the *valid* access token
    base_url: String,
    client_secret: String, // Still needed for headers on some endpoints to retrieve access token? Keep for now.
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

    /*
    // If there is no access token available, use this to retrieve it using the client secret
    fn build_auth_request(&self, method: Method, endpoint: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, endpoint);
        self.http_client
            .request(method, url)
            .header("Client-Secret", self.client_secret.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
    }
    */

    fn build_request(&self, method: Method, endpoint: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, endpoint);
        self.http_client
            .request(method, &url)
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
    }

    async fn send_and_deserialize<T: DeserializeOwned>(
        &self,
        request_builder: RequestBuilder,
    ) -> Result<T, AppError> {
        let response = request_builder.send().await?;
        let status = response.status();

        if status.is_success() {
            // Success Path: Attempt to deserialize the successful response
            response.json::<T>().await.map_err(|e: reqwest::Error| {
                // Log the specific error
                error!(
                    "Failed to deserialize successful Fortnox response (Status: {}): {}",
                    status, e
                );
                // Use the new specific error variant
                AppError::SuccessfulResponseDeserialization(e)
            })
        } else {
            // Error Path: Handle non-success status codes
            let raw_body_text = response.text().await.ok(); // Read body as text first

            // Attempt to parse the known Fortnox JSON error structure
            let parsed_error: Option<FortnoxErrorPayload> = raw_body_text
                .as_ref()
                .and_then(|body| serde_json::from_str(body).ok());

            if parsed_error.is_some() {
                 warn!( // Log as warn, the error type carries the severity
                    "Fortnox API request failed. Status: {}, Parsed Body: {:?}",
                    status, parsed_error
                );
            } else {
                 warn!( // Log as warn, the error type carries the severity
                    "Fortnox API request failed. Status: {}, Raw Body: {:?} (Could not parse as FortnoxErrorPayload)",
                    status, raw_body_text
                );
            }

            // Map specific status codes to specific AppError variants
            match status {
                ReqwestStatusCode::TOO_MANY_REQUESTS => Err(AppError::FortnoxRateLimited),
                _ => Err(AppError::FortnoxApiError {
                    status,
                    parsed_error, // Pass the Option<FortnoxErrorPayload>
                    raw_message: raw_body_text, // Pass the Option<String>
                }),
            }
        }
    }

    // --- get, fetch_ methods remain the same ---
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> Result<T, AppError> {
        let corrected_endpoint = if endpoint.starts_with('/') {
            endpoint
        } else {
            warn!(
                "Endpoint '{}' passed to get() did not start with '/'. Prepending.",
                endpoint
            );
            &format!("/{}", endpoint)
        };
        let request = self.build_request(Method::GET, corrected_endpoint);
        self.send_and_deserialize(request).await
    }

    pub async fn fetch_projects(&self) -> Result<ProjectResponse, AppError> {
        info!("Fetching projects via API client...");
        self.get::<ProjectResponse>("/projects").await
    }

     pub async fn fetch_employees(&self) -> Result<EmployeeListResponse, AppError> {
        info!("Fetching employees via API client...");
        self.get::<EmployeeListResponse>("/employees").await
    }

    pub async fn fetch_customers(&self) -> Result<CustomerListResponse, AppError> {
        info!("Fetching customers via API client...");
        self.get::<CustomerListResponse>("/customers").await
    }

    pub async fn fetch_projects_list(&self) -> Result<ProjectListResponse, AppError> {
        info!("Fetching projects list via API client...");
        self.get::<ProjectListResponse>("/projects").await
    }

     pub async fn fetch_articles(&self) -> Result<ArticleListResponse, AppError> {
        info!("Fetching articles/services via API client...");
        self.get::<ArticleListResponse>("/articles").await
    }

    // Method to fetch a specific Article/Service
    pub async fn fetch_article_by_number(
        &self,
        article_number: &str,
    ) -> Result<ArticleListItem, AppError> {
        #[derive(Serialize, Deserialize, Debug, Clone)]
        #[serde(rename_all = "PascalCase")]
        struct SingleArticleResponse {
            Article: ArticleListItem,
        }

        info!("Fetching article with number: {}", article_number);
        let endpoint = format!("/articles/{}", article_number); // No /3 needed
        let response = self.get::<SingleArticleResponse>(&endpoint).await?;
        Ok(response.Article)
    }

    // Method to fetch Schedule Time for a specific employee and date
    pub async fn fetch_schedule_time(
        &self,
        employee_id: &str,
        date: &str, // Expects "YYYY-MM-DD" format
    ) -> Result<ScheduleTimeResponse, AppError> {
        info!(
            "Fetching schedule time for employee {} on date {}",
            employee_id, date
        );
        let endpoint = format!("/scheduletimes/{}/{}", employee_id, date); // No /3 needed
        self.get::<ScheduleTimeResponse>(&endpoint).await
    }

    // Method to fetch Time/Absence Registrations using V2 endpoint
    // This one needs special handling as it DOES NOT use the /3 base path
    pub async fn fetch_time_registrations_v2(
        &self,
        params: Option<HashMap<String, String>>, // Use HashMap for flexible query params
    ) -> Result<Vec<DetailedRegistration>, AppError> {
        info!("Fetching time registrations (V2) via API client...");
        // V2 API uses a different base path!
        const TIME_V2_API_BASE_URL: &str = "https://api.fortnox.se"; // Base *without* /3
        let endpoint = "/api/time/registrations-v2";
        let url = format!("{}{}", TIME_V2_API_BASE_URL, endpoint); // Construct full URL manually

        let mut request_builder = self
            .http_client
            .request(Method::GET, url) // Use the manually constructed URL
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            .header(ACCEPT, "application/json");

        // Add query parameters if provided
        if let Some(query_params) = params {
            let mut query_pairs = Vec::new();
            for (key, value) in query_params {
                query_pairs.push((key, value));
            }
            if !query_pairs.is_empty() {
                // Only add .query if there are params
                request_builder = request_builder.query(&query_pairs);
                info!("Added query parameters: {:?}", query_pairs);
            }
        }

        // Use send_and_deserialize helper
        self.send_and_deserialize::<Vec<DetailedRegistration>>(request_builder)
            .await
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

        // This 'params' variable holds the data to be sent in the form body
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
        ];

        // Build the request
        let request_builder = self
            .http_client
            .post(Self::TOKEN_URL) // Use associated const
            .header(AUTHORIZATION, auth_header_value)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params); 

        // Send the request and await the response
        let response = request_builder.send().await?; // Added ? for potential reqwest error

        if response.status().is_success() {
            info!("Token exchange request successful (Status: {}).", response.status());
            // Success path - deserialize TokenResponse
            response
                .json::<TokenResponse>()
                .await // Await the json deserialization
                .map_err(|e| {
                    // Handle potential deserialization error even on success here
                    error!("Successfully received token response, but failed to deserialize it: {}", e);
                    // Map reqwest error during json() to our specific variant
                    AppError::SuccessfulResponseDeserialization(e)
                })
        } else {
            // Error path - construct FortnoxApiError
            let status = response.status();
            // Read the raw body text first. Use await and handle potential error.
            let error_text = response.text().await.ok(); // .ok() converts Result<String, Error> to Option<String>

            error!(
                "Failed to exchange code for token. Status: {}, Body: {:?}",
                status, error_text
            );

            // Attempt to parse the error body as FortnoxErrorPayload
            // Use 'and_then' to avoid parsing if error_text is None
            let parsed_error: Option<FortnoxErrorPayload> = error_text
                 .as_ref() // Borrow the Option<String>
                 .and_then(|body| serde_json::from_str(body).map_err(|e| {
                     // Log if JSON parsing of the error body fails
                     warn!("Could not parse Fortnox error response body as JSON: {}", e);
                     e // keep the error type for map_err
                 }).ok()); // Convert Result<_, serde_json::Error> to Option<_>


            // Provide all required fields for FortnoxApiError
            Err(AppError::FortnoxApiError {
                status,
                parsed_error, // Provide the parsed error (will be None if parsing failed or text read failed)
                raw_message: error_text, // Provide the raw text (will be None if text read failed)
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
            .append_pair("response_type", "code")
            .append_pair("account_type", "service");

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

    /// Loads the combined Fortnox info data from the cache file.
    fn load_info_cache(&self) -> Result<Option<FortnoxInfoCacheData>, AppError> {
        let path = &self.config.info_cache_path;
        if !path.exists() {
            info!("Info cache file {} not found.", path.display());
            return Ok(None);
        }
        match fs::read_to_string(path) {
            Ok(json_string) => {
                match serde_json::from_str::<FortnoxInfoCacheData>(&json_string) {
                    Ok(data) => {
                        info!("Info cache loaded successfully from {}", path.display());
                        Ok(Some(data))
                    }
                    Err(e) => {
                        warn!(
                            // Use warn instead of error, treat as cache miss
                            "Failed to parse info cache file {}: {}. Will attempt refetch.",
                            path.display(),
                            e
                        );
                        // Optionally delete the corrupt file?
                        // fs::remove_file(path).ok();
                        Ok(None) // Treat parse error as cache miss
                    }
                }
            }
            Err(e) => {
                // File might exist but couldn't be read (permissions?)
                error!(
                    "Failed to read info cache file {}: {}. Will attempt refetch.",
                    path.display(),
                    e
                );
                // Decide if this should be a hard error or just a cache miss
                // For robustness, treat as a cache miss for now.
                Ok(None) // Treat read error as cache miss
                         // Or return Err(AppError::Io(e)) if read failure is critical
            }
        }
    }

    /// Saves the combined Fortnox info data to the cache file.
    fn save_info_cache(&self, data: &FortnoxInfoCacheData) -> Result<(), AppError> {
        let path = &self.config.info_cache_path;
        let json_string = serde_json::to_string_pretty(data)?;

        // Consider creating parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = File::create(path)?;
        file.write_all(json_string.as_bytes())?;
        info!("Info cache data saved to {}", path.display());
        Ok(())
    }

    /// Gets reference data (employees, customers, projects, articles), using cache if valid.
    pub async fn get_fortnox_reference_data(&self) -> Result<FortnoxInfoCacheData, AppError> {
        // 1. Try loading from cache
        if let Ok(Some(cached_data)) = self.load_info_cache() {
            // 2. Check if cache is stale
            match cached_data.info.is_stale(INFO_CACHE_DURATION_SECS) {
                Ok(false) => {
                    info!("Using valid info cache data.");
                    return Ok(cached_data);
                }
                Ok(true) => {
                    info!("Info cache is stale. Refetching data...");
                }
                Err(e) => {
                    error!("Error checking cache staleness: {}. Refetching data...", e);
                    // Proceed to refetch
                }
            }
        } else {
            info!("No valid info cache found. Fetching fresh data...");
            // Proceed to refetch
        }

        // 3. Fetch fresh data if cache is missing, stale, or load failed
        let client = self.get_api_client().await?;
        info!("Fetching fresh reference data from Fortnox API...");

        // Use try_join! for concurrent fetches
        let (employees_resp, customers_resp, projects_resp, articles_resp) = tokio::try_join!(
            client.fetch_employees(),
            client.fetch_customers(),
            client.fetch_projects_list(), // Use the list variant
            client.fetch_articles()
        )?;

        info!("Successfully fetched fresh reference data.");

        let fresh_data = FortnoxInfoCacheData {
            info: CachedInfo::new()?, // Create new timestamp info
            employees: employees_resp.employees,
            customers: customers_resp.customers,
            projects: projects_resp.projects,
            articles: articles_resp.articles,
        };

        // 4. Attempt to save the fresh data to cache
        if let Err(e) = self.save_info_cache(&fresh_data) {
            error!("Failed to save fresh data to info cache: {}", e);
            // Log the error, but proceed with returning the fresh data
        }

        Ok(fresh_data)
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
        .route("/auth", get(handle_fortnox_auth));
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

/// Handler to fetch and display cached or fresh Fortnox reference data
async fn handle_get_info(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    info!("Handling /api/fortnox/info request...");

    // Get data using the service method (handles caching internally)
    let data = state.fortnox_service.get_fortnox_reference_data().await?;

    // Format the data into an HTML string
    let mut html = String::new();
    let last_updated_dt = chrono::DateTime::<chrono::Utc>::from(
        UNIX_EPOCH + Duration::from_secs(data.info.last_updated_unix_secs),
    );

    html.push_str("<h1>Fortnox Reference Information</h1>");
    html.push_str(&format!(
        "<p><i>Data last updated: {} (UTC)</i></p>",
        last_updated_dt.to_rfc2822() // Or another format like ISO 8601
    ));

    // Display counts
    html.push_str("<h2>Summary</h2>");
    html.push_str("<ul>");
    html.push_str(&format!("<li>Employees: {}</li>", data.employees.len()));
    html.push_str(&format!("<li>Customers: {}</li>", data.customers.len()));
    html.push_str(&format!("<li>Projects: {}</li>", data.projects.len()));
    html.push_str(&format!(
        "<li>Articles/Services: {}</li>",
        data.articles.len()
    ));
    html.push_str("</ul>");

    // Display some details (e.g., first 5 of each)
    html.push_str("<h2>Details (Sample)</h2>");

    html.push_str("<h3>Employees (First 5)</h3>");
    html.push_str("<ul>");
    for item in data.employees.iter().take(5) {
        html.push_str(&format!(
            "<li>{} {} ({}) {}</li>",
            item.first_name.as_deref().unwrap_or("?"),
            item.last_name.as_deref().unwrap_or("?"),
            item.employee_id,
            item.email.as_deref().unwrap_or("-")
        ));
    }
    html.push_str("</ul>");

    html.push_str("<h3>Customers (First 5)</h3>");
    html.push_str("<ul>");
    for item in data.customers.iter().take(5) {
        html.push_str(&format!(
            "<li>{} ({}) {}</li>",
            item.name,
            item.customer_number,
            item.email.as_deref().unwrap_or("-")
        ));
    }
    html.push_str("</ul>");

    html.push_str("<h3>Projects (First 5)</h3>");
    html.push_str("<ul>");
    for item in data.projects.iter().take(5) {
        html.push_str(&format!(
            "<li>{} ({}) - Status: {}</li>",
            item.description,
            item.project_number,
            item.status.as_deref().unwrap_or("N/A")
        ));
    }
    html.push_str("</ul>");

    html.push_str("<h3>Articles/Services (First 5)</h3>");
    html.push_str("<ul>");
    for item in data.articles.iter().take(5) {
        html.push_str(&format!(
            "<li>{} ({}) - Price: {}, Active: {}</li>",
            item.description,
            item.article_number,
            item.sales_price.as_deref().unwrap_or("N/A"),
            item.active.map_or("N/A".to_string(), |b| b.to_string())
        ));
    }
    html.push_str("</ul>");

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
    // info!("Running example API call sequence using FortnoxService...");

    // // Get the API client (handles token refresh internally)
    // match state.fortnox_service.get_api_client().await {
    //     Ok(api_client) => {
    //         info!("Example Task: Successfully obtained Fortnox API client.");

    //         // Perform API calls using the obtained client
    //         match api_client.fetch_projects().await {
    //             Ok(projects) => {
    //                 info!(
    //                     "Example Task: Successfully fetched {} projects.",
    //                     projects.projects.len()
    //                 );
    //                 println!("\n--- Fetched Fortnox Project Names (Example Task) ---");
    //                 if projects.projects.is_empty() {
    //                     println!("No projects found.");
    //                 } else {
    //                     for project in projects.projects.iter().take(5) {
    //                         // Print first 5
    //                         println!(" - {} ({})", project.description, project.project_number);
    //                     }
    //                 }
    //                 println!("-----------------------------------------------------\n");
    //             }
    //             Err(e) => error!("Example Task: Failed to fetch projects: {}", e),
    //         }
    //         // ... Add other example API calls here using 'api_client' ...
    //     }
    //     Err(e) => {
    //         error!("Example Task: Failed to get Fortnox API client: {}", e);
    //         match e {
    //             // If it indicates re-auth is needed
    //             AppError::MissingOrInvalidToken => {
    //                 warn!("Example Task: Fortnox authorization required. Please visit {}/ to authorize.", "https://acounter.net/api/fortnox/auth");
    //             }
    //             _ => {
    //                 // Other errors might be temporary network issues etc.
    //             }
    //         }
    //     }
    // }
    // info!("Example API call sequence finished.");
}
