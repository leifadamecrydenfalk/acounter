// src/fortnox.rs

use reqwest::{Client, Method, RequestBuilder, StatusCode};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::log::{info, warn, error};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use url::Url;
use chrono::{DateTime, Utc};

// Constants
pub const FORTNOX_AUTH_URL: &str = "https://apps.fortnox.se/oauth-v1/auth";
pub const FORTNOX_TOKEN_URL: &str = "https://apps.fortnox.se/oauth-v1/token";
pub const FORTNOX_API_BASE_URL: &str = "https://api.fortnox.se/3";
pub const FORTNOX_TIME_API_URL: &str = "https://api.fortnox.se/api/time";
pub const DEFAULT_CACHE_DIR: &str = "./fortnox_cache";
pub const DEFAULT_TOKEN_FILE: &str = "fortnox_token.json";
pub const DEFAULT_CACHE_DURATION_SECS: u64 = 24 * 60 * 60; // 24 hours

// Error type for the Fortnox API client
#[derive(Error, Debug)]
pub enum FortnoxError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    
    #[error("JSON serialization/deserialization failed: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("URL parsing error: {0}")]
    UrlParseError(#[from] url::ParseError),
    
    #[error("OAuth state mismatch")]
    OAuthStateMismatch,
    
    #[error("Missing authorization code")]
    MissingAuthCode,
    
    #[error("Access token not available or refresh failed")]
    MissingToken,
    
    #[error("Token refresh failed")]
    TokenRefreshFailed,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Fortnox API error: Status={status}, Message={message}")]
    ApiError {
        status: StatusCode,
        message: String,
    },
    
    #[error("System time error: {0}")]
    TimeError(String),
    
    #[error("Lock acquisition failed")]
    LockError,
    
    #[error("Cache error: {0}")]
    CacheError(String),
}

// Configuration for the Fortnox client
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

// OAuth token response from Fortnox
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    token_type: String,
    scope: String,
}

// Structure for storing token data persistently
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredTokenData {
    access_token: String,
    refresh_token: String,
    expires_at_unix_secs: u64,
    scope: String,
    token_type: String,
}

impl StoredTokenData {
    fn is_expired(&self, buffer_secs: u64) -> Result<bool, FortnoxError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| FortnoxError::TimeError(e.to_string()))?
            .as_secs();
        Ok(now_unix >= self.expires_at_unix_secs.saturating_sub(buffer_secs))
    }
}

// Cache metadata for any cached data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
    last_updated_unix_secs: u64,
    resource_type: String,
    resource_id: Option<String>,
    query_params: Option<HashMap<String, String>>,
}

impl CacheMetadata {
    fn new(resource_type: String, resource_id: Option<String>, query_params: Option<HashMap<String, String>>) -> Result<Self, FortnoxError> {
        Ok(Self {
            last_updated_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| FortnoxError::TimeError(e.to_string()))?
                .as_secs(),
            resource_type,
            resource_id,
            query_params,
        })
    }

    fn is_stale(&self, max_age_secs: u64) -> Result<bool, FortnoxError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| FortnoxError::TimeError(e.to_string()))?
            .as_secs();
        let cache_age = now_unix.saturating_sub(self.last_updated_unix_secs);
        Ok(cache_age > max_age_secs)
    }
}

// Generic cache container for any data type
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedData<T> {
    metadata: CacheMetadata,
    data: T,
}

// Auth callback parameters for OAuth
#[derive(Debug, Deserialize)]
pub struct AuthCallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

// Fortnox API Client Implementation
#[derive(Clone)]
pub struct FortnoxClient {
    config: Arc<FortnoxConfig>,
    http_client: Client,
    token_data: Arc<Mutex<Option<StoredTokenData>>>,
    oauth_state: Arc<Mutex<Option<String>>>,
}

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
    pub hours: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ScheduleTimeResponse {
    #[serde(rename = "ScheduleTime")]
    pub schedule_time: ScheduleTime,
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
    pub first_name: Option<String>,
    #[serde(rename = "LastName")]
    pub last_name: Option<String>,
    #[serde(rename = "FullName")]
    pub full_name: Option<String>,
    pub email: Option<String>,
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

// Fortnox Error Response parsing
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

impl FortnoxClient {
    // Create a new FortnoxClient instance
    pub fn new(config: FortnoxConfig) -> Result<Self, FortnoxError> {
        // Create HTTP client
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        
        // Create cache directory if it doesn't exist
        if !config.cache_dir.exists() {
            fs::create_dir_all(&config.cache_dir)?;
        }
        
        // Load existing token if available
        let initial_token_data = Self::load_token_data(&config.token_file_path)?;
        
        Ok(Self {
            config: Arc::new(config),
            http_client,
            token_data: Arc::new(Mutex::new(initial_token_data)),
            oauth_state: Arc::new(Mutex::new(None)),
        })
    }
    
    // Load token data from file
    fn load_token_data(path: &Path) -> Result<Option<StoredTokenData>, FortnoxError> {
        if !path.exists() {
            return Ok(None);
        }
        
        let json_string = fs::read_to_string(path)?;
        let stored_data: StoredTokenData = serde_json::from_str(&json_string)?;
        
        Ok(Some(stored_data))
    }
    
    // Save token data to file
    fn save_token_data(&self, token_response: &TokenResponse) -> Result<StoredTokenData, FortnoxError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| FortnoxError::TimeError(e.to_string()))?
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
        
        let mut file = File::create(&self.config.token_file_path)?;
        file.write_all(json_string.as_bytes())?;
        
        Ok(stored_data)
    }
    
    // Update token state in memory and on disk
    async fn update_token_state(&self, token_response: &TokenResponse) -> Result<(), FortnoxError> {
        let new_stored_data = self.save_token_data(token_response)?;
        
        let mut token_guard = self.token_data.lock().await;
        *token_guard = Some(new_stored_data);
        
        Ok(())
    }
    
    // Generate an authorization URL for the OAuth flow
    pub async fn generate_auth_url(&self) -> Result<String, FortnoxError> {
        let random_state: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        
        let mut state_guard = self.oauth_state.lock().await;
        *state_guard = Some(random_state.clone());
        
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
    
    // Handle the OAuth callback
    pub async fn handle_auth_callback(&self, params: AuthCallbackParams) -> Result<(), FortnoxError> {
        // Check for errors from Fortnox
        if let Some(error) = params.error {
            let description = params.error_description.unwrap_or_default();
            return Err(FortnoxError::ApiError {
                status: StatusCode::UNAUTHORIZED,
                message: format!("OAuth error: {} ({})", error, description),
            });
        }
        
        // Verify OAuth state
        let mut state_guard = self.oauth_state.lock().await;
        let expected_state = state_guard.take();
        
        match (expected_state, params.state) {
            (Some(expected), Some(received)) if expected == received => {
                // State matches, proceed
            },
            _ => {
                return Err(FortnoxError::OAuthStateMismatch);
            }
        }
        
        // Get authorization code
        let code = params.code.ok_or(FortnoxError::MissingAuthCode)?;
        
        // Exchange code for tokens
        let token_response = self.exchange_code_for_token(&code).await?;
        
        // Save the token data
        self.update_token_state(&token_response).await?;
        
        Ok(())
    }
    
    // Exchange authorization code for tokens
    async fn exchange_code_for_token(&self, code: &str) -> Result<TokenResponse, FortnoxError> {
        let credentials = format!("{}:{}", self.config.client_id, self.config.client_secret);
        let encoded_credentials = BASE64_STANDARD.encode(credentials);
        let auth_header_value = format!("Basic {}", encoded_credentials);
        
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
        ];
        
        let response = self.http_client
            .post(FORTNOX_TOKEN_URL)
            .header(AUTHORIZATION, auth_header_value)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;
        
        if response.status().is_success() {
            let token_response = response.json::<TokenResponse>().await?;
            Ok(token_response)
        } else {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            
            Err(FortnoxError::ApiError {
                status,
                message: error_body,
            })
        }
    }
    
    // Refresh the access token
    async fn refresh_access_token(&self) -> Result<String, FortnoxError> {
        let token_guard = self.token_data.lock().await;
        let refresh_token = match &*token_guard {
            Some(data) => data.refresh_token.clone(),
            None => return Err(FortnoxError::MissingToken),
        };
        
        // Drop the guard before making the HTTP request
        drop(token_guard);
        
        let credentials = format!("{}:{}", self.config.client_id, self.config.client_secret);
        let encoded_credentials = BASE64_STANDARD.encode(credentials);
        let auth_header_value = format!("Basic {}", encoded_credentials);
        
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
        ];
        
        let response = self.http_client
            .post(FORTNOX_TOKEN_URL)
            .header(AUTHORIZATION, auth_header_value)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;
        
        if response.status().is_success() {
            let token_response = response.json::<TokenResponse>().await?;
            self.update_token_state(&token_response).await?;
            Ok(token_response.access_token)
        } else {
            // If refresh fails, clear token data
            let mut token_guard = self.token_data.lock().await;
            *token_guard = None;
            
            // Try to remove the token file
            if self.config.token_file_path.exists() {
                let _ = fs::remove_file(&self.config.token_file_path);
            }
            
            Err(FortnoxError::TokenRefreshFailed)
        }
    }
    
    // Get a valid access token, refreshing if necessary
    pub async fn get_valid_access_token(&self) -> Result<String, FortnoxError> {
        let token_guard = self.token_data.lock().await;
        
        let needs_refresh = match &*token_guard {
            Some(data) => data.is_expired(60)?,
            None => true,
        };
        
        let access_token = if !needs_refresh {
            let token = token_guard.as_ref().unwrap().access_token.clone();
            drop(token_guard);
            token
        } else {
            drop(token_guard);
            self.refresh_access_token().await?
        };
        
        Ok(access_token)
    }
    
    // Build a request with the appropriate headers and access token
    async fn build_request(&self, method: Method, endpoint: &str, base_url: Option<&str>) -> Result<RequestBuilder, FortnoxError> {
        let access_token = self.get_valid_access_token().await?;
        
        let base = base_url.unwrap_or(FORTNOX_API_BASE_URL);
        let url = if endpoint.starts_with('/') {
            format!("{}{}", base, endpoint)
        } else {
            format!("{}/{}", base, endpoint)
        };
        
        Ok(self.http_client
            .request(method, &url)
            .header(AUTHORIZATION, format!("Bearer {}", access_token))
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json"))
    }
    
    // Send a request and deserialize the response
    async fn send_and_deserialize<T: DeserializeOwned>(&self, request_builder: RequestBuilder) -> Result<T, FortnoxError> {
        let response = request_builder.send().await?;
        let status = response.status();
        
        if status.is_success() {
            Ok(response.json::<T>().await?)
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            Err(FortnoxError::RateLimitExceeded)
        } else {
            let error_body = response.text().await.unwrap_or_default();
            
            Err(FortnoxError::ApiError {
                status,
                message: error_body,
            })
        }
    }
    
    // Generic method to get data from an endpoint
    async fn get<T: DeserializeOwned + Serialize>(&self, endpoint: &str, base_url: Option<&str>) -> Result<T, FortnoxError> {
        let request = self.build_request(Method::GET, endpoint, base_url).await?;
        self.send_and_deserialize(request).await
    }
    
    // Generate a cache key for a resource
    fn generate_cache_key(&self, resource_type: &str, resource_id: Option<&str>, query_params: Option<&HashMap<String, String>>) -> String {
        let mut key = resource_type.to_string();
        
        if let Some(id) = resource_id {
            key.push_str("_");
            key.push_str(id);
        }
        
        if let Some(params) = query_params {
            if !params.is_empty() {
                let mut sorted_keys: Vec<_> = params.keys().collect();
                sorted_keys.sort();
                
                for k in sorted_keys {
                    if let Some(v) = params.get(k) {
                        key.push_str("_");
                        key.push_str(k);
                        key.push_str("-");
                        key.push_str(v);
                    }
                }
            }
        }
        
        key
    }
    
    // Get the path to a cache file
    fn get_cache_file_path(&self, cache_key: &str) -> PathBuf {
        self.config.cache_dir.join(format!("{}.json", cache_key))
    }
    
    // Save data to cache
    fn save_to_cache<T: Serialize>(&self, 
                                  resource_type: &str, 
                                  resource_id: Option<&str>,
                                  query_params: Option<&HashMap<String, String>>,
                                  data: &T) -> Result<(), FortnoxError> {
        let cache_key = self.generate_cache_key(resource_type, resource_id, query_params);
        let cache_path = self.get_cache_file_path(&cache_key);
        
        // Create parent directories if they don't exist
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let metadata = CacheMetadata::new(
            resource_type.to_string(),
            resource_id.map(|s| s.to_string()),
            query_params.cloned(),
        )?;
        
        let cached_data = CachedData {
            metadata,
            data,
        };
        
        let json_string = serde_json::to_string_pretty(&cached_data)?;
        let mut file = File::create(cache_path)?;
        file.write_all(json_string.as_bytes())?;
        
        Ok(())
    }
    
    // Load data from cache
    fn load_from_cache<T: DeserializeOwned>(&self,
                                          resource_type: &str,
                                          resource_id: Option<&str>,
                                          query_params: Option<&HashMap<String, String>>) -> Result<Option<T>, FortnoxError> {
        let cache_key = self.generate_cache_key(resource_type, resource_id, query_params);
        let cache_path = self.get_cache_file_path(&cache_key);
        
        if !cache_path.exists() {
            return Ok(None);
        }
        
        let json_string = fs::read_to_string(cache_path)?;
        let cached_data: CachedData<T> = serde_json::from_str(&json_string)?;
        
        if cached_data.metadata.is_stale(self.config.cache_duration_secs)? {
            return Ok(None);
        }
        
        Ok(Some(cached_data.data))
    }
    
    // Generic method to get data with caching
    async fn get_with_cache<T: DeserializeOwned + Serialize>(&self, 
                                                           endpoint: &str,
                                                           resource_type: &str,
                                                           resource_id: Option<&str>,
                                                           query_params: Option<&HashMap<String, String>>,
                                                           base_url: Option<&str>) -> Result<T, FortnoxError> {
        // Try to load from cache first
        if let Some(cached_data) = self.load_from_cache(resource_type, resource_id, query_params)? {
            return Ok(cached_data);
        }
        
        // If not in cache or stale, fetch from API
        let request_builder = self.build_request(Method::GET, endpoint, base_url).await?;
        
        // Add query parameters if provided
        let request_builder = if let Some(params) = query_params {
            request_builder.query(params)
        } else {
            request_builder
        };
        
        let response_data: T = self.send_and_deserialize(request_builder).await?;
        
        // Save to cache
        self.save_to_cache(resource_type, resource_id, query_params, &response_data)?;
        
        Ok(response_data)
    }
    
    // --- API Methods ---
    
    // Get time registrations
    pub async fn get_time_registrations(&self, 
                                      from_date: &str, 
                                      to_date: &str,
                                      user_ids: Option<Vec<String>>,
                                      customer_ids: Option<Vec<String>>,
                                      project_ids: Option<Vec<String>>) -> Result<Vec<DetailedRegistration>, FortnoxError> {
        let mut params = HashMap::new();
        params.insert("fromDate".to_string(), from_date.to_string());
        params.insert("toDate".to_string(), to_date.to_string());
        
        if let Some(user_ids) = user_ids {
            for id in user_ids {
                params.insert(format!("userIds={}", id), String::new());
            }
        }
        
        if let Some(customer_ids) = customer_ids {
            for id in customer_ids {
                params.insert(format!("customerIds={}", id), String::new());
            }
        }
        
        if let Some(project_ids) = project_ids {
            for id in project_ids {
                params.insert(format!("projectIds={}", id), String::new());
            }
        }
        
        let endpoint = "/api/time/registrations-v2";
        self.get_with_cache(
            endpoint,
            "time_registrations",
            None,
            Some(&params),
            Some(FORTNOX_TIME_API_URL)
        ).await
    }
    
    // Get schedule time for employee on date
    pub async fn get_schedule_time(&self, employee_id: &str, date: &str) -> Result<ScheduleTimeResponse, FortnoxError> {
        let endpoint = format!("/scheduletimes/{}/{}", employee_id, date);
        self.get_with_cache(
            &endpoint,
            "schedule_time",
            Some(employee_id),
            Some(&HashMap::from([("date".to_string(), date.to_string())])),
            None
        ).await
    }
    
    // Get all employees
    pub async fn get_employees(&self) -> Result<EmployeeListResponse, FortnoxError> {
        self.get_with_cache(
            "/employees",
            "employees",
            None,
            None,
            None
        ).await
    }
    
    // Get employee by ID
    pub async fn get_employee(&self, employee_id: &str) -> Result<EmployeeListItem, FortnoxError> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct SingleEmployeeResponse {
            #[serde(rename = "Employee")]
            employee: EmployeeListItem,
        }
        
        let endpoint = format!("/employees/{}", employee_id);
        let response: SingleEmployeeResponse = self.get_with_cache(
            &endpoint,
            "employee",
            Some(employee_id),
            None,
            None
        ).await?;
        
        Ok(response.employee)
    }
    
    // Get all customers
    pub async fn get_customers(&self) -> Result<CustomerListResponse, FortnoxError> {
        self.get_with_cache(
            "/customers",
            "customers",
            None,
            None,
            None
        ).await
    }
    
    // Get customer by ID
    pub async fn get_customer(&self, customer_id: &str) -> Result<CustomerListItem, FortnoxError> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct SingleCustomerResponse {
            #[serde(rename = "Customer")]
            customer: CustomerListItem,
        }
        
        let endpoint = format!("/customers/{}", customer_id);
        let response: SingleCustomerResponse = self.get_with_cache(
            &endpoint,
            "customer",
            Some(customer_id),
            None,
            None
        ).await?;
        
        Ok(response.customer)
    }
    
    // Get all projects
    pub async fn get_projects(&self) -> Result<ProjectListResponse, FortnoxError> {
        self.get_with_cache(
            "/projects",
            "projects",
            None,
            None,
            None
        ).await
    }
    
    // Get project by ID
    pub async fn get_project(&self, project_id: &str) -> Result<ProjectListItem, FortnoxError> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct SingleProjectResponse {
            #[serde(rename = "Project")]
            project: ProjectListItem,
        }
        
        let endpoint = format!("/projects/{}", project_id);
        let response: SingleProjectResponse = self.get_with_cache(
            &endpoint,
            "project",
            Some(project_id),
            None,
            None
        ).await?;
        
        Ok(response.project)
    }
    
    // Get all articles
    pub async fn get_articles(&self) -> Result<ArticleListResponse, FortnoxError> {
        self.get_with_cache(
            "/articles",
            "articles",
            None,
            None,
            None
        ).await
    }
    
    // Get article by ID
    pub async fn get_article(&self, article_id: &str) -> Result<ArticleListItem, FortnoxError> {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct SingleArticleResponse {
            #[serde(rename = "Article")]
            article: ArticleListItem,
        }
        
        let endpoint = format!("/articles/{}", article_id);
        let response: SingleArticleResponse = self.get_with_cache(
            &endpoint,
            "article",
            Some(article_id),
            None,
            None
        ).await?;
        
        Ok(response.article)
    }
    
    // Clear cache for a specific resource
    pub fn clear_cache(&self, resource_type: &str, resource_id: Option<&str>) -> Result<(), FortnoxError> {
        let pattern = if let Some(id) = resource_id {
            format!("{}_{}*.json", resource_type, id)
        } else {
            format!("{}*.json", resource_type)
        };
        
        let cache_dir = &self.config.cache_dir;
        
        for entry in fs::read_dir(cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if let Some(file_name) = path.file_name() {
                if let Some(file_name_str) = file_name.to_str() {
                    // Simple pattern matching for the cache files
                    if file_name_str.starts_with(&pattern.replace("*.json", "")) {
                        fs::remove_file(&path)?;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    // Clear all cache
    pub fn clear_all_cache(&self) -> Result<(), FortnoxError> {
        let cache_dir = &self.config.cache_dir;
        
        if cache_dir.exists() {
            for entry in fs::read_dir(cache_dir)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_file() {
                    fs::remove_file(&path)?;
                }
            }
        }
        
        Ok(())
    }
    
    // Get token status
    pub async fn get_token_status(&self) -> Result<TokenStatus, FortnoxError> {
        let token_guard = self.token_data.lock().await;
        
        match &*token_guard {
            Some(data) => {
                let is_expired = data.is_expired(60)?;
                let now = SystemTime::now();
                let expires_at = UNIX_EPOCH + Duration::from_secs(data.expires_at_unix_secs);
                
                let expires_in_secs = if is_expired {
                    0
                } else {
                    expires_at
                        .duration_since(now)
                        .unwrap_or_default()
                        .as_secs()
                };
                
                let expires_at_datetime = DateTime::<Utc>::from(expires_at);
                
                Ok(TokenStatus {
                    has_token: true,
                    is_valid: !is_expired,
                    expires_in_secs,
                    expires_at: expires_at_datetime.to_rfc3339(),
                })
            },
            None => Ok(TokenStatus {
                has_token: false,
                is_valid: false,
                expires_in_secs: 0,
                expires_at: "".to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatus {
    pub has_token: bool,
    pub is_valid: bool,
    pub expires_in_secs: u64,
    pub expires_at: String,
}
