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
    fs::{self, File}, // Added File
    io::{BufReader, Write}, // Added BufReader, Write
    net::SocketAddr,
    path::{Path, PathBuf}, // Added PathBuf, Path
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH}, // Added time components
 };
 use axum::http::StatusCode as AxumStatusCode;
 use thiserror::Error;
 use tokio::sync::Mutex;
 use tokio::time::sleep; // For example task delay
 use tracing::{error, info, warn, Level}; // Added warn
 use tracing_subscriber::FmtSubscriber;
 use url::Url;

 // --- Added for HTTPS ---
 use axum_server::tls_rustls::RustlsConfig;
 use rustls_pemfile::{certs, pkcs8_private_keys};
 // --- /Added for HTTPS ---


 // --- Configuration & Constants ---

 const FORTNOX_AUTH_URL: &str = "https://apps.fortnox.se/oauth-v1/auth";
 const FORTNOX_TOKEN_URL: &str = "https://apps.fortnox.se/oauth-v1/token";
 const FORTNOX_API_BASE_URL: &str = "https://api.fortnox.se/3";
 const FORTNOX_SCOPES: &str = "project companyinformation"; // Add needed scopes

 // --- !! SECURITY WARNING !! ---
 // Storing tokens in a plain text file is NOT recommended for production.
 // Use environment variables, a secure vault, database with encryption,
 // or OS-level secure storage. Ensure file permissions are restrictive.
 const TOKEN_FILE: &str = "fortnox_token.json";
 // --- !! SECURITY WARNING !! ---

 // --- Error Handling ---

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
                // Redirect to root might be better? Or show error page?
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
        };

        // Return HTML error page
        (status_code, Html(format!("<h1>Error</h1><p>{}</p>", error_message))).into_response()
    }
 }

 // --- Data Structures ---

 #[derive(Debug, Serialize, Deserialize, Clone)]
 struct Config {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    // --- Added for HTTPS ---
    cert_path: String,
    key_path: String,
    // --- /Added for HTTPS ---
 }

 // Raw response from Fortnox token endpoint
 #[derive(Debug, Clone, Serialize, Deserialize)]
 struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    token_type: String,
    scope: String,
 }

 // Structure for storing token data persistently
 #[derive(Serialize, Deserialize, Debug, Clone)]
 struct StoredTokenData {
    access_token: String,
    refresh_token: String,
    // Store the absolute expiry time (Unix timestamp in seconds)
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
        // Check if 'now' is later than or equal to expiry time minus buffer
        Ok(now_unix >= self.expires_at_unix_secs.saturating_sub(buffer_secs))
    }
 }


 #[derive(Clone)]
 struct AppState {
    config: Arc<Config>,
    http_client: Client,
    oauth_state: Arc<Mutex<Option<String>>>,
    // Store the persistent token info
    token_data: Arc<Mutex<Option<StoredTokenData>>>,
 }

 #[derive(Deserialize, Debug)]
 struct AuthCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
 }

 // --- Fortnox API Response Structures ---
 // (Project structures - unchanged)
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
    // NOTE: Fortnox response might actually use "Projects" here
    projects: Vec<Project>,
    #[serde(rename = "@TotalResources")]
    total_resources: Option<i32>,
    #[serde(rename = "@TotalPages")]
    total_pages: Option<i32>,
    #[serde(rename = "@CurrentPage")]
    current_page: Option<i32>,
 }
 // Add other response structures (TimeEntry, Absence, etc.) as needed


 // --- Fortnox API Client ---
 #[derive(Clone)]
 struct FortnoxApiClient {
    http_client: Client,
    config: Arc<Config>,
    access_token: String, // Holds the *valid* access token for requests
    base_url: String,
 }

 impl FortnoxApiClient {
    /// Creates a new Fortnox API client instance. Requires a VALID access token.
    pub fn new(
        http_client: Client,
        config: Arc<Config>,
        access_token: String,
        base_url: &str,
    ) -> Self {
        FortnoxApiClient {
            http_client,
            config,
            access_token,
            base_url: base_url.to_string(),
        }
    }

    fn build_request(&self, method: Method, endpoint: &str) -> RequestBuilder {
        let url = format!("{}{}", self.base_url, endpoint);
        // info!("Building Fortnox API Request: {} {}", method, url); // Can be verbose
        self.http_client
            .request(method, url)
            .header(AUTHORIZATION, format!("Bearer {}", self.access_token))
            .header("Client-Secret", self.config.client_secret.clone())
            .header("Access-Token", self.access_token.clone())
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
            response.json::<T>().await.map_err(AppError::from)
        } else {
            let error_text = response.text().await.ok();
            error!(
                "Fortnox API request failed. Status: {}, Body: {:?}",
                status, error_text
            );
            Err(AppError::FortnoxApiError { status, message: error_text })
        }
    }

    pub async fn get<T: DeserializeOwned>(&self, endpoint: &str) -> Result<T, AppError> {
        let request = self.build_request(Method::GET, endpoint);
        self.send_and_deserialize(request).await
    }

    // Add post, put, delete methods similarly

    // --- Specific API Call Methods ---
    pub async fn fetch_projects(&self) -> Result<ProjectResponse, AppError> {
        info!("Fetching projects via API client...");
        self.get::<ProjectResponse>("/projects").await
    }
    // Add other methods (fetch_time_entries, etc.)
 }


 // --- Token Storage Functions ---

 fn save_token_data(token_response: &TokenResponse) -> Result<StoredTokenData, AppError> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AppError::SystemTimeError(e.to_string()))?
        .as_secs();
    // Calculate absolute expiry time
    let expires_at = now_unix + token_response.expires_in;

    let stored_data = StoredTokenData {
        access_token: token_response.access_token.clone(),
        refresh_token: token_response.refresh_token.clone(),
        expires_at_unix_secs: expires_at,
        scope: token_response.scope.clone(),
        token_type: token_response.token_type.clone(),
    };
    let json_string = serde_json::to_string_pretty(&stored_data)?;

    // --- SECURITY ---
    // Consider using libraries like `directories` to find appropriate config paths.
    // Encrypt the file content using a library like `magic-crypt` or `aes-gcm`.
    // Ensure file permissions are restrictive (e.g., 600 on Unix).
    // --- /SECURITY ---
    let mut file = File::create(TOKEN_FILE)?; // Overwrites existing file
    file.write_all(json_string.as_bytes())?;
    info!("Token data saved to {}", TOKEN_FILE);
    Ok(stored_data) // Return the data that was saved
 }

 fn load_token_data() -> Result<Option<StoredTokenData>, AppError> {
    if !Path::new(TOKEN_FILE).exists() {
        info!("Token file {} not found.", TOKEN_FILE);
        return Ok(None);
    }
    // --- SECURITY ---
    // If file is encrypted, decrypt here.
    // --- /SECURITY ---
    let json_string = fs::read_to_string(TOKEN_FILE)?;
    let stored_data: StoredTokenData = serde_json::from_str(&json_string)?;
    info!("Token data loaded from {}", TOKEN_FILE);
    Ok(Some(stored_data))
 }


 // --- Token Refresh Logic ---

 /// Attempts to refresh the access token using the stored refresh token.
 /// Updates the stored token file and the in-memory AppState on success.
 async fn refresh_access_token(state: &AppState) -> Result<StoredTokenData, AppError> {
    info!("Attempting to refresh access token...");
    let stored_token_opt = state.token_data.lock().await.clone();

    let refresh_token = match stored_token_opt {
        Some(ref data) => data.refresh_token.clone(),
        None => {
            error!("Cannot refresh: No token data found in state.");
            // If there's no token, user needs to authorize initially
            return Err(AppError::MissingOrInvalidToken);
        }
    };

    // Prepare credentials for Basic Auth
    let credentials = format!("{}:{}", state.config.client_id, state.config.client_secret);
    let encoded_credentials = BASE64_STANDARD.encode(credentials);
    let auth_header_value = format!("Basic {}", encoded_credentials);

    // Prepare form data
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
    ];

    // Make the request
    let response = state.http_client
        .post(FORTNOX_TOKEN_URL)
        .header(AUTHORIZATION, auth_header_value)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await?;

    if response.status().is_success() {
        let token_response: TokenResponse = response.json().await?;
        info!("Successfully refreshed access token.");

        // --- Save the newly refreshed data persistently ---
        let new_stored_data = match save_token_data(&token_response) {
            Ok(data) => data,
            Err(e) => {
                error!("CRITICAL: Failed to save refreshed token data: {}", e);
                // If saving fails, we have a problem. Return error, don't update state.
                return Err(e);
            }
        };

        // Update in-memory state as well
        *state.token_data.lock().await = Some(new_stored_data.clone());

        Ok(new_stored_data) // Return the new data
    } else {
        let status = response.status();
        let error_text = response.text().await.ok();
        error!(
            "Failed to refresh token. Status: {}, Body: {:?}",
            status, error_text
        );
        // Critical failure - maybe the refresh token was revoked?
        warn!("Clearing stored token data due to refresh failure.");
        *state.token_data.lock().await = None;
        // Attempt to remove the invalid token file
        match fs::remove_file(TOKEN_FILE) {
            Ok(_) => info!("Removed potentially invalid token file: {}", TOKEN_FILE),
            Err(e) => error!("Failed to remove token file {}: {}", TOKEN_FILE, e),
        }
        // Return specific error indicating refresh failed / re-auth needed
        Err(AppError::MissingOrInvalidToken)
    }
 }

 /// Ensures a valid access token is available, refreshing if necessary.
 /// Returns a valid access token string.
 async fn ensure_valid_token(state: &AppState) -> Result<String, AppError> {
    let mut token_data_guard = state.token_data.lock().await; // Lock mutex

    let needs_refresh = match *token_data_guard {
        Some(ref data) => data.is_expired(60)?, // Check if expired (60s buffer)
        None => true, // No token means we need one (implies refresh or initial auth)
    };

    if needs_refresh {
        info!("Token is invalid, missing, or nearing expiry. Attempting refresh...");
        // Drop the lock *before* calling refresh_access_token to avoid deadlock
        // because refresh_access_token also needs to lock the Mutex to update the state.
        drop(token_data_guard);

        match refresh_access_token(state).await {
            Ok(new_data) => {
                info!("Token refresh successful.");
                Ok(new_data.access_token) // Return the new access token
            }
            Err(e) => {
                error!("Token refresh failed: {}", e);
                Err(e) // Propagate the error (likely MissingOrInvalidToken)
            }
        }
    } else {
        // Token is valid, we can safely unwrap and clone the access token.
        // The lock is still held here.
        info!("Current token is valid.");
        Ok(token_data_guard.as_ref().unwrap().access_token.clone())
    }
    // Lock is automatically dropped when token_data_guard goes out of scope
 }


 // --- Main Application Logic ---

 #[tokio::main]
 async fn main() -> Result<(), AppError> {
    // --- Setup ---
    dotenv::dotenv().ok(); // Load .env file if present
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO) // Adjust log level (e.g., Level::DEBUG for more detail)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    // --- Load Configuration ---
    let config = Arc::new(Config {
        client_id: env::var("FORTNOX_CLIENT_ID")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_CLIENT_ID".into()))?,
        client_secret: env::var("FORTNOX_CLIENT_SECRET")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_CLIENT_SECRET".into()))?,
        redirect_uri: env::var("FORTNOX_REDIRECT_URI")
            .map_err(|_| AppError::MissingEnvVar("FORTNOX_REDIRECT_URI".into()))?,
        // --- Added for HTTPS ---
        // Expect environment variables for cert/key paths
        cert_path: env::var("CERT_PATH")
            .map_err(|_| AppError::MissingEnvVar("CERT_PATH".into()))?,
        key_path: env::var("KEY_PATH")
            .map_err(|_| AppError::MissingEnvVar("KEY_PATH".into()))?,
        // --- /Added for HTTPS ---
    });
    info!("Configuration loaded.");

    // --- Load Stored Token ---
    let initial_token_data = match load_token_data() {
        Ok(Some(data)) => {
            // Check expiry immediately, but store it anyway for refresh token access
             match data.is_expired(300) { // Check if expired now or within 5 mins
                  Ok(true) => {
                    info!("Loaded token is expired or nearing expiry. Will need refresh on first use.");
                    Some(data)
                  },
                  Ok(false) => {
                    info!("Loaded valid token from storage.");
                    Some(data)
                  },
                  Err(e) => {
                      error!("Failed to check expiry of loaded token: {}. Assuming expired.", e);
                      Some(data) // Keep data for refresh token
                  }
             }
        }
        Ok(None) => {
            info!("No stored token data found. Need initial authorization via /");
            None
        }
        Err(e) => {
            error!("Failed to load token data: {}. Assuming no token.", e);
            None // Treat loading error as needing new auth
        }
    };


    // --- Create Shared State ---
    let state = AppState {
        config: config.clone(), // Clone config Arc for state
        http_client: Client::builder()
            // Configure client timeouts, proxies etc. if needed
            .timeout(Duration::from_secs(30))
            .build()?,
        oauth_state: Arc::new(Mutex::new(None)),
        token_data: Arc::new(Mutex::new(initial_token_data)), // Initialize from loaded data
    };
    info!("Application state initialized.");


    // --- Setup Web Server ---
    let app = Router::new()
        .route("/", get(handle_root))
        .route("/fortnox/callback", get(handle_callback))
        .route("/status", get(handle_status))
        // Add other routes for specific actions if desired
        .with_state(state.clone()); // Clone state for the web server

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000)); // Keep port 3000 or change as needed
    info!("Attempting to bind server on https://{}", addr);

    // --- Configure TLS ---
    let tls_config = match RustlsConfig::from_pem_file(
        PathBuf::from(&config.cert_path), // Use PathBuf from config
        PathBuf::from(&config.key_path),  // Use PathBuf from config
    )
    .await // Needs to be awaited
    {
        Ok(config) => config,
        Err(e) => {
            let err_msg = format!("Failed to load TLS cert/key: {}", e);
            error!("{}", err_msg); // Log the specific error
            return Err(AppError::TlsConfig(err_msg)); // Return a specific TLS config error
        }
    };
    info!("TLS configuration loaded successfully from {} and {}", config.cert_path, config.key_path);


    // --- Example Background Task Spawn (Optional) ---
    // Spawn a task that periodically tries to use the API
    let task_state = state.clone(); // Clone state for the background task
    tokio::spawn(async move {
        info!("Example background task started.");
        // Wait a bit for the server to potentially become ready
        sleep(Duration::from_secs(10)).await;
        run_example_api_call(task_state).await;

        // In a real scenario, this might loop with a sleep
        // loop {
        //    sleep(Duration::from_secs(3600)).await; // e.g., run hourly
        //    run_example_api_call(task_state.clone()).await;
        // }
    });


    // --- Run Web Server with TLS ---
    info!("Starting server on https://{}", addr);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?; // Use axum_server::bind_rustls

    Ok(())
 }

 // --- Web Handlers ---

 // Handler for the root path: Initiates the OAuth flow
 async fn handle_root(State(state): State<AppState>) -> Result<Redirect, AppError> {
    info!("Handling / request, initiating OAuth flow...");
    let random_state: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store the state *before* redirecting
    *state.oauth_state.lock().await = Some(random_state.clone());
    info!("Generated OAuth state: {}", random_state);

    // --- IMPORTANT ---
    // Ensure FORTNOX_REDIRECT_URI in your .env starts with https://
    // --- IMPORTANT ---
    let mut auth_url = Url::parse(FORTNOX_AUTH_URL)?;
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", &state.config.client_id)
        .append_pair("redirect_uri", &state.config.redirect_uri)
        .append_pair("scope", FORTNOX_SCOPES)
        .append_pair("state", &random_state)
        .append_pair("access_type", "offline") // Request refresh token
        .append_pair("response_type", "code");

    info!("Redirecting user to Fortnox: {}", auth_url);
    Ok(Redirect::temporary(auth_url.as_str()))
 }

 // Handler for the OAuth callback URL ("/fortnox/callback")
 async fn handle_callback(
    State(state): State<AppState>,
    Query(params): Query<AuthCallbackParams>,
 ) -> Result<Html<String>, AppError> {
    info!("Handling /fortnox/callback request with params: {:?}", params);

    // 1. Check for OAuth errors from Fortnox
    if let Some(error) = params.error {
        let description = params.error_description.unwrap_or_default();
        error!(
            "OAuth failed on Fortnox side. Error: '{}', Description: '{}'",
            error, description
        );
        return Ok(Html(format!(
            "<h1>OAuth Error</h1><p>Fortnox returned an error: {} ({})</p><p>Please try <a href='/'>authenticating again</a>.</p>",
            error, description
        )));
    }

    // 2. Verify OAuth state (CSRF protection)
    let expected_state_opt = state.oauth_state.lock().await.take(); // take() removes it after check
    let received_state = params.state.clone();
    match (expected_state_opt.clone(), received_state) {
        (Some(expected), Some(received)) if expected == received => {
             info!("OAuth state verified successfully.");
        }
        _ => {
             error!(
                 "OAuth state mismatch. Expected: {:?}, Received: {:?}",
                 expected_state_opt, params.state // Log potentially sensitive state? Reconsider in prod.
             );
             *state.token_data.lock().await = None; // Clear any potentially stored token on mismatch
             return Err(AppError::OAuthStateMismatch);
        }
    }

    // 3. Get authorization code
    let code = params.code.ok_or(AppError::MissingAuthCode)?;
    info!("Received authorization code.");

    // 4. Exchange code for tokens
    let token_response = exchange_code_for_token(&state.http_client, &state.config, &code).await?;
    info!(
        "Successfully obtained initial tokens. Access token expires in {} seconds.",
        token_response.expires_in
    );

    // 5. Save the received token data persistently and update in-memory state
    match save_token_data(&token_response) {
        Ok(new_stored_data) => {
            *state.token_data.lock().await = Some(new_stored_data); // Update in-memory state
            info!("Initial token data saved and state updated.");
        },
        Err(e) => {
            error!("CRITICAL: Failed to save initial token data: {}", e);
             // Update state anyway so refresh token might be available? Or return error?
             // Let's update state but warn heavily.
             warn!("Proceeding with in-memory token despite save failure.");
             let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|se|AppError::SystemTimeError(se.to_string()))?.as_secs();
             let expires_at = now_unix + token_response.expires_in;
             let temp_stored_data = StoredTokenData {
                 access_token: token_response.access_token.clone(),
                 refresh_token: token_response.refresh_token.clone(),
                 expires_at_unix_secs: expires_at,
                 scope: token_response.scope.clone(),
                 token_type: token_response.token_type.clone(),
             };
             *state.token_data.lock().await = Some(temp_stored_data);
             // Perhaps return a specific error page indicating partial success?
             // For now, let it proceed but the token won't persist across restarts.
        }
    }


    // 6. Optionally, make an immediate API call to verify
    info!("Attempting an immediate API call with the new token...");
    match ensure_valid_token(&state).await {
         Ok(access_token) => {
             let api_client = FortnoxApiClient::new(
                 state.http_client.clone(),
                 state.config.clone(),
                 access_token,
                 FORTNOX_API_BASE_URL,
             );
             match api_client.fetch_projects().await {
                 Ok(project_response) => {
                     info!("Successfully fetched {} projects immediately after auth.", project_response.projects.len());
                     println!("\n--- Fetched Fortnox Project Names (Post-Callback) ---");
                     if project_response.projects.is_empty() {
                         println!("No projects found.");
                     } else {
                         for project in &project_response.projects {
                             println!(" - {} ({})", project.description, project.project_number);
                         }
                     }
                     println!("-----------------------------------------------------\n");
                     Ok(Html(format!(
                         "<h1>Success!</h1><p>Authentication successful. Fetched {} projects.</p><p>Token data saved. Server is now authorized.</p><p>Check console for project names.</p><p>You can close this window.</p>",
                         project_response.projects.len()
                     )))
                 }
                 Err(e) => {
                      error!("Callback: API call failed even after getting token: {}", e);
                      // Return error, token might be invalid immediately? Rare.
                      Err(e)
                 }
             }
         }
         Err(e) => {
              error!("Callback: Failed to ensure valid token immediately after exchange: {}", e);
              // This shouldn't happen unless refresh failed immediately or state is inconsistent
              Err(e)
         }
    }

 }

 // Example status handler
 async fn handle_status(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    info!("Handling /status request");
    let token_lock = state.token_data.lock().await;
    let status_message = match &*token_lock {
        Some(token) => {
            match token.is_expired(60) {
                 Ok(true) => format!("Token present but expired or needs refresh soon (Refresh Token: ...{}).",
                                      &token.refresh_token.chars().take(8).collect::<String>()), // Show partial refresh token for debugging
                 Ok(false) => format!("Token present and valid until approx Unix timestamp {}. (Access Token: ...{})",
                                       token.expires_at_unix_secs,
                                       &token.access_token.chars().take(8).collect::<String>()), // Show partial access token
                 Err(e) => format!("Token present but failed to check expiry: {}", e),
            }
        }
        None => "No token present in memory. Needs authorization via /".to_string(),
    };
    let html_body = format!(
        "<h1>Server Status</h1><p>Current Time (Server): {}</p><p>Token Status: {}</p><p><a href='/'>Re-authorize</a></p>",
        chrono::Local::now().to_rfc3339(), // Use chrono for readable time
        status_message
    );
    // Make sure to add chrono to Cargo.toml: chrono = { version = "0.4", features = ["serde"] }
    Ok(Html(html_body))
 }


 // --- Helper Functions ---

 // Exchanges the authorization code for tokens (initial exchange)
 async fn exchange_code_for_token(
    client: &Client,
    config: &Config,
    code: &str,
 ) -> Result<TokenResponse, AppError> {
    info!("Exchanging authorization code for tokens...");
    let credentials = format!("{}:{}", config.client_id, config.client_secret);
    let encoded_credentials = BASE64_STANDARD.encode(credentials);
    let auth_header_value = format!("Basic {}", encoded_credentials);

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", &config.redirect_uri), // Ensure this matches the HTTPS URI
    ];

    let response = client
        .post(FORTNOX_TOKEN_URL)
        .header(AUTHORIZATION, auth_header_value)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await?;

    if response.status().is_success() {
        // Deserialize into the raw TokenResponse first
        response.json::<TokenResponse>().await.map_err(AppError::from)
    } else {
        let status = response.status();
        let error_text = response.text().await.ok();
        error!(
            "Failed to exchange code for token. Status: {}, Body: {:?}",
            status, error_text
        );
        Err(AppError::FortnoxApiError { status, message: error_text })
    }
 }

 // --- Example Background Task Logic ---
 async fn run_example_api_call(state: AppState) {
    info!("Running example API call sequence...");

    match ensure_valid_token(&state).await {
        Ok(access_token) => {
            info!("Successfully ensured valid token for example task.");
            let api_client = FortnoxApiClient::new(
                state.http_client.clone(),
                state.config.clone(),
                access_token, // Use the ensured valid token
                FORTNOX_API_BASE_URL,
            );

            // Perform API calls
            match api_client.fetch_projects().await {
                Ok(projects) => {
                    info!("Example Task: Successfully fetched {} projects.", projects.projects.len());
                    println!("\n--- Fetched Fortnox Project Names (Example Task) ---");
                    if projects.projects.is_empty() {
                        println!("No projects found.");
                    } else {
                        for project in projects.projects.iter().take(5) { // Print first 5
                            println!(" - {} ({})", project.description, project.project_number);
                        }
                    }
                    println!("-----------------------------------------------------\n");
                }
                Err(e) => error!("Example Task: Failed to fetch projects: {}", e),
            }
            // ... Add other example API calls here ...
        }
        Err(e) => {
            error!("Example Task: Failed to get valid token: {}. Cannot perform API calls.", e);
            match e {
                // If it's the specific error indicating re-auth is needed
                AppError::MissingOrInvalidToken => {
                    // Use the configured redirect URI host/port for the message
                    let server_base = state.config.redirect_uri.split("/fortnox/callback").next().unwrap_or("https://localhost:3000");
                    warn!("Example Task: Authorization required. Please visit {}/ to authorize.", server_base);
                }
                _ => {
                    // Other errors might be temporary network issues etc.
                }
            }
        }
    }
    info!("Example API call sequence finished.");
 }
