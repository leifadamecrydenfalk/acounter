// src/main.rs
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use governor::{
    clock::DefaultClock,
    state::keyed::DashMapStateStore, 
    Quota, RateLimiter,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::num::NonZeroU32;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting API server");

    // Create application state with config
    let state = AppState {
        limiter: Arc::new(RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(config.rate_limit_requests).unwrap_or_else(|| NonZeroU32::new(1).unwrap())
        ))),
        http_client: Client::new(),
        config: Arc::new(config),
    };

    let config_clone = state.config.clone();

    // Build our application with routes
    let app = Router::new()
        // Public endpoints
        .route("/", get(|| async { "Hello, World!" }))
        .route("/health", get(health_check))
        .route("/auth/google", get(google_auth_redirect))
        .route("/auth/google/callback", get(google_auth_callback))
        
        // Protected API endpoints
        .route("/api/me", get(get_user_profile))
        .route("/api/data", get(get_protected_data))
        
        // Apply middleware with state for both
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        
        // Add state
        .with_state(state);

    // Run the server
    let addr = format!("{}:{}", config_clone.server_host, config_clone.server_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

// Application state with config
#[derive(Clone)]
struct AppState {
    limiter: Arc<RateLimiter<String, DashMapStateStore<String>, DefaultClock>>,
    http_client: Client,
    config: Arc<Config>,
}

// JWT claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,   // Subject (user ID)
    email: String, // User email
    exp: i64,      // Expiration time
}

// Google OAuth callback parameters
#[derive(Deserialize)]
struct GoogleCallback {
    code: String,
}

// Google OAuth token response
#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    id_token: Option<String>,
    expires_in: u64,
}

// Google userinfo response
#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    name: Option<String>,
}

// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

// Rate limit middleware
async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, StatusCode> {
    // Get client identifier (IP address in this case)
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Check if rate limited
    if let Err(_) = state.limiter.check_key(&client_ip) {
        error!("Rate limit exceeded for IP: {}", client_ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}

// Auth middleware - Now using config from state
async fn auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, StatusCode> {
    // Skip auth for non-API routes
    if !request.uri().path().starts_with("/api") {
        return Ok(next.run(request).await);
    }

    // Get authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Extract the token
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate the token using config
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Token is valid, proceed
    Ok(next.run(request).await)
}

// Google auth redirect - Now using config
async fn google_auth_redirect(
    State(state): State<AppState>,
) -> impl IntoResponse {
    // Build Google OAuth URL from config
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile",
        state.config.google_client_id, state.config.google_redirect_uri
    );
    
    axum::response::Redirect::to(&auth_url)
}

// Google auth callback - Now using config
async fn google_auth_callback(
    Query(params): Query<GoogleCallback>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    // Exchange authorization code for token using config
    let token_res = state.http_client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", params.code.as_str()),
            ("client_id", state.config.google_client_id.as_str()),
            ("client_secret", state.config.google_client_secret.as_str()),
            ("redirect_uri", state.config.google_redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let token_data: GoogleTokenResponse = token_res
        .json()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Get user info
    let user_res = state.http_client
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(&token_data.access_token)
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let user_info: GoogleUserInfo = user_res
        .json()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Create JWT token with expiration from config
    let now = chrono::Utc::now();
    let exp = now
        .checked_add_signed(chrono::Duration::hours(state.config.jwt_expiration_hours as i64))
        .expect("valid timestamp")
        .timestamp();
    
    let claims = Claims {
        sub: user_info.sub,
        email: user_info.email,
        exp,
    };
    
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret_bytes()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Return token (in a real app, you might redirect to a frontend)
    Ok(Json(serde_json::json!({
        "token": token,
        "token_type": "Bearer",
        "expires_in": token_data.expires_in
    })))
}

// Get user profile (protected endpoint) - Now using config
async fn get_user_profile(
    headers: HeaderMap,
    State(state): State<AppState>
) -> Result<impl IntoResponse, StatusCode> {
    // Extract and validate token
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Return user info
    Ok(Json(serde_json::json!({
        "id": token_data.claims.sub,
        "email": token_data.claims.email
    })))
}

// Get protected data
async fn get_protected_data() -> impl IntoResponse {
    Json(serde_json::json!({
        "message": "This is protected data",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    // Server Configuration
    pub server_host: String,
    pub server_port: u16,
    pub environment: String,
    
    // JWT Authentication
    pub jwt_secret: String,
    pub jwt_expiration_hours: u64,
    
    // Rate Limiting
    pub rate_limit_requests: u32,
    pub rate_limit_duration_secs: u64,
    
    // Google OAuth Configuration
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_uri: String,
}

impl Config {
    pub fn from_env() -> Result<Self, envy::Error> {
        // Load .env file if it exists
        dotenv::dotenv().ok();
        
        // Parse environment variables into Config struct
        envy::from_env::<Config>()
    }
    
    pub fn jwt_secret_bytes(&self) -> &[u8] {
        self.jwt_secret.as_bytes()
    }
}

