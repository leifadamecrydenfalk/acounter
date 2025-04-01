// src/main.rs
use std::sync::Arc;
use std::time::Duration;
use std::num::NonZeroU32;

// Web framework and HTTP
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post, delete},
    Json, Router,
};
use tower_http::trace::TraceLayer;

// Authentication and security
use governor::{
    clock::DefaultClock,
    state::keyed::DashMapStateStore, 
    Quota, RateLimiter,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

// HTTP client
use reqwest::Client;

// Serialization
use serde::{Deserialize, Serialize};

// Logging
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Database
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// Async traits
use async_trait::async_trait;

// Email
use lettre::message::{header, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

// Error handling
use thiserror::Error;

//=============================================================================
// Configuration
//=============================================================================

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

    // Database
    pub database_url: String,
    
    // SMTP
    pub smtp_server: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from_email: String,
    
    // Optional notification channels
    pub slack_webhook_url: Option<String>,
    pub telegram_bot_token: Option<String>,
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

//=============================================================================
// Models
//=============================================================================

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

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Alert {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub condition: String,
    pub severity: AlertSeverity,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "alert_severity", rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Subscription {
    pub id: Uuid,
    pub alert_id: Uuid,
    pub channel_type: NotificationChannel,
    pub target: String, // Email address, webhook URL, etc.
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "notification_channel", rename_all = "lowercase")]
pub enum NotificationChannel {
    Email,
    Slack,
    Telegram,
    Webhook,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct AlertHistory {
    pub id: Uuid,
    pub alert_id: Uuid,
    pub triggered_at: DateTime<Utc>,
    pub data: serde_json::Value,
    pub resolved_at: Option<DateTime<Utc>>,
}

// Request and response DTOs
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAlertRequest {
    pub name: String,
    pub description: Option<String>,
    pub condition: String,
    pub severity: AlertSeverity,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub alert_id: Uuid,
    pub channel_type: NotificationChannel,
    pub target: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TriggerAlertRequest {
    pub alert_id: Uuid,
    pub data: serde_json::Value,
}

//=============================================================================
// Error types
//=============================================================================

#[derive(Error, Debug)]
pub enum NotificationError {
    #[error("Failed to send notification: {0}")]
    SendError(String),
    #[error("Invalid notification target: {0}")]
    InvalidTarget(String),
    #[error("Channel not configured: {0}")]
    ChannelNotConfigured(String),
}

//=============================================================================
// Application State
//=============================================================================

// Application state with config
#[derive(Clone)]
struct AppState {
    limiter: Arc<RateLimiter<String, DashMapStateStore<String>, DefaultClock>>,
    http_client: Client,
    config: Arc<Config>,
    db_pool: Option<Arc<PgPool>>, // Optional for when not using database
    notification_service: Option<Arc<NotificationService>>, // Optional for when not using notifications
}

//=============================================================================
// Main Function
//=============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = Config::from_env()?;
    
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting API server in {} mode", config.environment);

    // Track available features for health reporting
    let mut available_features = vec!["authentication"];
    
    // Connect to database if URL provided
    let db_pool = if !config.database_url.is_empty() {
        match establish_connection(&config.database_url).await {
            Ok(pool) => {
                info!("Database connection established");
                available_features.push("database");
                Some(Arc::new(pool))
            },
            Err(e) => {
                error!("Failed to connect to database: {}", e);
                None
            }
        }
    } else {
        info!("No database URL configured, database features will be disabled");
        None
    };

    // Setup notification services if needed
    let notification_service = if db_pool.is_some() {
        let email_config_valid = !config.smtp_server.is_empty() 
            && !config.smtp_username.is_empty() 
            && !config.smtp_password.is_empty();
            
        if email_config_valid {
            match EmailNotifier::new(
                config.smtp_server.clone(),
                config.smtp_port,
                config.smtp_username.clone(),
                config.smtp_password.clone(),
                config.smtp_from_email.clone(),
            ) {
                Ok(email_notifier) => {
                    let slack_notifier = config.slack_webhook_url
                        .clone()
                        .map(|url| {
                            available_features.push("slack_notifications");
                            SlackNotifier::new(Some(url))
                        });

                    let telegram_notifier = config.telegram_bot_token
                        .clone()
                        .map(|token| {
                            available_features.push("telegram_notifications");
                            TelegramNotifier::new(token)
                        });

                    let webhook_notifier = WebhookNotifier::new();
                    available_features.push("email_notifications");
                    available_features.push("webhook_notifications");

                    Some(Arc::new(NotificationService::new(
                        email_notifier,
                        slack_notifier,
                        telegram_notifier,
                        webhook_notifier,
                    )))
                },
                Err(e) => {
                    error!("Failed to initialize email notifier: {}", e);
                    None
                }
            }
        } else {
            info!("Email configuration incomplete, notification features will be limited");
            None
        }
    } else {
        None
    };

    // Create application state with config
    let state = AppState {
        limiter: Arc::new(RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(config.rate_limit_requests).unwrap_or_else(|| NonZeroU32::new(1).unwrap())
        ))),
        http_client: Client::new(),
        config: Arc::new(config.clone()),
        db_pool,
        notification_service,
    };

    // Create a health check handler that reports available features
    let features = available_features.clone();
    async fn health_check_with_features(features: Vec<&str>) -> impl IntoResponse {
        Json(serde_json::json!({
            "status": "ok",
            "available_features": features,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }

    // Create fallback handlers for unavailable features
    async fn database_unavailable() -> impl IntoResponse {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "This endpoint requires database connectivity which is not currently available",
                "status": "service_unavailable"
            }))
        )
    }

    async fn notifications_unavailable() -> impl IntoResponse {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "This endpoint requires notification services which are not currently available",
                "status": "service_unavailable"
            }))
        )
    }

    // Build the public routes router
    let public_router = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/health", get(move || health_check_with_features(features)))
        .route("/auth/google", get(google_auth_redirect))
        .route("/auth/google/callback", get(google_auth_callback));

    // Basic API routes that don't depend on database
    let base_api_router = Router::new()
        .route("/me", get(get_user_profile))
        .route("/data", get(get_protected_data));

    // Build alerts router - either with real handlers or fallbacks
    let alerts_router = if state.db_pool.is_some() {
        Router::new()
            .route("/", post(create_alert))
            .route("/", get(list_alerts))
            .route("/:id", get(get_alert))
            .route("/:id", post(update_alert))
            .route("/:id/activate", post(activate_alert))
            .route("/:id/deactivate", post(deactivate_alert))
    } else {
        Router::new()
            .route("/", post(database_unavailable))
            .route("/", get(database_unavailable))
            .route("/:id", get(database_unavailable))
            .route("/:id", post(database_unavailable))
            .route("/:id/activate", post(database_unavailable))
            .route("/:id/deactivate", post(database_unavailable))
    };

    // Build subscriptions router - either with real handlers or fallbacks
    let subscriptions_router = if state.db_pool.is_some() {
        Router::new()
            .route("/", post(create_subscription))
            .route("/", get(list_subscriptions))
            .route("/:id", get(get_subscription))
            .route("/:id", delete(delete_subscription))
    } else {
        Router::new()
            .route("/", post(database_unavailable))
            .route("/", get(database_unavailable))
            .route("/:id", get(database_unavailable))
            .route("/:id", delete(database_unavailable))
    };

    // Determine the appropriate trigger handler
    let trigger_router = if state.db_pool.is_some() && state.notification_service.is_some() {
        Router::new().route("/trigger", post(trigger_alert))
    } else if state.db_pool.is_some() {
        Router::new().route("/trigger", post(notifications_unavailable))
    } else {
        Router::new().route("/trigger", post(database_unavailable))
    };

    // Compose the API router by nesting feature-specific routers
    let api_router = base_api_router
        .nest("/alerts", alerts_router)
        .nest("/subscriptions", subscriptions_router)
        .merge(trigger_router);

    // Combine all routers
    let app = public_router
        .nest("/api", api_router)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Run the server
    let addr = format!("{}:{}", config.server_host, config.server_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Listening on http://{}", addr);
    info!("Available features: {:?}", available_features);
    axum::serve(listener, app).await?;

    Ok(())
}

//=============================================================================
// Route Handler Functions
//=============================================================================

// Google auth redirect
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

// Google auth callback
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

// Get user profile (protected endpoint)
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

// Create a DELETE handler function to match the route in the router
async fn delete_subscription(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let db = state.db_pool.ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let result = sqlx::query("DELETE FROM subscriptions WHERE id = $1")
        .bind(id)
        .execute(&*db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to delete subscription: {}", e),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Subscription with id {} not found", id),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

//=============================================================================
// Alert Routes
//=============================================================================

async fn create_alert(
    State(state): State<AppState>,
    Json(payload): Json<CreateAlertRequest>,
) -> Result<Json<Alert>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let id = Uuid::new_v4();
    let now = chrono::Utc::now();

    let alert = sqlx::query_as::<_, Alert>(
        r#"
        INSERT INTO alerts (id, name, description, condition, severity, created_at, updated_at, is_active)
        VALUES ($1, $2, $3, $4, $5, $6, $7, true)
        RETURNING id, name, description, condition, severity, created_at, updated_at, is_active
        "#,
    )
    .bind(id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.condition)
    .bind(&payload.severity)
    .bind(now)
    .bind(now)
    .fetch_one(&**db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create alert: {}", e),
        )
    })?;

    Ok(Json(alert))
}

async fn list_alerts(
    State(state): State<AppState>,
) -> Result<Json<Vec<Alert>>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let alerts = sqlx::query_as::<_, Alert>(
        r#"
        SELECT id, name, description, condition, severity, created_at, updated_at, is_active
        FROM alerts
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(&**db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to list alerts: {}", e),
        )
    })?;

    Ok(Json(alerts))
}

async fn get_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let alert = sqlx::query_as::<_, Alert>(
        r#"
        SELECT id, name, description, condition, severity, created_at, updated_at, is_active
        FROM alerts
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_one(&**db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::NOT_FOUND,
            format!("Alert with id {} not found", id),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get alert: {}", e),
        ),
    })?;

    Ok(Json(alert))
}

async fn update_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateAlertRequest>,
) -> Result<Json<Alert>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let now = chrono::Utc::now();

    let alert = sqlx::query_as::<_, Alert>(
        r#"
        UPDATE alerts
        SET name = $1, description = $2, condition = $3, severity = $4, updated_at = $5
        WHERE id = $6
        RETURNING id, name, description, condition, severity, created_at, updated_at, is_active
        "#,
    )
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.condition)
    .bind(&payload.severity)
    .bind(now)
    .bind(id)
    .fetch_one(&**db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::NOT_FOUND,
            format!("Alert with id {} not found", id),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update alert: {}", e),
        ),
    })?;

    Ok(Json(alert))
}

async fn activate_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let now = chrono::Utc::now();

    let alert = sqlx::query_as::<_, Alert>(
        r#"
        UPDATE alerts
        SET is_active = true, updated_at = $1
        WHERE id = $2
        RETURNING id, name, description, condition, severity, created_at, updated_at, is_active
        "#,
    )
    .bind(now)
    .bind(id)
    .fetch_one(&**db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::NOT_FOUND,
            format!("Alert with id {} not found", id),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to activate alert: {}", e),
        ),
    })?;

    Ok(Json(alert))
}

async fn deactivate_alert(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Alert>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let now = chrono::Utc::now();

    let alert = sqlx::query_as::<_, Alert>(
        r#"
        UPDATE alerts
        SET is_active = false, updated_at = $1
        WHERE id = $2
        RETURNING id, name, description, condition, severity, created_at, updated_at, is_active
        "#,
    )
    .bind(now)
    .bind(id)
    .fetch_one(&**db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::NOT_FOUND,
            format!("Alert with id {} not found", id),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to deactivate alert: {}", e),
        ),
    })?;

    Ok(Json(alert))
}

//=============================================================================
// Subscription Routes
//=============================================================================

async fn create_subscription(
    State(state): State<AppState>,
    Json(payload): Json<CreateSubscriptionRequest>,
) -> Result<Json<Subscription>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let id = Uuid::new_v4();
    let now = chrono::Utc::now();

    // First, verify that the alert exists
    let alert_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM alerts WHERE id = $1)",
    )
    .bind(payload.alert_id)
    .fetch_one(&**db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    if !alert_exists {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Alert with id {} not found", payload.alert_id),
        ));
    }

    let subscription = sqlx::query_as::<_, Subscription>(
        r#"
        INSERT INTO subscriptions (id, alert_id, channel_type, target, created_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, alert_id, channel_type, target, created_at
        "#,
    )
    .bind(id)
    .bind(payload.alert_id)
    .bind(&payload.channel_type)
    .bind(&payload.target)
    .bind(now)
    .fetch_one(&**db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create subscription: {}", e),
        )
    })?;

    Ok(Json(subscription))
}

async fn list_subscriptions(
    State(state): State<AppState>,
) -> Result<Json<Vec<Subscription>>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let subscriptions = sqlx::query_as::<_, Subscription>(
        r#"
        SELECT id, alert_id, channel_type, target, created_at
        FROM subscriptions
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(&**db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to list subscriptions: {}", e),
        )
    })?;

    Ok(Json(subscriptions))
}

async fn get_subscription(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Subscription>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;

    let subscription = sqlx::query_as::<_, Subscription>(
        r#"
        SELECT id, alert_id, channel_type, target, created_at
        FROM subscriptions
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_one(&**db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::NOT_FOUND,
            format!("Subscription with id {} not found", id),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get subscription: {}", e),
        ),
    })?;

    Ok(Json(subscription))
}

//=============================================================================
// Trigger Alert Route
//=============================================================================

async fn trigger_alert(
    State(state): State<AppState>,
    Json(payload): Json<TriggerAlertRequest>,
) -> Result<Json<AlertHistory>, (StatusCode, String)> {
    let db = state.db_pool.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Database not configured".to_string())
    )?;
    
    let notification_service = state.notification_service.as_ref().ok_or_else(|| 
        (StatusCode::INTERNAL_SERVER_ERROR, "Notification service not configured".to_string())
    )?;

    // 1. Check if alert exists and is active
    let alert = sqlx::query_as::<_, Alert>(
        r#"
        SELECT id, name, description, condition, severity, created_at, updated_at, is_active
        FROM alerts
        WHERE id = $1
        "#,
    )
    .bind(payload.alert_id)
    .fetch_one(&**db)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => (
            StatusCode::NOT_FOUND,
            format!("Alert with id {} not found", payload.alert_id),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        ),
    })?;

    if !alert.is_active {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Alert with id {} is not active", payload.alert_id),
        ));
    }

    // 2. Begin a transaction
    let mut tx = db.begin().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to begin transaction: {}", e),
        )
    })?;

    // 3. Record the alert trigger in history
    let history_id = Uuid::new_v4();
    let now = chrono::Utc::now();

    let history = sqlx::query_as::<_, AlertHistory>(
        r#"
        INSERT INTO alert_history (id, alert_id, triggered_at, data, resolved_at)
        VALUES ($1, $2, $3, $4, NULL)
        RETURNING id, alert_id, triggered_at, data, resolved_at
        "#,
    )
    .bind(history_id)
    .bind(alert.id)
    .bind(now)
    .bind(&payload.data)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to record alert history: {}", e),
        )
    })?;

    // 4. Find all subscriptions for this alert
    let subscriptions = sqlx::query_as::<_, Subscription>(
        r#"
        SELECT id, alert_id, channel_type, target, created_at
        FROM subscriptions
        WHERE alert_id = $1
        "#,
    )
    .bind(alert.id)
    .fetch_all(&mut *tx) 
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to fetch subscriptions: {}", e),
        )
    })?;

    // 5. Commit the transaction
    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to commit transaction: {}", e),
        )
    })?;

    // 6. Send notifications for each subscription (outside the DB transaction)
    for subscription in subscriptions {
        // Send notification asynchronously
        let alert_clone = alert.clone();
        let ns_clone = Arc::clone(notification_service);
        let data_clone = payload.data.clone();
        
        tokio::spawn(async move {
            if let Err(e) = ns_clone
                .send_notification(
                    &alert_clone,
                    &subscription.channel_type,
                    &subscription.target,
                    &data_clone,
                )
                .await
            {
                tracing::error!(
                    "Failed to send notification to {}: {}",
                    subscription.target,
                    e
                );
            } else {
                tracing::info!(
                    "Notification sent successfully to {} via {:?}",
                    subscription.target,
                    subscription.channel_type
                );
            }
        });
    }

    Ok(Json(history))
}

//=============================================================================
// Middleware Functions
//=============================================================================

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

// Auth middleware
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

//=============================================================================
// Database Functions
//=============================================================================

pub async fn establish_connection(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(database_url)
        .await
}

//=============================================================================
// Notification Service
//=============================================================================

#[async_trait]
pub trait Notifier {
    async fn send_notification(
        &self,
        alert: &Alert,
        target: &str,
        data: &serde_json::Value,
    ) -> Result<(), NotificationError>;
}

pub struct NotificationService {
    email_notifier: EmailNotifier,
    slack_notifier: Option<SlackNotifier>,
    telegram_notifier: Option<TelegramNotifier>,
    webhook_notifier: WebhookNotifier,
}

impl NotificationService {
    pub fn new(
        email_notifier: EmailNotifier,
        slack_notifier: Option<SlackNotifier>,
        telegram_notifier: Option<TelegramNotifier>,
        webhook_notifier: WebhookNotifier,
    ) -> Self {
        Self {
            email_notifier,
            slack_notifier,
            telegram_notifier,
            webhook_notifier,
        }
    }

    pub async fn send_notification(
        &self,
        alert: &Alert,
        channel: &NotificationChannel,
        target: &str,
        data: &serde_json::Value,
    ) -> Result<(), NotificationError> {
        match channel {
            NotificationChannel::Email => {
                self.email_notifier.send_notification(alert, target, data).await
            }
            NotificationChannel::Slack => {
                if let Some(notifier) = &self.slack_notifier {
                    notifier.send_notification(alert, target, data).await
                } else {
                    Err(NotificationError::ChannelNotConfigured("Slack".to_string()))
                }
            }
            NotificationChannel::Telegram => {
                if let Some(notifier) = &self.telegram_notifier {
                    notifier.send_notification(alert, target, data).await
                } else {
                    Err(NotificationError::ChannelNotConfigured("Telegram".to_string()))
                }
            }
            NotificationChannel::Webhook => {
                self.webhook_notifier.send_notification(alert, target, data).await
            }
        }
    }
}

//=============================================================================
// Email Notifier
//=============================================================================

pub struct EmailNotifier {
    from_email: String,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailNotifier {
    pub fn new(
        smtp_server: String,
        smtp_port: u16,
        username: String,
        password: String,
        from_email: String,
    ) -> Result<Self, NotificationError> {
        let creds = Credentials::new(username, password);
        
        let tls_parameters = TlsParameters::new(smtp_server.clone())
            .map_err(|e| NotificationError::SendError(format!("TLS error: {}", e)))?;

        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_server)
            .map_err(|e| NotificationError::SendError(format!("SMTP relay error: {}", e)))?
            .port(smtp_port)
            .credentials(creds)
            .tls(Tls::Required(tls_parameters))
            .build();

        Ok(Self {
            from_email,
            transport,
        })
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    async fn send_notification(
        &self,
        alert: &Alert,
        target: &str,
        data: &serde_json::Value,
    ) -> Result<(), NotificationError> {
        // Validate email format
        if !target.contains('@') {
            return Err(NotificationError::InvalidTarget(format!(
                "Invalid email address: {}",
                target
            )));
        }

        // Create email subject based on alert severity and name
        let subject = format!("[{:?}] Alert: {}", alert.severity, alert.name);
        
        // Format email body
        let text_body = format!(
            "Alert triggered: {}\n\nSeverity: {:?}\n\nDetails:\n{}\n\nData: {}",
            alert.name,
            alert.severity,
            alert.description.as_deref().unwrap_or("No description provided"),
            serde_json::to_string_pretty(data).unwrap_or_else(|_| "Failed to format data".to_string())
        );
        
        // Create HTML version of the body
        let html_body = format!(
            "<h2>Alert triggered: {}</h2><p><strong>Severity:</strong> {:?}</p><p><strong>Details:</strong></p><p>{}</p><pre>{}</pre>",
            alert.name,
            alert.severity,
            alert.description.as_deref().unwrap_or("No description provided"),
            serde_json::to_string_pretty(data).unwrap_or_else(|_| "Failed to format data".to_string())
        );

        // Build the email
        let email = Message::builder()
            .from(self.from_email.parse().map_err(|e| {
                NotificationError::SendError(format!("Invalid from address: {}", e))
            })?)
            .to(target.parse().map_err(|e| {
                NotificationError::SendError(format!("Invalid to address: {}", e))
            })?)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body)
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body)
                    )
            )
            .map_err(|e| NotificationError::SendError(format!("Failed to build email: {}", e)))?;

        // Send the email
        self.transport
            .send(email)
            .await
            .map_err(|e| NotificationError::SendError(format!("Failed to send email: {}", e)))?;

        Ok(())
    }
}

//=============================================================================
// Slack Notifier
//=============================================================================

pub struct SlackNotifier {
    client: Client,
    webhook_url: Option<String>,
}

impl SlackNotifier {
    pub fn new(webhook_url: Option<String>) -> Self {
        Self {
            client: Client::new(),
            webhook_url,
        }
    }
}

#[async_trait]
impl Notifier for SlackNotifier {
    async fn send_notification(
        &self,
        alert: &Alert,
        target: &str,
        data: &serde_json::Value,
    ) -> Result<(), NotificationError> {
        // Use provided target (webhook URL) or fallback to the default one
        let webhook_url = if target.starts_with("https://hooks.slack.com") {
            target.to_string()
        } else if let Some(url) = &self.webhook_url {
            url.clone()
        } else {
            return Err(NotificationError::InvalidTarget(
                "No Slack webhook URL provided".to_string(),
            ));
        };

        // Determine color based on severity
        let color = match alert.severity {
            AlertSeverity::Info => "#2196F3",    // Blue
            AlertSeverity::Warning => "#FFC107", // Amber
            AlertSeverity::Error => "#FF5722",   // Deep Orange
            AlertSeverity::Critical => "#F44336", // Red
        };

        // Format data as a string
        let data_str = serde_json::to_string_pretty(data)
            .unwrap_or_else(|_| "Failed to format data".to_string());

        // Build the Slack message payload
        let payload = serde_json::json!({
            "attachments": [{
                "color": color,
                "title": format!("Alert: {}", alert.name),
                "text": alert.description.clone().unwrap_or_else(|| "No description provided".to_string()),
                "fields": [
                    {
                        "title": "Severity",
                        "value": format!("{:?}", alert.severity),
                        "short": true
                    },
                    {
                        "title": "Data",
                        "value": format!("```{}```", data_str),
                        "short": false
                    }
                ],
                "footer": "Rust Alert System",
                "ts": chrono::Utc::now().timestamp()
            }]
        });

        // Send the request to Slack
        let response = self
            .client
            .post(&webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| NotificationError::SendError(format!("HTTP request failed: {}", e)))?;

        // Check if the request was successful
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response body".to_string());
            return Err(NotificationError::SendError(format!(
                "Slack API error: {} - {}",
                status, body
            )));
        }

        Ok(())
    }
}

//=============================================================================
// Telegram Notifier
//=============================================================================

pub struct TelegramNotifier {
    client: Client,
    bot_token: String,
}

impl TelegramNotifier {
    pub fn new(bot_token: String) -> Self {
        Self {
            client: Client::new(),
            bot_token,
        }
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    async fn send_notification(
        &self,
        alert: &Alert,
        target: &str,
        data: &serde_json::Value,
    ) -> Result<(), NotificationError> {
        // Validate chat_id
        let chat_id = target.parse::<i64>().map_err(|_| {
            NotificationError::InvalidTarget(format!("Invalid Telegram chat ID: {}", target))
        })?;

        // Format the message
        let message = format!(
            "*Alert: {}*\n\nSeverity: {:?}\n\n{}\n\n```\n{}\n```",
            alert.name,
            alert.severity,
            alert.description.as_deref().unwrap_or("No description provided"),
            serde_json::to_string_pretty(data).unwrap_or_else(|_| "Failed to format data".to_string())
        );

        // Build the API URL
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );

        // Send the request to Telegram
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }))
            .send()
            .await
            .map_err(|e| NotificationError::SendError(format!("HTTP request failed: {}", e)))?;

        // Check if the request was successful
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response body".to_string());
            return Err(NotificationError::SendError(format!(
                "Telegram API error: {} - {}",
                status, body
            )));
        }

        Ok(())
    }
}

//=============================================================================
// Webhook Notifier
//=============================================================================

pub struct WebhookNotifier {
    client: Client,
}

impl WebhookNotifier {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    async fn send_notification(
        &self,
        alert: &Alert,
        target: &str,
        data: &serde_json::Value,
    ) -> Result<(), NotificationError> {
        // Validate webhook URL
        if !target.starts_with("http://") && !target.starts_with("https://") {
            return Err(NotificationError::InvalidTarget(format!(
                "Invalid webhook URL: {}",
                target
            )));
        }

        // Build the payload
        let payload = serde_json::json!({
            "alert": {
                "id": alert.id.to_string(),
                "name": alert.name,
                "description": alert.description,
                "severity": alert.severity,
                "triggered_at": chrono::Utc::now()
            },
            "data": data
        });

        // Send the webhook request
        let response = self
            .client
            .post(target)
            .json(&payload)
            .send()
            .await
            .map_err(|e| NotificationError::SendError(format!("HTTP request failed: {}", e)))?;

        // Check if the request was successful (2xx status code)
        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response body".to_string());
            
            return Err(NotificationError::SendError(format!(
                "Webhook error: {} - {}",
                status, body
            )));
        }

        Ok(())
    }
}