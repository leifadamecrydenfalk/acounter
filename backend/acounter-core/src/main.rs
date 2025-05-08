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
use chrono::Datelike;
use chrono::NaiveDate;
use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use serde::{Deserialize, Serialize}; // Added Serialize, Deserialize
use std::collections::HashMap;
use std::{env, fs, net::SocketAddr, path::PathBuf, sync::Arc};
use thiserror::Error;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod fortnox_client;
use fortnox_client::{
    run_fortnox_token_refresh,
    AuthCallbackParams,
    DetailedRegistration,
    EmployeeListItem, // Added EmployeeListItem
    EmployeeListResponse,
    FortnoxClient,
    FortnoxConfig,
    FortnoxError,
    FortnoxMe, // Added FortnoxMe
    ScheduleTime,
    DEFAULT_CACHE_DURATION_SECS,
};

mod turborilla_time_validation;
use crate::turborilla_time_validation::*;

// --- AppError Definition (Update Fortnox variant) ---
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    #[error("Fortnox API client error")]
    Fortnox(#[from] FortnoxError),
}

// --- IntoResponse Implementation (Match on specific FortnoxError) ---
impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        error!("Error occurred: {:?}", self);

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
                    let axum_status = AxumStatusCode::from_u16(status.as_u16())
                        .unwrap_or(AxumStatusCode::INTERNAL_SERVER_ERROR);
                    error!("Fortnox API Error: Status={}, Msg={}", status, message);
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

// --- New User Struct ---
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")] // Consistent naming for JSON output
pub struct CompanyUser {
    // From EmployeeListItem
    pub employee_id: String,
    pub personal_identity_number: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub full_name: Option<String>,
    pub employee_email: String, // Email from employee record

    // From FortnoxMe (for the authenticated user, if they are an employee)
    pub user_id: Option<String>,    // This is the `Id` from FortnoxMe
    pub user_email: Option<String>, // Email from /me endpoint, can differ from employee_email
    pub user_name: Option<String>,  // Name from /me endpoint
    pub locale: Option<String>,
    pub is_sys_admin: Option<bool>,
}

// --- New function to fetch and combine user details ---
async fn fetch_all_company_user_details(
    client: &Arc<FortnoxClient>,
) -> Result<Vec<CompanyUser>, AppError> {
    info!("Fetching all company user details...");

    // 1. Fetch all employees
    // `get_employees` already uses get_with_cache, so it returns EmployeeListResponse or FortnoxError
    let employee_list_response = client.get_employees().await?; // Propagates FortnoxError, maps to AppError
    let employees: Vec<EmployeeListItem> = employee_list_response.employees;
    info!("Fetched {} employee entries.", employees.len());

    // 2. Fetch current authenticated user's details (/me)
    // `get_me` already uses get_with_cache, so it returns FortnoxMe or FortnoxError
    let me_info: FortnoxMe = client.get_me().await?; // Propagates FortnoxError, maps to AppError
    info!(
        "Fetched /me info for authenticated user ID: {}, Email: {:?}",
        me_info.id, me_info.email
    );

    // 3. Combine the data
    let mut detailed_users: Vec<CompanyUser> = Vec::new();

    for emp_item in employees {
        let mut user = CompanyUser {
            employee_id: emp_item.employee_id.clone(),
            personal_identity_number: emp_item.personal_identity_number.clone(),
            first_name: emp_item.first_name.clone(),
            last_name: emp_item.last_name.clone(),
            full_name: emp_item.full_name.clone(),
            employee_email: emp_item.email.clone(), // Email from the employee record
            user_id: None,
            user_email: None,
            user_name: None,
            locale: None,
            is_sys_admin: None,
        };

        // Try to match the authenticated user (/me info) with this employee record.
        // Primary matching key: email from employee record against email from /me info.
        // The /me endpoint's email is Option<String>.
        if let Some(me_user_email) = &me_info.email {
            if me_user_email.eq_ignore_ascii_case(&emp_item.email) {
                debug!(
                    "Matched employee {} ({}) with /me user by email.",
                    emp_item.employee_id, emp_item.email
                );
                user.user_id = Some(me_info.id.clone());
                user.user_email = me_info.email.clone(); // Email from /me
                user.user_name = me_info.name.clone(); // Name from /me
                user.locale = me_info.locale.clone();
                user.is_sys_admin = me_info.sys_admin;
            }
        }
        // As a fallback, or if emails might differ but names match, one could add name-based matching.
        // However, email is generally more unique for user accounts.
        // Example (less reliable):
        // else if emp_item.full_name.as_deref().is_some() && me_info.name.as_deref().is_some() {
        //     if emp_item.full_name.as_deref().unwrap().eq_ignore_ascii_case(me_info.name.as_deref().unwrap()) {
        //         debug!("Matched employee {} ({:?}) with /me user by name.", emp_item.employee_id, emp_item.full_name);
        //         user.user_id = Some(me_info.id.clone());
        //         // ... populate other fields ...
        //     }
        // }

        detailed_users.push(user);
    }

    info!(
        "Processed {} employees into detailed user list.",
        detailed_users.len()
    );
    Ok(detailed_users)
}

// --- Main Function (Adjust error mapping) ---
#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Setting tracing subscriber failed")?;
    info!("Tracing subscriber initialized.");

    let app_config = load_app_config()?;
    info!("App configuration loaded.");
    let fortnox_config = load_fortnox_config()?;
    info!("Fortnox configuration loaded.");

    let fortnox_client_instance = FortnoxClient::new(fortnox_config)?;
    let fortnox_client_arc = Arc::new(fortnox_client_instance);
    info!("Fortnox Client initialized.");

    let refresh_client = fortnox_client_arc.clone();
    tokio::spawn(run_fortnox_token_refresh(refresh_client));

    let state = AppState {
        fortnox_client: fortnox_client_arc.clone(),
    };
    info!("Application state initialized.");

    // Existing: Fetch and save basic employee list
    let employees_output_filename = "turborilla_employees.json";
    match fetch_and_save_employees(&state.fortnox_client, employees_output_filename).await {
        Ok(_) => info!(
            "Successfully fetched and saved basic employee list to '{}'.",
            employees_output_filename
        ),
        Err(app_err) => {
            error!(
                "Error fetching/saving basic employee list to '{}': {:?}. Server startup will continue.",
                employees_output_filename, app_err
            );
        }
    }

    // New: Fetch and save comprehensive company user details
    let company_users_output_filename = "company_users_detailed.json";
    match fetch_all_company_user_details(&state.fortnox_client).await {
        Ok(users) => {
            info!(
                "Successfully fetched {} comprehensive user entries.",
                users.len()
            );
            match serde_json::to_string_pretty(&users) {
                Ok(json_string) => {
                    // Ensure parent directory exists
                    let output_path = PathBuf::from(company_users_output_filename);
                    if let Some(parent) = output_path.parent() {
                        if !parent.exists() {
                            if let Err(e) = fs::create_dir_all(parent) {
                                error!(
                                    "Failed to create directory {:?} for {}: {}",
                                    parent, company_users_output_filename, e
                                );
                                // Continue without saving if dir creation fails, or handle as fatal
                            }
                        }
                    }

                    if let Err(e) = fs::write(&output_path, json_string) {
                        error!(
                            "Failed to write comprehensive user details to {}: {}",
                            company_users_output_filename, e
                        );
                    } else {
                        info!(
                            "Successfully saved comprehensive user details to {}",
                            company_users_output_filename
                        );
                    }
                }
                Err(e) => {
                    // This would be a AppError::Fortnox(FortnoxError::Json(e)) if it happened in the client
                    // Here it's a direct serde_json error.
                    error!("Failed to serialize comprehensive user details: {}", e);
                }
            }
        }
        Err(app_err) => {
            // This app_err is already an AppError (likely AppError::Fortnox)
            error!(
                "Error fetching comprehensive company user details: {:?}. Server startup will continue.",
                app_err
            );
        }
    }

    let fortnox_routes = Router::new()
        .route("/auth", get(handle_api_fortnox_auth))
        .route("/auth/callback", get(handle_api_fortnox_auth_callback));
    let api_routes = Router::new().nest("/fortnox", fortnox_routes);
    let app = Router::new()
        .nest("/api", api_routes)
        .route("/status", get(handle_status))
        .with_state(state);

    let tls_config = load_tls_config(&app_config).await?;
    info!("TLS configuration loaded.");

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Starting server on https://{}", addr);
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .context("HTTPS server failed")?;

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
            .unwrap_or_else(|_| PathBuf::from("fortnox_token.json")),
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
    let auth_url = state.fortnox_client.generate_auth_url().await?;
    Ok(Redirect::temporary(&auth_url))
}

async fn handle_api_fortnox_auth_callback(
    State(state): State<AppState>,
    Query(params): Query<AuthCallbackParams>,
) -> Result<Html<String>, AppError> {
    info!("Handling /api/fortnox/auth/callback...");
    state.fortnox_client.handle_auth_callback(params).await?;
    info!("Successfully handled Fortnox auth callback.");
    Ok(Html(
        "<h1>Success!</h1><p>Authentication successful. Token data saved.</p>".to_string(),
    ))
}

async fn handle_status(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    info!("Handling /status request...");
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

async fn fetch_and_save_employee_schedule_for_month(
    client: &Arc<FortnoxClient>,
    employee_id: &str,
    year: i32,
    month: u32,
    output_filename: &str,
) -> Result<(), AppError> {
    info!(
        "Starting to fetch schedule for employee ID: {} for month: {}-{}",
        employee_id, year, month
    );

    let mut collected_schedules: Vec<ScheduleTime> = Vec::new();

    if !(1..=12).contains(&month) {
        error!("Invalid month provided: {}", month);
        return Err(AppError::Fortnox(FortnoxError::ConfigError(format!(
            "Invalid month: {}",
            month
        ))));
    }

    let mut current_date = match NaiveDate::from_ymd_opt(year, month, 1) {
        Some(date) => date,
        None => {
            error!("Invalid year/month combination: {}-{}", year, month);
            return Err(AppError::Fortnox(FortnoxError::ConfigError(format!(
                "Invalid start date for {}-{}",
                year, month
            ))));
        }
    };

    while current_date.month() == month {
        let date_str = current_date.format("%Y-%m-%d").to_string();
        info!(
            "Fetching schedule for employee {} on date: {}",
            employee_id, date_str
        );

        match client.get_schedule_time(employee_id, &date_str).await {
            Ok(response) => {
                collected_schedules.push(response.schedule_time);
                info!(
                    "Successfully fetched schedule for {}: {} hours",
                    date_str,
                    collected_schedules.last().unwrap().hours
                );
            }
            Err(e) => {
                warn!(
                    "Failed to get schedule for employee {} on {}: {:?}. Skipping this day.",
                    employee_id, date_str, e
                );
            }
        }

        if let Some(next_day) = current_date.succ_opt() {
            current_date = next_day;
        } else {
            error!(
                "Could not determine next day after {}, stopping.",
                current_date
            );
            break;
        }
    }

    if collected_schedules.is_empty() {
        warn!(
            "No schedule data was collected for employee {} for {}-{}. File will not be saved.",
            employee_id, year, month
        );
        return Ok(());
    }

    info!(
        "Collected {} schedule entries for employee {}. Saving to '{}'...",
        collected_schedules.len(),
        employee_id,
        output_filename
    );

    let output_path = PathBuf::from(output_filename);
    match serde_json::to_string_pretty(&collected_schedules) {
        Ok(json_string) => {
            if let Err(e) = fs::write(&output_path, json_string) {
                error!("Failed to write schedule data to {:?}: {}", output_path, e);
                return Err(AppError::Io(e));
            } else {
                info!("Successfully saved schedule data to {:?}", output_path);
            }
        }
        Err(e) => {
            error!(
                "Failed to serialize schedule data for employee {}: {}",
                employee_id, e
            );
            return Err(AppError::Fortnox(FortnoxError::Json(e)));
        }
    }

    Ok(())
}

async fn fetch_and_save_time_registrations(
    client: &Arc<FortnoxClient>,
    employee_id: &str,
    year: i32,
    month: u32,
    output_filename: &str,
) -> Result<(), AppError> {
    info!(
        "Starting to fetch time registrations for employee ID: {} for month: {}-{}",
        employee_id, year, month
    );

    if !(1..=12).contains(&month) {
        error!("Invalid month provided: {}", month);
        return Err(AppError::Fortnox(FortnoxError::ConfigError(format!(
            "Invalid month: {}",
            month
        ))));
    }

    let first_day = NaiveDate::from_ymd_opt(year, month, 1).ok_or_else(|| {
        AppError::Fortnox(FortnoxError::ConfigError(format!(
            "Invalid start date for {}-{}",
            year, month
        )))
    })?;

    let next_month_year = if month == 12 { year + 1 } else { year };
    let next_month_month = if month == 12 { 1 } else { month + 1 };
    let first_day_next_month = NaiveDate::from_ymd_opt(next_month_year, next_month_month, 1)
        .ok_or_else(|| {
            AppError::Fortnox(FortnoxError::ConfigError(format!(
                "Invalid end date calculation for {}-{}",
                year, month
            )))
        })?;
    let last_day = first_day_next_month.pred_opt().unwrap_or(first_day);

    let from_date_str = first_day.format("%Y-%m-%d").to_string();
    let to_date_str = last_day.format("%Y-%m-%d").to_string();

    info!(
        "Fetching Fortnox time entries for Emp={}, Period: {} to {}",
        employee_id, from_date_str, to_date_str
    );

    let registrations: Vec<DetailedRegistration> = client
        .get_time_registrations(
            &from_date_str,
            &to_date_str,
            Some(vec![employee_id.to_string()]),
            None,
            None,
        )
        .await?;

    if registrations.is_empty() {
        warn!(
            "No time registrations found for employee {} for {}-{}. File '{}' will not be saved.",
            employee_id, year, month, output_filename
        );
        return Ok(());
    }

    info!(
        "Collected {} time registration entries for employee {}. Saving to '{}'...",
        registrations.len(),
        employee_id,
        output_filename
    );

    let output_path = PathBuf::from(output_filename);
    let json_string = serde_json::to_string_pretty(&registrations)
        .map_err(|e| AppError::Fortnox(FortnoxError::Json(e)))?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, json_string)?;

    info!(
        "Successfully saved time registration data to {:?}",
        output_path
    );
    Ok(())
}

async fn fetch_and_save_employees(
    client: &Arc<FortnoxClient>,
    output_filename: &str,
) -> Result<(), AppError> {
    info!(
        "Starting to fetch employee list, saving to '{}'",
        output_filename
    );

    let employee_response: EmployeeListResponse = client
        .get_with_cache(
            "/employees",
            "employees",
            None,
            None,
            None,
            "Get All Employees",
        )
        .await?;

    if employee_response.employees.is_empty() {
        warn!(
            "No employees found or returned from Fortnox API. Saving empty list to '{}'.",
            output_filename
        );
    } else {
        info!(
            "Fetched {} employee entries. Saving to '{}'...",
            employee_response.employees.len(),
            output_filename
        );
    }

    let output_path = PathBuf::from(output_filename);
    let json_string = serde_json::to_string_pretty(&employee_response)
        .map_err(|e| AppError::Fortnox(FortnoxError::Json(e)))?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, json_string)?;

    info!("Successfully saved employee data to {:?}", output_path);
    Ok(())
}
