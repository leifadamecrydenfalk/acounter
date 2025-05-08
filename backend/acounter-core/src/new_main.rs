// src/main.rs
use anyhow::{Context, Result};
use axum::http::StatusCode as AxumStatusCode;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::{Datelike, NaiveDate, Utc};
use rust_decimal::prelude::FromPrimitive;
// Added Utc, Datelike, NaiveDate
use rust_decimal::Decimal; // Added
use rust_decimal_macros::dec; // Added
use std::{
    collections::HashMap, env, net::SocketAddr, path::PathBuf, sync::Arc,
    time::Duration as StdDuration,
}; // Added StdDuration, HashMap
use thiserror::Error;
use tokio::sync::Mutex as TokioMutex; // Renamed to avoid conflict if turborilla_time_validation::Mutex is brought into scope
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

mod fortnox_client;
use fortnox_client::{
    run_fortnox_token_refresh,
    AuthCallbackParams,
    DetailedRegistration as FortnoxDetailedRegistration, // Alias for clarity
    EmployeeListItem as FortnoxEmployeeListItem,         // Alias for clarity
    FortnoxClient,
    FortnoxConfig,
    FortnoxError,
    DEFAULT_CACHE_DURATION_SECS,
};

// Keep turborilla_time_validation as a module
mod turborilla_time_validation;
use turborilla_time_validation::{
    AllocationBasisCache,                 // For TimeReportingSystem initialization
    Employee as SystemEmployee,           // Alias for clarity
    EmployeeType as SystemEmployeeType,   // Alias for clarity
    MockNotificationService,              // For initializing TimeReportingSystem
    TestClock,                            // For initializing TimeReportingSystem
    TimeEntryData as SystemTimeEntryData, // Alias for clarity
    TimeReportingSystem,
};

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

#[derive(Debug, Clone)]
struct AppConfig {
    cert_path: String,
    key_path: String,
}

#[derive(Clone)]
pub struct AppState {
    pub fortnox_client: Arc<FortnoxClient>,
    pub time_reporting_system: Arc<TimeReportingSystem>, // Added
}

// --- FortnoxDataSynchronizer ---
struct FortnoxDataSynchronizer {
    fortnox_client: Arc<FortnoxClient>,
    time_system: Arc<TimeReportingSystem>,
}

impl FortnoxDataSynchronizer {
    pub fn new(fortnox_client: Arc<FortnoxClient>, time_system: Arc<TimeReportingSystem>) -> Self {
        Self {
            fortnox_client,
            time_system,
        }
    }

    // Placeholder mapping functions - these require significant business logic
    fn map_fortnox_employee_to_system_employee(
        &self,
        fe: &FortnoxEmployeeListItem,
    ) -> SystemEmployee {
        // This is highly dependent on how Turborilla maps Fortnox data to its internal model.
        // Main project, manager, type, and exemption are not directly in FortnoxEmployeeListItem.
        // You might need to:
        // 1. Hardcode mappings based on EmployeeId.
        // 2. Use custom fields in Fortnox if they exist.
        // 3. Have a separate configuration file/database for these mappings.
        // 4. The "Main Projects (from April 1, 2025)" implies date-sensitive logic for main_project.

        let name = fe.full_name.clone().unwrap_or_else(|| {
            format!(
                "{} {}",
                fe.first_name.clone().unwrap_or_default(),
                fe.last_name.clone().unwrap_or_default()
            )
        });

        // Example: Extremely simplified logic
        let employee_type = if fe.employee_id.starts_with("FGN") {
            // Hypothetical convention
            SystemEmployeeType::Foreign
        } else {
            SystemEmployeeType::Turborilla
        };

        let main_project = match fe.employee_id.as_str() {
            "EMP_PETER" => "P700".to_string(), // Placeholder IDs
            "EMP_DANA" => "P300".to_string(),
            _ => "P_UNKNOWN".to_string(), // Default if not mapped
        };

        let manager = match fe.employee_id.as_str() {
            "EMP_PETER" => Some("MGR_TOBIAS".to_string()),
            _ => None,
        };

        let is_exempt = fe.employee_id == "JENS"; // Based on guideline

        SystemEmployee {
            id: fe.employee_id.clone(),
            name,
            employee_type,
            main_project,
            manager,
            is_exempt_from_balance_rules: is_exempt,
        }
    }

    pub async fn sync_employees(&self) -> Result<(), FortnoxError> {
        info!("Starting employee synchronization from Fortnox...");
        let fortnox_employees_response = self.fortnox_client.get_employees().await?;

        let mut system_employees_map = self.time_system.employees.lock().unwrap();
        system_employees_map.clear(); // Simple clear and reload strategy

        for fe in fortnox_employees_response.employees {
            let system_employee = self.map_fortnox_employee_to_system_employee(&fe);
            info!(
                "Syncing employee: ID={}, Name={}",
                system_employee.id, system_employee.name
            );
            system_employees_map.insert(system_employee.id.clone(), system_employee);
        }
        info!(
            "Employee synchronization complete. Synced {} employees.",
            system_employees_map.len()
        );
        Ok(())
    }

    pub async fn sync_schedules_for_month(
        &self,
        year: i32,
        month: u32,
    ) -> Result<(), FortnoxError> {
        info!(
            "Starting schedule synchronization from Fortnox for {}-{}...",
            year, month
        );
        let employee_ids: Vec<String> = {
            self.time_system
                .employees
                .lock()
                .unwrap()
                .keys()
                .cloned()
                .collect()
        };

        if employee_ids.is_empty() {
            warn!("No employees found in TimeReportingSystem. Skipping schedule sync.");
            return Ok(());
        }

        let first_day_of_month = match NaiveDate::from_ymd_opt(year, month, 1) {
            Some(date) => date,
            None => {
                error!("Invalid year/month for schedule sync: {}-{}", year, month);
                return Ok(());
            }
        };
        let first_day_of_next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap()
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap()
        };

        // Collect all schedule data to be inserted before acquiring the main lock
        let mut schedules_to_update: Vec<(String, NaiveDate, Decimal)> = Vec::new();

        for emp_id in employee_ids {
            let is_turborilla_employee = {
                // Lock for employees is fine, guard dropped
                let employees_guard = self.time_system.employees.lock().unwrap();
                employees_guard
                    .get(&emp_id)
                    .map_or(false, |e| e.employee_type == SystemEmployeeType::Turborilla)
            };

            if !is_turborilla_employee {
                debug!(
                    "Skipping schedule sync for non-Turborilla employee: {}",
                    emp_id
                );
                continue;
            }

            let mut current_date = first_day_of_month;
            while current_date < first_day_of_next_month {
                let date_str = current_date.format("%Y-%m-%d").to_string();

                // Perform the .await call *without* holding the time_system.schedules lock
                match self
                    .fortnox_client
                    .get_schedule_time(&emp_id, &date_str)
                    .await
                {
                    Ok(schedule_response) => {
                        if let Ok(hours_val) = schedule_response.schedule_time.hours.parse::<f64>()
                        {
                            if let Some(hours_decimal) = Decimal::from_f64(hours_val) {
                                schedules_to_update.push((
                                    emp_id.clone(),
                                    current_date,
                                    hours_decimal,
                                ));
                            } else {
                                warn!("Could not convert schedule hours '{}' to Decimal for Emp: {}, Date: {}", schedule_response.schedule_time.hours, emp_id, current_date);
                            }
                        } else {
                            warn!(
                                "Could not parse schedule hours '{}' for Emp: {}, Date: {}",
                                schedule_response.schedule_time.hours, emp_id, current_date
                            );
                        }
                    }
                    Err(FortnoxError::ApiError { status, .. }) if status == 404 => {
                        info!(
                            "No Fortnox schedule found for Emp: {}, Date: {}. Assuming 0.0 hours.",
                            emp_id, current_date
                        );
                        schedules_to_update.push((emp_id.clone(), current_date, dec!(0.0)));
                    }
                    Err(e) => {
                        error!(
                            "Failed to get schedule for Emp: {}, Date: {}: {}",
                            emp_id, current_date, e
                        );
                        // Optionally, decide whether to continue or propagate the error.
                        // For now, it logs and continues with the next date/employee.
                    }
                }
                current_date = current_date
                    .succ_opt()
                    .expect("Date overflow in schedule sync");
            }
        }

        // Now, acquire the lock once and apply all updates
        if !schedules_to_update.is_empty() {
            let mut system_schedules_map = self.time_system.schedules.lock().unwrap();
            // If you are doing a full refresh for the month, you might want to clear
            // existing entries for this month first. For example:
            // system_schedules_map.retain(|(_emp_id_key, date_key), _hours| {
            //     !(date_key.year() == year && date_key.month() == month &&
            //       schedules_to_update.iter().any(|(e_id, d, _)| e_id == _emp_id_key && d == date_key))
            // });
            // Or a simpler clear if it's a full overwrite for all employees for the month:
            // system_schedules_map.retain(|(_, date_key), _| !(date_key.year() == year && date_key.month() == month));

            for (emp_id, date, hours) in schedules_to_update {
                info!(
                    "Updating system schedule for Emp: {}, Date: {}, Hours: {}",
                    emp_id, date, hours
                );
                system_schedules_map.insert((emp_id, date), hours);
            }
        }
        info!("Schedule synchronization for {}-{} complete.", year, month);
        Ok(())
    }

    fn map_fortnox_time_entry_to_system_entry(
        &self,
        fe: &FortnoxDetailedRegistration,
    ) -> Option<SystemTimeEntryData> {
        let Ok(entry_date) = NaiveDate::parse_from_str(&fe.worked_date, "%Y-%m-%d") else {
            warn!(
                "Could not parse worked_date '{}' for Fortnox entry ID {}",
                fe.worked_date, fe.id
            );
            return None;
        };

        Some(SystemTimeEntryData {
            id: fe.id.clone(),
            emp_id: fe.user_id.clone(),
            date: entry_date,
            hours: Decimal::from_f64(fe.worked_hours).unwrap_or_else(|| dec!(0.0)),
            reg_code: fe.registration_code.code.clone(),
            project: fe.project.as_ref().map(|p| p.id.clone()),
            customer: fe.customer.as_ref().map(|c| c.id.clone()), // Fortnox customer ID
            service: fe.service.as_ref().map(|s| s.id.clone()),
            note: fe.note.clone(),
            full_day_flag: false, // Not directly available in Fortnox DetailedRegistration
        })
    }

    pub async fn sync_historical_time_entries(
        &self,
        from_date: NaiveDate,
        to_date: NaiveDate,
    ) -> Result<(), FortnoxError> {
        info!(
            "Starting historical time entry synchronization from Fortnox for {} to {}...",
            from_date, to_date
        );

        let employee_ids: Vec<String> = {
            self.time_system
                .employees
                .lock()
                .unwrap()
                .keys()
                .cloned()
                .collect()
        };

        if employee_ids.is_empty() {
            warn!("No employees found. Skipping historical time entry sync.");
            return Ok(());
        }

        // Fetch all entries for the period for the known employees
        let fortnox_entries_response = self
            .fortnox_client
            .get_time_registrations(
                &from_date.format("%Y-%m-%d").to_string(),
                &to_date.format("%Y-%m-%d").to_string(),
                Some(employee_ids.clone()), // Ensure we only get entries for employees we know
                None,
                None,
            )
            .await?;

        let mut system_time_entries_map = self.time_system.time_entries.lock().unwrap();
        // Potentially clear historical entries for this period before adding new ones
        // system_time_entries_map.retain(|(_emp_id, date), _entries| !(*date >= from_date && *date <= to_date));

        for fe in fortnox_entries_response {
            if let Some(system_entry) = self.map_fortnox_time_entry_to_system_entry(&fe) {
                info!(
                    "Syncing historical entry: Emp={}, Date={}, Hours={}",
                    system_entry.emp_id, system_entry.date, system_entry.hours
                );
                system_time_entries_map
                    .entry((system_entry.emp_id.clone(), system_entry.date))
                    .or_default()
                    .push(system_entry);

                // Invalidate allocation cache for the week of this entry and the next
                let iso_week = fe.worked_date.parse::<NaiveDate>().unwrap().iso_week(); // Assuming parse succeeds due to map_fortnox_time_entry...
                self.time_system
                    .allocation_basis_cache
                    .invalidate_cache_for_week(&fe.user_id, iso_week.year(), iso_week.week());
                if let Some(next_week_date) = fe
                    .worked_date
                    .parse::<NaiveDate>()
                    .unwrap()
                    .checked_add_days(chrono::Days::new(7))
                {
                    let next_iso_week = next_week_date.iso_week();
                    self.time_system
                        .allocation_basis_cache
                        .invalidate_cache_for_week(
                            &fe.user_id,
                            next_iso_week.year(),
                            next_iso_week.week(),
                        );
                }
            }
        }
        info!("Historical time entry synchronization complete.");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Setting tracing subscriber failed")?;
    info!("Tracing subscriber initialized.");

    let app_config = load_app_config()?;
    info!("App configuration loaded.");
    let fortnox_config_loaded = load_fortnox_config()?; // Renamed to avoid conflict
    info!("Fortnox configuration loaded.");

    let fortnox_client = Arc::new(FortnoxClient::new(fortnox_config_loaded.clone())?);
    info!("Fortnox Client initialized.");

    tokio::spawn(run_fortnox_token_refresh(fortnox_client.clone()));

    // --- Initialize TimeReportingSystem ---
    let clock = TestClock::new("2024-01-01 00:00:00"); // Dummy clock for now
    let notification_svc = MockNotificationService::new();
    let time_reporting_system = Arc::new(TimeReportingSystem::new(
        clock.clone(),
        notification_svc.clone(),
    ));
    info!("TimeReportingSystem initialized.");

    // --- Create and use FortnoxDataSynchronizer ---
    let data_synchronizer = Arc::new(FortnoxDataSynchronizer::new(
        fortnox_client.clone(),
        time_reporting_system.clone(),
    ));

    // Perform initial sync at startup (non-blocking)
    let initial_sync_task = data_synchronizer.clone();
    tokio::spawn(async move {
        info!("Performing initial data synchronization...");
        if let Err(e) = initial_sync_task.sync_employees().await {
            error!("Initial employee sync failed: {}", e);
        }
        let now = Utc::now();
        if let Err(e) = initial_sync_task
            .sync_schedules_for_month(now.year(), now.month())
            .await
        {
            error!("Initial schedule sync for current month failed: {}", e);
        }
        // Sync historical time entries for the last, say, 4 weeks for allocation basis
        let today = chrono::Local::now().date_naive();
        let four_weeks_ago = today - chrono::Duration::weeks(4);
        if let Err(e) = initial_sync_task
            .sync_historical_time_entries(four_weeks_ago, today - chrono::Duration::days(1))
            .await
        {
            error!("Initial historical time entry sync failed: {}", e);
        }
        info!("Initial data synchronization attempt finished.");
    });

    // Periodic Sync Task
    let periodic_sync_task = data_synchronizer.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(StdDuration::from_secs(4 * 60 * 60)).await; // Sync every 4 hours
            info!("Starting periodic data synchronization...");
            if let Err(e) = periodic_sync_task.sync_employees().await {
                error!("Periodic employee sync failed: {}", e);
            }
            let now = Utc::now();
            if let Err(e) = periodic_sync_task
                .sync_schedules_for_month(now.year(), now.month())
                .await
            {
                error!("Periodic schedule sync for current month failed: {}", e);
            }
            // Sync historical entries for a rolling window, e.g., last 4 weeks
            let today = chrono::Local::now().date_naive();
            let four_weeks_ago = today - chrono::Duration::weeks(4);
            if let Err(e) = periodic_sync_task
                .sync_historical_time_entries(four_weeks_ago, today - chrono::Duration::days(1))
                .await
            {
                error!("Periodic historical time entry sync failed: {}", e);
            }
            info!("Periodic data synchronization finished.");
        }
    });

    // --- Create Shared App State for Axum ---
    let app_state_for_axum = AppState {
        // Renamed to avoid conflict in this scope
        fortnox_client: fortnox_client.clone(),
        time_reporting_system: time_reporting_system.clone(), // Pass TRS to Axum state
    };
    info!("Application state initialized.");

    let fortnox_routes = Router::new()
        .route("/auth", get(handle_api_fortnox_auth))
        .route("/auth/callback", get(handle_api_fortnox_auth_callback));
    let api_routes = Router::new().nest("/fortnox", fortnox_routes);
    let app = Router::new()
        .nest("/api", api_routes)
        .route("/status", get(handle_status))
        // You might add new routes here that interact with time_reporting_system
        .with_state(app_state_for_axum);

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
            .unwrap_or_else(|_| PathBuf::from(fortnox_client::DEFAULT_TOKEN_FILE)),
        cache_dir: PathBuf::from(
            env::var("CACHE_DIR").unwrap_or_else(|_| fortnox_client::DEFAULT_CACHE_DIR.to_string()),
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

    // Trigger an immediate data sync after successful auth if desired
    let immediate_sync_client = state.fortnox_client.clone();
    let immediate_sync_time_system = state.time_reporting_system.clone();
    tokio::spawn(async move {
        info!("Triggering data sync after successful auth callback...");
        let synchronizer =
            FortnoxDataSynchronizer::new(immediate_sync_client, immediate_sync_time_system);
        if let Err(e) = synchronizer.sync_employees().await {
            error!("Post-auth employee sync failed: {}", e);
        }
        let now = Utc::now();
        if let Err(e) = synchronizer
            .sync_schedules_for_month(now.year(), now.month())
            .await
        {
            error!("Post-auth schedule sync failed: {}", e);
        }
        let today = chrono::Local::now().date_naive();
        let four_weeks_ago = today - chrono::Duration::weeks(4);
        if let Err(e) = synchronizer
            .sync_historical_time_entries(four_weeks_ago, today - chrono::Duration::days(1))
            .await
        {
            error!("Post-auth historical time entry sync failed: {}", e);
        }
        info!("Post-auth data synchronization attempt finished.");
    });

    Ok(Html(
        "<h1>Success!</h1><p>Authentication successful. Token data saved. Data sync initiated.</p>"
            .to_string(),
    ))
}

async fn handle_status(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    info!("Handling /status request...");
    let token_status = state.fortnox_client.get_token_status().await?;

    let status_message = format!(
        "Token Status: has_token={}, is_valid={}, is_expired={}, expires_in={}s, expires_at={}",
        token_status.has_token,
        token_status.is_valid,
        token_status.is_expired,
        token_status.expires_in_secs,
        token_status.expires_at
    );

    // Example: Display count of synced employees
    let employee_count = state.time_reporting_system.employees.lock().unwrap().len();
    let schedule_count = state.time_reporting_system.schedules.lock().unwrap().len();
    let historical_entry_days_count = state
        .time_reporting_system
        .time_entries
        .lock()
        .unwrap()
        .len();

    let html_body = format!(
        "<h1>Server Status</h1><p>Current Time (Server): {}</p><p>{}</p><hr>\
         <p>Synced Employees: {}</p>\
         <p>Synced Schedule Entries (Employee,Date): {}</p>\
         <p>Days with Synced Historical Time Entries: {}</p><hr>\
         <p><a href='/api/fortnox/auth'>Re-authorize with Fortnox</a></p>",
        chrono::Local::now().to_rfc3339(),
        status_message,
        employee_count,
        schedule_count,
        historical_entry_days_count
    );
    Ok(Html(html_body))
}
