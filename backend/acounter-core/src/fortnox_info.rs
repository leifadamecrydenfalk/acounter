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

use crate::AppError;

// --- Employee Data ---
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Employee {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "EmployeeId")]
    pub employee_id: String,
    #[serde(rename = "PersonalIdentityNumber")]
    pub personal_identity_number: Option<String>, // Might be sensitive, handle with care
    #[serde(rename = "FirstName")]
    pub first_name: Option<String>,
    #[serde(rename = "LastName")]
    pub last_name: Option<String>,
    #[serde(rename = "FullName")]
    pub full_name: Option<String>, // Often useful
    #[serde(rename = "Address1")]
    pub address1: Option<String>,
    #[serde(rename = "Address2")]
    pub address2: Option<String>,
    #[serde(rename = "PostCode")]
    pub post_code: Option<String>,
    #[serde(rename = "City")]
    pub city: Option<String>,
    #[serde(rename = "Country")]
    pub country: Option<String>,
    #[serde(rename = "Phone")]
    pub phone: Option<String>,
    #[serde(rename = "Email")]
    pub email: Option<String>,
    #[serde(rename = "EmploymentForm")]
    pub employment_form: Option<String>,
    #[serde(rename = "SalaryForm")]
    pub salary_form: Option<String>,
    #[serde(rename = "JobTitle")]
    pub job_title: Option<String>,
    #[serde(rename = "PersonelType")] // Note: Fortnox might use 'PersonelType' (with one 'n')
    pub personnel_type: Option<String>, // E.g., TJM (Tjänsteman), ARB (Arbetare)
    #[serde(rename = "StartDate")]
    pub start_date: Option<String>,
    #[serde(rename = "EndDate")]
    pub end_date: Option<String>, // Indicates inactive if set and in the past
    #[serde(rename = "Active")]
    pub active: Option<bool>, // Explicit active flag is useful
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EmployeeResponse {
    #[serde(rename = "Employees")]
    pub employees: Vec<Employee>,
    #[serde(rename = "@TotalResources")]
    pub total_resources: Option<i32>,
    #[serde(rename = "@TotalPages")]
    pub total_pages: Option<i32>,
    #[serde(rename = "@CurrentPage")]
    pub current_page: Option<i32>,
}

// --- Salary Code Data (Often used for Time/Absence Registration Codes) ---
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SalaryCode {
    #[serde(rename = "@url")]
    pub url: Option<String>,
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "CodeType")] // e.g., ARBETTID, FRÅNVARO, TILLÄGG, AVDRAG
    pub code_type: String, // Might be 'SalaryCodeType' depending on Fortnox version
                           // Add other relevant fields if needed from API docs
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SalaryCodeResponse {
    #[serde(rename = "SalaryCodes")] // Check API documentation for the exact key name
    pub salary_codes: Vec<SalaryCode>,
    #[serde(rename = "@TotalResources")]
    pub total_resources: Option<i32>,
    #[serde(rename = "@TotalPages")]
    pub total_pages: Option<i32>,
    #[serde(rename = "@CurrentPage")]
    pub current_page: Option<i32>,
}

// --- Structure to hold combined information ---
#[derive(Debug, Clone, Serialize, Deserialize)] // Serialize might be useful if you return JSON later
pub struct TimeRegistrationInfo {
    pub mandatory_for_worked_time: Vec<String>,
    pub mandatory_for_absence: Vec<String>,
    pub other_notes: String,
    pub available_salary_codes: Vec<SalaryCode>, // Actual codes fetched
                                                 // We could add fetched Services/Projects here too if needed
}

// --- Structure for Cached Data ---
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CachedInfo {
    pub employees: Vec<Employee>,
    pub time_info: TimeRegistrationInfo, // Use the existing structure
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
}