// src/fortnox_data.rs
use crate::convert_fortnox_error; // Use the helper to convert errors
use crate::fortnox::{
    ArticleListItem, ArticleListResponse, CustomerListItem, CustomerListResponse,
    DetailedRegistration, EmployeeListItem, EmployeeListResponse, FortnoxClient, FortnoxError,
    ProjectListItem, ProjectListResponse, ScheduleTimeResponse, FORTNOX_API_BASE_URL,
    FORTNOX_TIME_API_URL,
};
use crate::time_validation::{
    EmployeeConfig, MonthStatus, TimeDeviation, TimeValidationService, WeekStatus,
};
use crate::AppError; // Use the main AppError
use chrono::{Datelike, Duration, NaiveDate};
use std::{collections::HashMap, fs, sync::Arc};
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct FortnoxDataService {
    client: Arc<FortnoxClient>,
}

impl FortnoxDataService {
    pub fn new(client: Arc<FortnoxClient>) -> Self {
        Self { client }
    }

    // --- Employee Data ---

    /// Fetches all employees from Fortnox, using cache.
    pub async fn get_all_employees(&self) -> Result<Vec<EmployeeListItem>, AppError> {
        info!("Fetching all employees (using cache)...");
        match self
            .client
            .get_with_cache::<EmployeeListResponse>(
                "/employees",
                "employees", // resource_type for caching
                None,        // resource_id
                None,        // query_params
                None,        // base_url (defaults to FORTNOX_API_BASE_URL)
            )
            .await
        {
            Ok(response) => Ok(response.employees),
            Err(e) => {
                error!("Failed to fetch employees: {}", e);
                Err(convert_fortnox_error(e))
            }
        }
    }

    /// Fetches a specific employee by ID from Fortnox, using cache.
    pub async fn get_employee(&self, employee_id: &str) -> Result<EmployeeListItem, AppError> {
        info!("Fetching employee {} (using cache)...", employee_id);
        match self.client.get_employee(employee_id).await {
            Ok(employee) => Ok(employee),
            Err(e) => {
                error!("Failed to fetch employee {}: {}", employee_id, e);
                Err(convert_fortnox_error(e))
            }
        }
    }

    // --- Project Data ---

    /// Fetches all projects from Fortnox, using cache.
    /// Handles pagination if necessary (basic example, Fortnox might require more complex handling).
    pub async fn get_all_projects(&self) -> Result<Vec<ProjectListItem>, AppError> {
        info!("Fetching all projects (using cache)...");
        // Basic pagination handling (adjust if Fortnox API needs more sophisticated logic)
        let mut all_projects = Vec::new();
        let mut current_page = 1;
        let limit = 100; // Fetch 100 projects per page (adjust as needed)

        loop {
            let endpoint = format!("/projects?limit={}&page={}", limit, current_page);
            let mut params = HashMap::new();
            params.insert("limit".to_string(), limit.to_string());
            params.insert("page".to_string(), current_page.to_string());

            debug!("Fetching projects page {}", current_page);
            match self
                .client
                .get_with_cache::<ProjectListResponse>(
                    &endpoint,
                    "projects",    // resource_type
                    None,          // resource_id
                    Some(&params), // Fixed typo: ¶ms -> &params
                    None,          // base_url
                )
                .await
            {
                Ok(response) => {
                    let fetched_count = response.projects.len();
                    all_projects.extend(response.projects);

                    // Determine if there are more pages
                    let total_pages = response.total_pages.unwrap_or(1); // Default to 1 page if not provided
                    debug!(
                        "Fetched {} projects on page {}. Total pages: {}",
                        fetched_count, current_page, total_pages
                    );

                    if fetched_count == 0 || current_page >= total_pages {
                        break; // No more projects or reached last page
                    }
                    current_page += 1;
                }
                Err(e) => {
                    error!("Failed to fetch projects page {}: {}", current_page, e);
                    // If one page fails, return the error, or potentially return partial results
                    return Err(convert_fortnox_error(e));
                }
            }
        }
        info!("Finished fetching {} total projects.", all_projects.len());
        Ok(all_projects)
    }

    /// Fetches a specific project by ID from Fortnox, using cache.
    pub async fn get_project(&self, project_id: &str) -> Result<ProjectListItem, AppError> {
        info!("Fetching project {} (using cache)...", project_id);
        match self.client.get_project(project_id).await {
            Ok(project) => Ok(project),
            Err(e) => {
                error!("Failed to fetch project {}: {}", project_id, e);
                Err(convert_fortnox_error(e))
            }
        }
    }

    // --- Customer Data ---

    /// Fetches all customers from Fortnox, using cache.
    pub async fn get_all_customers(&self) -> Result<Vec<CustomerListItem>, AppError> {
        info!("Fetching all customers (using cache)...");
        match self
            .client
            .get_with_cache::<CustomerListResponse>(
                "/customers",
                "customers", // resource_type
                None,        // resource_id
                None,        // query_params
                None,        // base_url
            )
            .await
        {
            Ok(response) => Ok(response.customers),
            Err(e) => {
                error!("Failed to fetch customers: {}", e);
                Err(convert_fortnox_error(e))
            }
        }
    }

    // --- Article/Service Data ---

    /// Fetches all articles (used as Services in Time Reporting) from Fortnox, using cache.
    pub async fn get_all_articles(&self) -> Result<Vec<ArticleListItem>, AppError> {
        info!("Fetching all articles/services (using cache)...");
        match self
            .client
            .get_with_cache::<ArticleListResponse>(
                "/articles",
                "articles", // resource_type
                None,       // resource_id
                None,       // query_params
                None,       // base_url
            )
            .await
        {
            Ok(response) => Ok(response.articles),
            Err(e) => {
                error!("Failed to fetch articles/services: {}", e);
                Err(convert_fortnox_error(e))
            }
        }
    }

    // --- Time Registration Data ---

    /// Fetches detailed time registrations for a specific employee within a date range.
    /// Uses caching based on employee ID and date range.
    pub async fn get_time_registrations_for_period(
        &self,
        employee_id: &str,
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> Result<Vec<DetailedRegistration>, AppError> {
        let start_str = start_date.format("%Y-%m-%d").to_string();
        let end_str = end_date.format("%Y-%m-%d").to_string();
        info!(
            "Fetching time registrations for employee {} from {} to {} (using cache)...",
            employee_id, start_str, end_str
        );

        // Create a custom cache key that includes the employee ID
        let resource_type = "time_registrations_employee";
        let resource_id = Some(employee_id);

        // Construct query parameters
        let mut params = HashMap::new();
        params.insert("fromDate".to_string(), start_str.clone());
        params.insert("toDate".to_string(), end_str.clone());

        // Check for cached data with our specific employee key
        if let Ok(Some(cached_data)) = self.client.load_from_cache::<Vec<DetailedRegistration>>(
            resource_type,
            resource_id,
            Some(&params),
        ) {
            info!(
                "Retrieved {} cached time registrations for employee {} from {} to {}",
                cached_data.len(),
                employee_id,
                start_str,
                end_str
            );
            return Ok(cached_data);
        }

        // Not in cache, use the API
        match self
            .client
            .get_time_registrations(
                &start_str,
                &end_str,
                Some(vec![employee_id.to_string()]), // Filter by specific user
                None,                                // No customer filter
                None,                                // No project filter
            )
            .await
        {
            Ok(registrations) => {
                info!(
                    "Fetched {} time registrations for employee {} from {} to {}",
                    registrations.len(),
                    employee_id,
                    start_str,
                    end_str
                );

                // Save the result in our cache with the employee-specific key
                if let Err(e) = self.client.save_to_cache(
                    resource_type,
                    resource_id,
                    Some(&params),
                    &registrations,
                ) {
                    warn!(
                        "Failed to cache time registrations for employee {}: {}",
                        employee_id, e
                    );
                }

                Ok(registrations)
            }
            Err(e) => {
                error!(
                    "Failed to fetch time registrations for employee {} from {} to {}: {}",
                    employee_id, start_str, end_str, e
                );
                Err(convert_fortnox_error(e))
            }
        }
    }

    // --- Schedule Time Data ---

    /// Fetches the scheduled hours for a specific employee on a given date.
    /// Returns 0.0 if no schedule is found or if hours cannot be parsed.
    /// Uses caching based on employee ID and date.
    pub async fn get_schedule_hours_for_day(
        &self,
        employee_id: &str,
        date: NaiveDate,
    ) -> Result<f64, AppError> {
        let date_str = date.format("%Y-%m-%d").to_string();
        info!(
            "Fetching scheduled hours for employee {} on {} (using cache)...",
            employee_id, date_str
        );

        // Cache key params
        let mut cache_params = HashMap::new();
        cache_params.insert("date".to_string(), date_str.clone());

        // Use the underlying client method which uses get_with_cache
        match self.client.get_schedule_time(employee_id, &date_str).await {
            Ok(response) => {
                match response.schedule_time.hours.parse::<f64>() {
                    Ok(hours) => {
                        debug!(
                            "Successfully parsed schedule hours: {} for employee {} on {}",
                            hours, employee_id, date_str
                        );
                        Ok(hours)
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse schedule hours '{}' for employee {} on {}: {}. Returning 0.0.",
                            response.schedule_time.hours, employee_id, date_str, e
                        );
                        Ok(0.0) // Treat unparseable hours as 0
                    }
                }
            }
            Err(FortnoxError::ApiError { status, .. })
                if status == reqwest::StatusCode::NOT_FOUND =>
            {
                // If the API returns 404 Not Found, it likely means no schedule exists for that day/employee.
                // This is expected for non-working days or international employees.
                debug!(
                    "No schedule found (404) for employee {} on {}. Returning 0.0 hours.",
                    employee_id, date_str
                );
                Ok(0.0)
            }
            Err(e) => {
                error!(
                    "Failed to fetch schedule time for employee {} on {}: {}",
                    employee_id, date_str, e
                );
                Err(convert_fortnox_error(e))
            }
        }
    }

    // --- Cache Management ---

    /// Clears the entire Fortnox data cache.
    pub fn clear_all_cache(&self) -> Result<(), AppError> {
        info!("Clearing all Fortnox data cache...");
        match self.client.clear_all_cache() {
            Ok(_) => {
                info!("Successfully cleared all cache.");
                Ok(())
            }
            Err(e) => {
                error!("Failed to clear all cache: {}", e);
                Err(convert_fortnox_error(e))
            }
        }
    }

    /// Clears cache for a specific resource type (e.g., "employees", "projects").
    pub fn clear_cache_for_resource(&self, resource_type: &str) -> Result<(), AppError> {
        info!("Clearing cache for resource type: {}...", resource_type);
        match self.client.clear_cache(resource_type, None) {
            Ok(_) => {
                info!(
                    "Successfully cleared cache for resource type: {}.",
                    resource_type
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to clear cache for resource type {}: {}",
                    resource_type, e
                );
                Err(convert_fortnox_error(e))
            }
        }
    }

    /// Clears cache for a specific employee's time registrations
    pub fn clear_employee_time_cache(&self, employee_id: &str) -> Result<(), AppError> {
        info!(
            "Clearing time registration cache for employee: {}...",
            employee_id
        );

        // Clear custom employee-specific cache
        match self
            .client
            .clear_cache("time_registrations_employee", Some(employee_id))
        {
            Ok(_) => {
                info!(
                    "Successfully cleared time registration cache for employee: {}.",
                    employee_id
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to clear time registration cache for employee {}: {}",
                    employee_id, e
                );
                Err(convert_fortnox_error(e))
            }
        }
    }

    // --- Time Validation Integration Methods ---

    /// Marks a week as complete for an employee and runs validation
    pub async fn mark_week_complete(
        &self,
        employee_id: &str,
        year: i32,
        week: i32,
        time_validation_service: &mut TimeValidationService,
    ) -> Result<WeekStatus, AppError> {
        info!(
            "Marking week {} of {} as complete for employee {}",
            week, year, employee_id
        );

        // Get the date range for the specified week
        let (start_date, end_date) = get_week_date_range(year, week);

        // Fetch the employee's time registrations for the week
        let registrations = self
            .get_time_registrations_for_period(employee_id, start_date, end_date)
            .await?;

        // Check for deviations
        let mut deviations = Vec::new();

        // Get employee config
        let employee_config = time_validation_service
            .employee_configs
            .get(employee_id)
            .ok_or_else(|| {
                AppError::FortnoxServiceError(format!(
                    "No configuration found for employee {}",
                    employee_id
                ))
            })?
            .clone();

        // Validate each registration
        for registration in &registrations {
            // Check mandatory fields
            if let Err(deviation) = time_validation_service.validate_mandatory_fields(registration)
            {
                deviations.push(deviation);
            }

            // Get scheduled hours for this day
            let date = NaiveDate::parse_from_str(&registration.worked_date, "%Y-%m-%d").unwrap();
            let scheduled_hours = self.get_schedule_hours_for_day(employee_id, date).await?;

            // Validate work hours
            if let Err(deviation) = time_validation_service.validate_work_hours(
                registration,
                scheduled_hours,
                &employee_config,
            ) {
                deviations.push(deviation);
            }

            // Validate absence allocation
            if let Err(deviation) =
                time_validation_service.validate_absence_allocation(registration, &employee_config)
            {
                deviations.push(deviation);
            }
        }

        // Check for WFF adjacent to absence
        let wff_deviations =
            time_validation_service.validate_wff_adjacent_to_absence(&registrations, employee_id);
        deviations.extend(wff_deviations);

        // Determine week status
        let status = if deviations.is_empty() {
            WeekStatus::Complete
        } else {
            WeekStatus::HasDeviations(deviations)
        };

        // Mark the week as complete in the time validation service
        time_validation_service.mark_week_complete(employee_id, year, week);

        // Clear cache for this employee to ensure fresh data next time
        let _ = self.clear_employee_time_cache(employee_id);

        Ok(status)
    }

    /// Marks a month as complete for an employee and runs validation
    pub async fn mark_month_complete(
        &self,
        employee_id: &str,
        year: i32,
        month: i32,
        time_validation_service: &mut TimeValidationService,
    ) -> Result<MonthStatus, AppError> {
        info!(
            "Marking month {} of {} as complete for employee {}",
            month, year, employee_id
        );

        // Get the date range for the specified month
        let start_date = NaiveDate::from_ymd_opt(year, month as u32, 1).unwrap();
        let end_date = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
                .unwrap()
                .pred_opt()
                .unwrap()
        } else {
            NaiveDate::from_ymd_opt(year, (month + 1) as u32, 1)
                .unwrap()
                .pred_opt()
                .unwrap()
        };

        // Fetch the employee's time registrations for the month
        let registrations = self
            .get_time_registrations_for_period(employee_id, start_date, end_date)
            .await?;

        // Check for deviations
        let mut deviations = Vec::new();

        // Get employee config
        let employee_config = time_validation_service
            .employee_configs
            .get(employee_id)
            .ok_or_else(|| {
                AppError::FortnoxServiceError(format!(
                    "No configuration found for employee {}",
                    employee_id
                ))
            })?
            .clone();

        // Validate each registration
        for registration in &registrations {
            // Check mandatory fields
            if let Err(deviation) = time_validation_service.validate_mandatory_fields(registration)
            {
                deviations.push(deviation);
            }

            // Get scheduled hours for this day
            let date = NaiveDate::parse_from_str(&registration.worked_date, "%Y-%m-%d").unwrap();
            let scheduled_hours = self.get_schedule_hours_for_day(employee_id, date).await?;

            // Validate work hours
            if let Err(deviation) = time_validation_service.validate_work_hours(
                registration,
                scheduled_hours,
                &employee_config,
            ) {
                deviations.push(deviation);
            }

            // Validate absence allocation
            if let Err(deviation) =
                time_validation_service.validate_absence_allocation(registration, &employee_config)
            {
                deviations.push(deviation);
            }
        }

        // Check for WFF adjacent to absence
        let wff_deviations =
            time_validation_service.validate_wff_adjacent_to_absence(&registrations, employee_id);
        deviations.extend(wff_deviations);

        // Determine month status
        let status = if deviations.is_empty() {
            MonthStatus::Complete
        } else {
            MonthStatus::HasDeviations(deviations)
        };

        // Mark the month as complete in the time validation service
        time_validation_service.mark_month_complete(employee_id, year, month);

        // Clear cache for this employee to ensure fresh data next time
        let _ = self.clear_employee_time_cache(employee_id);

        Ok(status)
    }

    /// Run daily checks for all employees' time reporting status
    pub async fn run_daily_reminders_check(
        &self,
        time_validation_service: &mut TimeValidationService,
    ) -> Result<(), AppError> {
        info!("Running daily time reporting reminders check");

        // Let the time validation service run its checks
        time_validation_service.run_daily_checks();

        // Could be expanded with additional integration logic

        Ok(())
    }
}

// Helper function to get the date range for a specific week
pub fn get_week_date_range(year: i32, week: i32) -> (NaiveDate, NaiveDate) {
    // Get January 4th for the specified year, which is always in week 1
    let jan4 = NaiveDate::from_ymd_opt(year, 1, 4).unwrap();

    // Find the Monday of week 1
    let week1_monday = jan4 - Duration::days(jan4.weekday().num_days_from_monday() as i64);

    // Calculate the start date (Monday) of the requested week
    let start_date = week1_monday + Duration::weeks((week - 1) as i64);

    // Calculate the end date (Sunday) of the requested week
    let end_date = start_date + Duration::days(6);

    (start_date, end_date)
}
