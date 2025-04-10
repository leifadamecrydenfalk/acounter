// src/time_validation.rs
use chrono::{DateTime, Datelike, Duration, Local, NaiveDate, Utc, Weekday};
use std::collections::{HashMap, HashSet};
use tracing::{error, info, warn};

use crate::*;

// --- Time Validation Structures ---

// Represents the status of a week's time reporting
#[derive(Debug, Clone, PartialEq)]
pub enum WeekStatus {
    Incomplete,
    Complete,
    HasDeviations(Vec<TimeDeviation>),
}

// Represents the status of a month's time reporting
#[derive(Debug, Clone, PartialEq)]
pub enum MonthStatus {
    Incomplete,
    Complete,
    HasDeviations(Vec<TimeDeviation>),
}

// Types of deviations that can occur in time reports
#[derive(Debug, Clone, PartialEq)]
pub enum TimeDeviation {
    MissingMandatoryField { field: String, date: NaiveDate },
    IncorrectWorkHours { date: NaiveDate, scheduled: f64, reported: f64 },
    MissingFlexTime { date: NaiveDate, missing_hours: f64 },
    IncorrectProjectAllocation { date: NaiveDate, message: String },
    IncorrectAbsenceAllocation { date: NaiveDate, project: String },
    AdjacentWffToAbsence { wff_date: NaiveDate, absence_date: NaiveDate, absence_type: String },
}

// Employee configuration for validation rules
#[derive(Debug, Clone)]
pub struct EmployeeConfig {
    pub employee_id: String,
    pub is_international: bool,
    pub  is_special_hours: bool, // For employees like Jens with special hour arrangements
    pub  main_project: String,   // Project to allocate absence to
}

// Service to handle time validation and notifications
pub struct TimeValidationService {
    pub employee_configs: HashMap<String, EmployeeConfig>,
    pub week_statuses: HashMap<(String, i32, i32), WeekStatus>, // (employee_id, year, week) -> status
    pub month_statuses: HashMap<(String, i32, i32), MonthStatus>, // (employee_id, year, month) -> status
}

impl TimeValidationService {
    pub fn new() -> Self {
        let mut employee_configs = HashMap::new();
        
        // Add employee configurations based on the main project assignments
        // For project 700 Work For Hire
        for employee_id in ["Peter", "Benzo", "Empa", "Nils", "Lasse", "Elias", "Sebastian", "Maggie", "Zac"] {
            employee_configs.insert(
                employee_id.to_string(),
                EmployeeConfig {
                    employee_id: employee_id.to_string(),
                    is_international: false,
                    is_special_hours: false,
                    main_project: "700".to_string(),
                }
            );
        }
        
        // For project 300 MSM3
        for employee_id in ["Dana", "Andrea", "Jens"] {
            let is_special_hours = employee_id == "Jens";
            employee_configs.insert(
                employee_id.to_string(),
                EmployeeConfig {
                    employee_id: employee_id.to_string(),
                    is_international: false,
                    is_special_hours,
                    main_project: "300".to_string(),
                }
            );
        }
        
        // Project 610 PC premium game
        employee_configs.insert(
            "Joe".to_string(),
            EmployeeConfig {
                employee_id: "Joe".to_string(),
                is_international: false,
                is_special_hours: false,
                main_project: "610".to_string(),
            }
        );
        
        // Project 902 OH
        for employee_id in ["Bryan", "Ida"] {
            employee_configs.insert(
                employee_id.to_string(),
                EmployeeConfig {
                    employee_id: employee_id.to_string(),
                    is_international: false,
                    is_special_hours: false,
                    main_project: "902".to_string(),
                }
            );
        }
        
        Self {
            employee_configs,
            week_statuses: HashMap::new(),
            month_statuses: HashMap::new(),
        }
    }
    
    // Check if all mandatory fields are present in a time registration
    pub fn validate_mandatory_fields(&self, registration: &DetailedRegistration) -> Result<(), TimeDeviation> {
        let is_work_time = registration.registration_code.code == "TID"; // Assuming "TID" is the code for work time
        
        // For work time, check all required fields
        if is_work_time {
            // Date is already required in the structure
            
            // Check if client info is present
            if registration.customer.is_none() {
                return Err(TimeDeviation::MissingMandatoryField {
                    field: "customer".to_string(),
                    date: NaiveDate::parse_from_str(&registration.worked_date, "%Y-%m-%d").unwrap(),
                });
            }
            
            // Check if project info is present
            if registration.project.is_none() {
                return Err(TimeDeviation::MissingMandatoryField {
                    field: "project".to_string(),
                    date: NaiveDate::parse_from_str(&registration.worked_date, "%Y-%m-%d").unwrap(),
                });
            }
            
            // Check if service info is present
            if registration.service.is_none() {
                return Err(TimeDeviation::MissingMandatoryField {
                    field: "service".to_string(),
                    date: NaiveDate::parse_from_str(&registration.worked_date, "%Y-%m-%d").unwrap(),
                });
            }
            
            // Registration code is already validated by being in the structure
            
            // Hours worked is already in the structure
        }
        // For absence, just need date, code, and hours
        else {
            // These are all required in the structure
        }
        
        Ok(())
    }
    
    // Validate work hours against scheduled time
    pub fn validate_work_hours(&self, 
                          registration: &DetailedRegistration, 
                          scheduled_hours: f64,
                          employee_config: &EmployeeConfig) -> Result<(), TimeDeviation> {
        // Skip this validation for employees with special hour arrangements
        if employee_config.is_special_hours {
            return Ok(());
        }
        
        let date = NaiveDate::parse_from_str(&registration.worked_date, "%Y-%m-%d").unwrap();
        
        // For Swedish public holidays with international employees
        if scheduled_hours == 0.0 && employee_config.is_international {
            // Check if they have the correct service code for holidays
            if let Some(service) = &registration.service {
                if service.id != "16" { // "16" is the "Other" service code
                    return Err(TimeDeviation::IncorrectProjectAllocation {
                        date,
                        message: "International employees should use Service 16 for Swedish holidays".to_string(),
                    });
                }
            }
            return Ok(());
        }
        
        // Regular validation of work hours
        if registration.registration_code.type_ == "WORK" {
            if registration.worked_hours < scheduled_hours 
               && !self.has_absence_for_remaining_hours(registration, scheduled_hours) {
                return Err(TimeDeviation::IncorrectWorkHours {
                    date,
                    scheduled: scheduled_hours,
                    reported: registration.worked_hours,
                });
            } else if registration.worked_hours > scheduled_hours 
                    && !self.has_flex_time_plus(registration, scheduled_hours) {
                return Err(TimeDeviation::MissingFlexTime {
                    date,
                    missing_hours: registration.worked_hours - scheduled_hours,
                });
            }
        }
        
        Ok(())
    }
    
    // Check if the employee has absence registrations to account for remaining scheduled hours
    pub   fn has_absence_for_remaining_hours(&self, registration: &DetailedRegistration, scheduled_hours: f64) -> bool {
        // In a real implementation, we would check other registrations for the same day
        // This is just a placeholder
        false
    }
    
    // Check if the employee has flex time plus registrations for hours over scheduled time
    pub  fn has_flex_time_plus(&self, registration: &DetailedRegistration, scheduled_hours: f64) -> bool {
        // In a real implementation, we would check other registrations for the same day
        // This is just a placeholder
        false
    }
    
    // Validate that absence is allocated to the employee's main project
    pub fn validate_absence_allocation(&self, 
                                  registration: &DetailedRegistration, 
                                  employee_config: &EmployeeConfig) -> Result<(), TimeDeviation> {
        if registration.registration_code.type_ == "ABSENCE" {
            // Check if the project is correct for absence
            if let Some(project) = &registration.project {
                if project.id != employee_config.main_project {
                    let date = NaiveDate::parse_from_str(&registration.worked_date, "%Y-%m-%d").unwrap();
                    return Err(TimeDeviation::IncorrectAbsenceAllocation {
                        date,
                        project: project.id.clone(),
                    });
                }
            }
        }
        
        Ok(())
    }
    
    // Validate that WFF adjacent to absence is also marked as absence
    pub fn validate_wff_adjacent_to_absence(&self, 
                                       registrations: &[DetailedRegistration],
                                       employee_id: &str) -> Vec<TimeDeviation> {
        let mut deviations = Vec::new();
        let mut absence_dates = HashMap::new();
        let mut wff_dates = HashSet::new();
        
        // First, collect all absence and WFF dates
        for reg in registrations {
            let date = NaiveDate::parse_from_str(&reg.worked_date, "%Y-%m-%d").unwrap();
            
            if reg.registration_code.type_ == "ABSENCE" {
                absence_dates.insert(date, reg.registration_code.code.clone());
            } else if let Some(service) = &reg.service {
                if service.id == "52" { // "52" is the "Work Free Friday" service code
                    wff_dates.insert(date);
                }
            }
        }
        
        // Now check if any WFF is adjacent to absence
        for wff_date in &wff_dates {
            // Check if the day before or after is an absence day
            let day_before = *wff_date - Duration::days(1);
            let day_after = *wff_date + Duration::days(1);
            
            if let Some(absence_type) = absence_dates.get(&day_before) {
                deviations.push(TimeDeviation::AdjacentWffToAbsence {
                    wff_date: *wff_date,
                    absence_date: day_before,
                    absence_type: absence_type.clone(),
                });
            } else if let Some(absence_type) = absence_dates.get(&day_after) {
                deviations.push(TimeDeviation::AdjacentWffToAbsence {
                    wff_date: *wff_date,
                    absence_date: day_after,
                    absence_type: absence_type.clone(),
                });
            }
        }
        
        deviations
    }
    
    // Mark a week as complete for an employee
    pub fn mark_week_complete(&mut self, employee_id: &str, year: i32, week: i32) {
        let status = self.validate_week(employee_id, year, week);
        self.week_statuses.insert((employee_id.to_string(), year, week), status);
    }
    
    // Mark a month as complete for an employee
    pub  fn mark_month_complete(&mut self, employee_id: &str, year: i32, month: i32) {
        let status = self.validate_month(employee_id, year, month);
        self.month_statuses.insert((employee_id.to_string(), year, month), status);
    }
    
    // Validate all time registrations for a given week
    pub  fn validate_week(&self, employee_id: &str, year: i32, week: i32) -> WeekStatus {
        // In a real implementation, this would fetch all registrations for the week
        // and validate them against the rules
        // For now, we'll just return a placeholder status
        WeekStatus::Complete
    }
    
    // Validate all time registrations for a given month
    pub  fn validate_month(&self, employee_id: &str, year: i32, month: i32) -> MonthStatus {
        // Similar to validate_week, but for a full month
        MonthStatus::Complete
    }
    
    // Check if weeks need reminders
    pub   fn check_weekly_reminders(&self) {
        let today = Local::now().date_naive();
        let current_year = today.year();
        let current_week = today.iso_week().week() as i32;
        
        // If it's Monday, check if the previous week is complete
        if today.weekday() == Weekday::Mon {
            let prev_week = if current_week > 1 { current_week - 1 } else { 52 }; // Handle year wraparound
            let prev_year = if current_week > 1 { current_year } else { current_year - 1 };
            
            for (employee_id, _) in &self.employee_configs {
                let key = (employee_id.clone(), prev_year, prev_week);
                
                if !self.week_statuses.contains_key(&key) || 
                   matches!(self.week_statuses.get(&key), Some(WeekStatus::Incomplete)) {
                    // Send reminder
                    info!("REMINDER: {} needs to complete time reporting for week {} of {}", 
                          employee_id, prev_week, prev_year);
                }
            }
        }
    }
    
    // Check if months need reminders
    pub  fn check_monthly_reminders(&self) {
        let today = Local::now().date_naive();
        let current_year = today.year();
        let current_month = today.month() as i32;
        
        // Calculate previous month (for checking if it's complete)
        let (prev_month_year, prev_month) = if current_month > 1 {
            (current_year, current_month - 1)
        } else {
            (current_year - 1, 12)
        };
        
        // Check if we're within 7 days of the new month
        if today.day() <= 7 {
            for (employee_id, _) in &self.employee_configs {
                let key = (employee_id.clone(), prev_month_year, prev_month);
                
                if !self.month_statuses.contains_key(&key) || 
                   matches!(self.month_statuses.get(&key), Some(MonthStatus::Incomplete)) {
                    // Send reminder
                    info!("URGENT REMINDER: {} needs to complete time reporting for month {} of {} (affects payroll!)", 
                          employee_id, prev_month, prev_month_year);
                }
            }
        }
    }
    
    // Check for deviations and send notifications
    pub  fn check_deviations(&self) {
        for ((employee_id, year, week), status) in &self.week_statuses {
            if let WeekStatus::HasDeviations(deviations) = status {
                for deviation in deviations {
                    self.send_deviation_notification(employee_id, deviation);
                }
            }
        }
        
        for ((employee_id, year, month), status) in &self.month_statuses {
            if let MonthStatus::HasDeviations(deviations) = status {
                for deviation in deviations {
                    // For month deviations, also notify manager if it's past a certain point
                    self.send_deviation_notification(employee_id, deviation);
                    
                    // If we're more than a day past month completion, notify manager
                    let today = Local::now().date_naive();
                    let month_completion_deadline = NaiveDate::from_ymd_opt(*year, *month as u32, 7).unwrap();
                    if today > month_completion_deadline + Duration::days(1) {
                        self.notify_manager(employee_id, deviation);
                    }
                }
            }
        }
    }
    
    // Send a notification about a deviation
    fn send_deviation_notification(&self, employee_id: &str, deviation: &TimeDeviation) {
        match deviation {
            TimeDeviation::MissingMandatoryField { field, date } => {
                info!("NOTIFICATION to {}: Missing mandatory field '{}' for date {}", 
                      employee_id, field, date);
            },
            TimeDeviation::IncorrectWorkHours { date, scheduled, reported } => {
                info!("NOTIFICATION to {}: Incorrect work hours for date {}. Scheduled: {} hours, Reported: {} hours", 
                      employee_id, date, scheduled, reported);
            },
            TimeDeviation::MissingFlexTime { date, missing_hours } => {
                info!("NOTIFICATION to {}: Missing flex time+ for {} extra hours on {}", 
                      employee_id, missing_hours, date);
            },
            TimeDeviation::IncorrectProjectAllocation { date, message } => {
                info!("NOTIFICATION to {}: Incorrect project allocation on {}. {}", 
                      employee_id, date, message);
            },
            TimeDeviation::IncorrectAbsenceAllocation { date, project } => {
                let config = self.employee_configs.get(employee_id).unwrap();
                info!("NOTIFICATION to {}: Absence on {} should be allocated to your main project {} instead of {}", 
                      employee_id, date, config.main_project, project);
            },
            TimeDeviation::AdjacentWffToAbsence { wff_date, absence_date, absence_type } => {
                info!("NOTIFICATION to {}: Work Free Friday on {} is adjacent to {} absence on {}. The Friday should also be {} absence.", 
                      employee_id, wff_date, absence_type, absence_date, absence_type);
            },
        }
    }
    
    // Notify manager about persistent deviations
    pub  fn notify_manager(&self, employee_id: &str, deviation: &TimeDeviation) {
        // For now, assume managers are Tobias and Peter
        info!("MANAGER NOTIFICATION to Tobias and Peter: {} has unresolved time reporting issue that may affect payroll: {:?}", 
              employee_id, deviation);
    }
    
    // Run all checks (could be scheduled to run daily)
    pub  fn run_daily_checks(&mut self) {
        self.check_weekly_reminders();
        self.check_monthly_reminders();
        self.check_deviations();
    }
}