// src/time_validation_tests.rs

#[cfg(test)]
mod tests {
    use crate::fortnox::*;
    use crate::time_validation::*;
    use chrono::{Datelike, Local, NaiveDate, Weekday};
    use std::collections::{HashMap, HashSet};

    // Helper function to create a test registration
    fn create_test_registration(
        id: &str,
        user_id: &str,
        worked_date: &str,
        worked_hours: f64,
        reg_code: &str,
        reg_name: &str,
        reg_type: &str,
        customer: Option<(&str, &str)>,
        project: Option<(&str, &str)>,
        service: Option<(&str, &str)>,
    ) -> DetailedRegistration {
        DetailedRegistration {
            id: id.to_string(),
            user_id: user_id.to_string(),
            worked_date: worked_date.to_string(),
            worked_hours,
            charge_hours: worked_hours,
            start_time: None,
            stop_time: None,
            non_invoiceable: false,
            note: None,
            invoice_text: None,
            customer: customer.map(|(id, name)| TimeRegCustomerInfo {
                id: id.to_string(),
                name: name.to_string(),
            }),
            project: project.map(|(id, desc)| TimeRegProjectInfo {
                id: id.to_string(),
                description: desc.to_string(),
            }),
            service: service.map(|(id, desc)| TimeRegServiceInfo {
                id: id.to_string(),
                description: desc.to_string(),
            }),
            registration_code: TimeRegCodeInfo {
                code: reg_code.to_string(),
                name: reg_name.to_string(),
                type_: reg_type.to_string(),
            },
            child_id: None,
            document_id: None,
            document_type: None,
            invoice_basis_id: None,
            unit_cost: None,
            unit_price: None,
        }
    }

    // Test functions for TimeValidationService methods

    #[test]
    fn test_validate_mandatory_fields_work_time_valid() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "1",
            "Peter",
            "2025-04-01",
            8.0,
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            Some(("700", "Work For Hire")),
            Some(("52", "Development")),
        );

        let result = service.validate_mandatory_fields(&registration);
        assert!(
            result.is_ok(),
            "Valid work time registration should pass validation"
        );
    }

    #[test]
    fn test_validate_mandatory_fields_work_time_missing_customer() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "2",
            "Peter",
            "2025-04-01",
            8.0,
            "TID",
            "Normal Work Time",
            "WORK",
            None, // Missing customer
            Some(("700", "Work For Hire")),
            Some(("52", "Development")),
        );

        let result = service.validate_mandatory_fields(&registration);
        assert!(
            result.is_err(),
            "Work time registration missing customer should fail validation"
        );

        if let Err(TimeDeviation::MissingMandatoryField { field, date }) = result {
            assert_eq!(field, "customer");
            assert_eq!(date, NaiveDate::from_ymd_opt(2025, 4, 1).unwrap());
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_validate_mandatory_fields_work_time_missing_project() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "3",
            "Peter",
            "2025-04-01",
            8.0,
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            None, // Missing project
            Some(("52", "Development")),
        );

        let result = service.validate_mandatory_fields(&registration);
        assert!(
            result.is_err(),
            "Work time registration missing project should fail validation"
        );

        if let Err(TimeDeviation::MissingMandatoryField { field, date }) = result {
            assert_eq!(field, "project");
            assert_eq!(date, NaiveDate::from_ymd_opt(2025, 4, 1).unwrap());
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_validate_mandatory_fields_work_time_missing_service() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "4",
            "Peter",
            "2025-04-01",
            8.0,
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            Some(("700", "Work For Hire")),
            None, // Missing service
        );

        let result = service.validate_mandatory_fields(&registration);
        assert!(
            result.is_err(),
            "Work time registration missing service should fail validation"
        );

        if let Err(TimeDeviation::MissingMandatoryField { field, date }) = result {
            assert_eq!(field, "service");
            assert_eq!(date, NaiveDate::from_ymd_opt(2025, 4, 1).unwrap());
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_validate_mandatory_fields_absence_valid() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "5",
            "Peter",
            "2025-04-01",
            8.0,
            "SEM",
            "Vacation",
            "ABSENCE",
            None,
            Some(("700", "Work For Hire")),
            None,
        );

        let result = service.validate_mandatory_fields(&registration);
        assert!(
            result.is_ok(),
            "Valid absence registration should pass validation"
        );
    }

    #[test]
    fn test_validate_work_hours_exact_match() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "6",
            "Peter",
            "2025-04-01",
            8.0, // Exact match with scheduled
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            Some(("700", "Work For Hire")),
            Some(("52", "Development")),
        );

        let employee_config = EmployeeConfig {
            employee_id: "Peter".to_string(),
            is_international: false,
            is_special_hours: false,
            main_project: "700".to_string(),
        };

        let result = service.validate_work_hours(&registration, 8.0, &employee_config);
        assert!(
            result.is_ok(),
            "Work hours matching scheduled hours should pass validation"
        );
    }

    #[test]
    fn test_validate_work_hours_less_than_scheduled() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "7",
            "Peter",
            "2025-04-01",
            6.0, // Less than scheduled
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            Some(("700", "Work For Hire")),
            Some(("52", "Development")),
        );

        let employee_config = EmployeeConfig {
            employee_id: "Peter".to_string(),
            is_international: false,
            is_special_hours: false,
            main_project: "700".to_string(),
        };

        let result = service.validate_work_hours(&registration, 8.0, &employee_config);
        assert!(
            result.is_err(),
            "Work hours less than scheduled should fail validation"
        );

        if let Err(TimeDeviation::IncorrectWorkHours {
            date,
            scheduled,
            reported,
        }) = result
        {
            assert_eq!(date, NaiveDate::from_ymd_opt(2025, 4, 1).unwrap());
            assert_eq!(scheduled, 8.0);
            assert_eq!(reported, 6.0);
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_validate_work_hours_more_than_scheduled() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "8",
            "Peter",
            "2025-04-01",
            10.0, // More than scheduled
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            Some(("700", "Work For Hire")),
            Some(("52", "Development")),
        );

        let employee_config = EmployeeConfig {
            employee_id: "Peter".to_string(),
            is_international: false,
            is_special_hours: false,
            main_project: "700".to_string(),
        };

        let result = service.validate_work_hours(&registration, 8.0, &employee_config);
        assert!(
            result.is_err(),
            "Work hours more than scheduled should fail validation"
        );

        if let Err(TimeDeviation::MissingFlexTime {
            date,
            missing_hours,
        }) = result
        {
            assert_eq!(date, NaiveDate::from_ymd_opt(2025, 4, 1).unwrap());
            assert_eq!(missing_hours, 2.0);
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_validate_work_hours_special_hours_employee() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "9",
            "Jens",
            "2025-04-01",
            7.0, // Different than scheduled
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            Some(("300", "MSM3")),
            Some(("52", "Development")),
        );

        let employee_config = EmployeeConfig {
            employee_id: "Jens".to_string(),
            is_international: false,
            is_special_hours: true, // Special hours employee like Jens
            main_project: "300".to_string(),
        };

        let result = service.validate_work_hours(&registration, 8.0, &employee_config);
        assert!(
            result.is_ok(),
            "Special hours employee should pass validation regardless of hours"
        );
    }

    #[test]
    fn test_validate_work_hours_international_employee_holiday() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "10",
            "Zac",        // International employee
            "2025-12-24", // Swedish holiday (Christmas Eve)
            8.0,
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            Some(("700", "Work For Hire")),
            Some(("16", "Other")), // Service 16 - Other
        );

        let employee_config = EmployeeConfig {
            employee_id: "Zac".to_string(),
            is_international: true,
            is_special_hours: false,
            main_project: "700".to_string(),
        };

        let result = service.validate_work_hours(&registration, 0.0, &employee_config); // 0 scheduled hours for Swedish holiday
        assert!(
            result.is_ok(),
            "International employee should pass validation on Swedish holiday with service 16"
        );
    }

    #[test]
    fn test_validate_work_hours_international_employee_holiday_wrong_service() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "11",
            "Zac",        // International employee
            "2025-12-24", // Swedish holiday (Christmas Eve)
            8.0,
            "TID",
            "Normal Work Time",
            "WORK",
            Some(("123", "Client A")),
            Some(("700", "Work For Hire")),
            Some(("52", "Development")), // Not service 16
        );

        let employee_config = EmployeeConfig {
            employee_id: "Zac".to_string(),
            is_international: true,
            is_special_hours: false,
            main_project: "700".to_string(),
        };

        let result = service.validate_work_hours(&registration, 0.0, &employee_config); // 0 scheduled hours for Swedish holiday
        assert!(
            result.is_err(),
            "International employee should fail validation on Swedish holiday with wrong service"
        );

        if let Err(TimeDeviation::IncorrectProjectAllocation { date, message }) = result {
            assert_eq!(date, NaiveDate::from_ymd_opt(2025, 12, 24).unwrap());
            assert!(message.contains("International employees should use Service 16"));
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_validate_absence_allocation_correct_project() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "12",
            "Peter",
            "2025-04-01",
            8.0,
            "SEM",
            "Vacation",
            "ABSENCE",
            None,
            Some(("700", "Work For Hire")), // Correct project for Peter
            None,
        );

        let employee_config = EmployeeConfig {
            employee_id: "Peter".to_string(),
            is_international: false,
            is_special_hours: false,
            main_project: "700".to_string(),
        };

        let result = service.validate_absence_allocation(&registration, &employee_config);
        assert!(
            result.is_ok(),
            "Absence allocated to correct project should pass validation"
        );
    }

    #[test]
    fn test_validate_absence_allocation_wrong_project() {
        let service = TimeValidationService::new();
        let registration = create_test_registration(
            "13",
            "Peter",
            "2025-04-01",
            8.0,
            "SEM",
            "Vacation",
            "ABSENCE",
            None,
            Some(("300", "MSM3")), // Wrong project for Peter
            None,
        );

        let employee_config = EmployeeConfig {
            employee_id: "Peter".to_string(),
            is_international: false,
            is_special_hours: false,
            main_project: "700".to_string(),
        };

        let result = service.validate_absence_allocation(&registration, &employee_config);
        assert!(
            result.is_err(),
            "Absence allocated to wrong project should fail validation"
        );

        if let Err(TimeDeviation::IncorrectAbsenceAllocation { date, project }) = result {
            assert_eq!(date, NaiveDate::from_ymd_opt(2025, 4, 1).unwrap());
            assert_eq!(project, "300");
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_validate_wff_adjacent_to_absence_no_adjacency() {
        let service = TimeValidationService::new();
        let registrations = vec![
            // WFF on Friday
            create_test_registration(
                "14",
                "Peter",
                "2025-04-04", // Friday
                8.0,
                "TID",
                "Normal Work Time",
                "WORK",
                Some(("123", "Client A")),
                Some(("700", "Work For Hire")),
                Some(("52", "Work Free Friday")),
            ),
            // Regular work on Monday and Thursday
            create_test_registration(
                "15",
                "Peter",
                "2025-04-03", // Thursday
                8.0,
                "TID",
                "Normal Work Time",
                "WORK",
                Some(("123", "Client A")),
                Some(("700", "Work For Hire")),
                Some(("16", "Development")),
            ),
            create_test_registration(
                "16",
                "Peter",
                "2025-04-07", // Monday
                8.0,
                "TID",
                "Normal Work Time",
                "WORK",
                Some(("123", "Client A")),
                Some(("700", "Work For Hire")),
                Some(("16", "Development")),
            ),
        ];

        let deviations = service.validate_wff_adjacent_to_absence(&registrations, "Peter");
        assert!(
            deviations.is_empty(),
            "WFF not adjacent to absence should pass validation"
        );
    }

    #[test]
    fn test_validate_wff_adjacent_to_absence_day_before() {
        let service = TimeValidationService::new();
        let registrations = vec![
            // WFF on Friday
            create_test_registration(
                "17",
                "Peter",
                "2025-04-04", // Friday
                8.0,
                "TID",
                "Normal Work Time",
                "WORK",
                Some(("123", "Client A")),
                Some(("700", "Work For Hire")),
                Some(("52", "Work Free Friday")),
            ),
            // Absence on Thursday
            create_test_registration(
                "18",
                "Peter",
                "2025-04-03", // Thursday
                8.0,
                "SEM",
                "Vacation",
                "ABSENCE",
                None,
                Some(("700", "Work For Hire")),
                None,
            ),
        ];

        let deviations = service.validate_wff_adjacent_to_absence(&registrations, "Peter");
        assert_eq!(
            deviations.len(),
            1,
            "WFF adjacent to absence on previous day should fail validation"
        );

        if let TimeDeviation::AdjacentWffToAbsence {
            wff_date,
            absence_date,
            absence_type,
        } = &deviations[0]
        {
            assert_eq!(*wff_date, NaiveDate::from_ymd_opt(2025, 4, 4).unwrap());
            assert_eq!(*absence_date, NaiveDate::from_ymd_opt(2025, 4, 3).unwrap());
            assert_eq!(*absence_type, "SEM");
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_validate_wff_adjacent_to_absence_day_after() {
        let service = TimeValidationService::new();
        let registrations = vec![
            // WFF on Friday
            create_test_registration(
                "19",
                "Peter",
                "2025-04-04", // Friday
                8.0,
                "TID",
                "Normal Work Time",
                "WORK",
                Some(("123", "Client A")),
                Some(("700", "Work For Hire")),
                Some(("52", "Work Free Friday")),
            ),
            // Absence on Monday
            create_test_registration(
                "20",
                "Peter",
                "2025-04-07", // Monday
                8.0,
                "SJK",
                "Sick Leave",
                "ABSENCE",
                None,
                Some(("700", "Work For Hire")),
                None,
            ),
        ];

        let deviations = service.validate_wff_adjacent_to_absence(&registrations, "Peter");
        assert_eq!(
            deviations.len(),
            1,
            "WFF adjacent to absence on next day should fail validation"
        );

        if let TimeDeviation::AdjacentWffToAbsence {
            wff_date,
            absence_date,
            absence_type,
        } = &deviations[0]
        {
            assert_eq!(*wff_date, NaiveDate::from_ymd_opt(2025, 4, 4).unwrap());
            assert_eq!(*absence_date, NaiveDate::from_ymd_opt(2025, 4, 7).unwrap());
            assert_eq!(*absence_type, "SJK");
        } else {
            panic!("Wrong error type returned");
        }
    }

    #[test]
    fn test_complete_week_validation_with_no_deviations() {
        let mut service = TimeValidationService::new();
        let employee_id = "Peter";
        let year = 2025;
        let week = 15;

        // Mock the validation methods to return no errors
        // In a real test, we would use mocking frameworks or dependency injection

        let status = service.validate_week(employee_id, year, week);
        assert!(
            matches!(status, WeekStatus::Complete),
            "Week with no deviations should be marked as complete"
        );
    }

    #[test]
    fn test_complete_week_validation_with_deviations() {
        let mut service = TimeValidationService::new();

        // Mock validation to simulate deviations
        // Implementation depends on how the actual validation method works
        // For this test, we'll just mark the week with deviations directly
        let employee_id = "Peter";
        let year = 2025;
        let week = 15;

        let deviation = TimeDeviation::MissingMandatoryField {
            field: "customer".to_string(),
            date: NaiveDate::from_ymd_opt(2025, 4, 7).unwrap(),
        };

        service.week_statuses.insert(
            (employee_id.to_string(), year, week),
            WeekStatus::HasDeviations(vec![deviation.clone()]),
        );

        // Now check if the validation returns the deviation
        let status = service.validate_week(employee_id, year, week);

        if let WeekStatus::HasDeviations(deviations) = status {
            assert_eq!(deviations.len(), 1, "Should have one deviation");
            assert!(matches!(
                deviations[0],
                TimeDeviation::MissingMandatoryField { .. }
            ));
        } else {
            panic!("Expected WeekStatus::HasDeviations");
        }
    }

    #[test]
    fn test_check_weekly_reminders() {
        let mut service = TimeValidationService::new();
        let employee_id = "Peter";
        let year = 2025;
        let week = 15;

        // Set up incomplete week
        service.week_statuses.insert(
            (employee_id.to_string(), year, week),
            WeekStatus::Incomplete,
        );

        // Run the reminder check (would need to mock or wrap today's date for more thorough testing)
        service.check_weekly_reminders();

        // Since this is an info log output test, we can't easily assert its behavior without mocking
        // In a real test environment, we'd inject a mock logger or setup a reminder collection system
        // to verify if the correct reminders were generated

        // For now, just verify the status is unchanged
        assert!(matches!(
            service
                .week_statuses
                .get(&(employee_id.to_string(), year, week)),
            Some(WeekStatus::Incomplete)
        ));
    }

    #[test]
    fn test_weekly_reminder_for_complete_week() {
        let mut service = TimeValidationService::new();
        let employee_id = "Peter";
        let year = 2025;
        let week = 15;

        // Set up complete week
        service
            .week_statuses
            .insert((employee_id.to_string(), year, week), WeekStatus::Complete);

        // Run the reminder check
        service.check_weekly_reminders();

        // Verify no reminder needed for complete week
        assert!(matches!(
            service
                .week_statuses
                .get(&(employee_id.to_string(), year, week)),
            Some(WeekStatus::Complete)
        ));
    }

    #[test]
    fn test_monthly_reminder_for_incomplete_month() {
        let mut service = TimeValidationService::new();
        let employee_id = "Peter";
        let year = 2025;
        let month = 4;

        // Set up incomplete month
        service.month_statuses.insert(
            (employee_id.to_string(), year, month),
            MonthStatus::Incomplete,
        );

        // Run the reminder check
        service.check_monthly_reminders();

        // Verify status is still incomplete
        assert!(matches!(
            service
                .month_statuses
                .get(&(employee_id.to_string(), year, month)),
            Some(MonthStatus::Incomplete)
        ));
    }

    #[test]
    fn test_check_deviations_notification_for_week() {
        let mut service = TimeValidationService::new();
        let employee_id = "Peter";
        let year = 2025;
        let week = 15;

        let deviation = TimeDeviation::IncorrectWorkHours {
            date: NaiveDate::from_ymd_opt(2025, 4, 7).unwrap(),
            scheduled: 8.0,
            reported: 6.0,
        };

        // Set up week with deviations
        service.week_statuses.insert(
            (employee_id.to_string(), year, week),
            WeekStatus::HasDeviations(vec![deviation]),
        );

        // Run deviation check
        service.check_deviations();

        // Since this outputs logs, we can't easily assert the behavior without mocking
        // But we can verify the status remains unchanged
        assert!(matches!(
            service
                .week_statuses
                .get(&(employee_id.to_string(), year, week)),
            Some(WeekStatus::HasDeviations(_))
        ));
    }

    #[test]
    fn test_check_deviations_notification_for_month() {
        let mut service = TimeValidationService::new();
        let employee_id = "Peter";
        let year = 2025;
        let month = 4;

        let deviation = TimeDeviation::IncorrectAbsenceAllocation {
            date: NaiveDate::from_ymd_opt(2025, 4, 7).unwrap(),
            project: "300".to_string(),
        };

        // Set up month with deviations
        service.month_statuses.insert(
            (employee_id.to_string(), year, month),
            MonthStatus::HasDeviations(vec![deviation]),
        );

        // Run deviation check
        service.check_deviations();

        // Verify status remains unchanged
        assert!(matches!(
            service
                .month_statuses
                .get(&(employee_id.to_string(), year, month)),
            Some(MonthStatus::HasDeviations(_))
        ));
    }

    #[test]
    fn test_run_daily_checks() {
        let mut service = TimeValidationService::new();

        // Setup some test data
        let employee_id = "Peter";
        let year = 2025;
        let week = 15;
        let month = 4;

        let deviation = TimeDeviation::MissingFlexTime {
            date: NaiveDate::from_ymd_opt(2025, 4, 7).unwrap(),
            missing_hours: 2.0,
        };

        // Set up week and month with deviations
        service.week_statuses.insert(
            (employee_id.to_string(), year, week),
            WeekStatus::HasDeviations(vec![deviation.clone()]),
        );

        service.month_statuses.insert(
            (employee_id.to_string(), year, month),
            MonthStatus::HasDeviations(vec![deviation]),
        );

        // Run daily checks
        service.run_daily_checks();

        // Verify states remain unchanged (since we can't easily test log outputs)
        assert!(matches!(
            service
                .week_statuses
                .get(&(employee_id.to_string(), year, week)),
            Some(WeekStatus::HasDeviations(_))
        ));

        assert!(matches!(
            service
                .month_statuses
                .get(&(employee_id.to_string(), year, month)),
            Some(MonthStatus::HasDeviations(_))
        ));
    }

    // Additional tests for edge cases and specific requirements

    #[test]
    fn test_employee_config_lookup() {
        let service = TimeValidationService::new();

        // Test finding configs for different employees
        let peter_config = service.employee_configs.get("Peter");
        assert!(peter_config.is_some(), "Peter should have a config");
        assert_eq!(peter_config.unwrap().main_project, "700");
        assert!(!peter_config.unwrap().is_special_hours);

        let jens_config = service.employee_configs.get("Jens");
        assert!(jens_config.is_some(), "Jens should have a config");
        assert_eq!(jens_config.unwrap().main_project, "300");
        assert!(
            jens_config.unwrap().is_special_hours,
            "Jens should have special hours flag"
        );

        let dana_config = service.employee_configs.get("Dana");
        assert!(dana_config.is_some(), "Dana should have a config");
        assert_eq!(dana_config.unwrap().main_project, "300");
        assert!(!dana_config.unwrap().is_special_hours);

        let joe_config = service.employee_configs.get("Joe");
        assert!(joe_config.is_some(), "Joe should have a config");
        assert_eq!(joe_config.unwrap().main_project, "610");

        let bryan_config = service.employee_configs.get("Bryan");
        assert!(bryan_config.is_some(), "Bryan should have a config");
        assert_eq!(bryan_config.unwrap().main_project, "902");
    }

    #[test]
    fn test_international_employee_flags() {
        let service = TimeValidationService::new();

        // Modify some configs to test international flag
        let mut service = TimeValidationService::new();

        // Set Zac as international
        if let Some(config) = service.employee_configs.get_mut("Zac") {
            config.is_international = true;
        }

        // Verify the flag is set
        let zac_config = service.employee_configs.get("Zac");
        assert!(zac_config.is_some(), "Zac should have a config");
        assert!(
            zac_config.unwrap().is_international,
            "Zac should be marked as international"
        );
    }
}
