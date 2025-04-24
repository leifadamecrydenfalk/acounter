// src/fortnox_tests.rs

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use tokio::runtime::Runtime;

    use super::super::fortnox::{AuthCallbackParams, FortnoxClient, FortnoxConfig, FortnoxError};

    // Helper function to get test-specific paths
    fn get_test_paths(test_name: &str) -> (String, String) {
        let token_path = format!("./test_fortnox_token_{}.json", test_name);
        let cache_dir = format!("./test_fortnox_cache_{}", test_name);
        (token_path, cache_dir)
    }

    // Clean up test files before and after tests
    fn setup(test_name: &str) {
        teardown(test_name); // Clean any previous test data first
        let (_, cache_dir) = get_test_paths(test_name);
        fs::create_dir_all(&cache_dir).unwrap();
    }

    fn teardown(test_name: &str) {
        let (token_path, cache_dir) = get_test_paths(test_name);
        let _ = fs::remove_file(&token_path);
        let _ = fs::remove_dir_all(&cache_dir);
    }

    // Helper function to create a test client
    fn create_test_client(test_name: &str) -> FortnoxClient {
        let (token_path, cache_dir) = get_test_paths(test_name);

        let config = FortnoxConfig {
            client_id: env::var("FORTNOX_CLIENT_ID")
                .unwrap_or_else(|_| "test_client_id".to_string()),
            client_secret: env::var("FORTNOX_CLIENT_SECRET")
                .unwrap_or_else(|_| "test_client_secret".to_string()),
            redirect_uri: env::var("FORTNOX_REDIRECT_URI")
                .unwrap_or_else(|_| "https://localhost:3000/api/fortnox/auth/callback".to_string()),
            scopes: env::var("FORTNOX_SCOPES")
                .unwrap_or_else(|_| "companyinformation timeregistration".to_string()),
            token_file_path: PathBuf::from(token_path),
            cache_dir: PathBuf::from(cache_dir),
            cache_duration_secs: 60, // Short duration for tests
        };

        FortnoxClient::new(config).expect("Failed to create test client")
    }

    #[test]
    fn test_generate_auth_url() {
        let test_name = "generate_auth_url";
        setup(test_name);

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        let result = rt.block_on(async { client.generate_auth_url().await });

        assert!(
            result.is_ok(),
            "Failed to generate auth URL: {:?}",
            result.err()
        );
        let url = result.unwrap();
        assert!(
            url.starts_with("https://apps.fortnox.se/oauth-v1/auth"),
            "URL doesn't start with expected base"
        );
        assert!(url.contains("client_id="), "URL missing client_id");
        assert!(url.contains("scope="), "URL missing scope");
        assert!(url.contains("state="), "URL missing state");

        teardown(test_name);
    }

    #[test]
    fn test_auth_callback_state_mismatch() {
        let test_name = "auth_callback_state_mismatch";
        setup(test_name);

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        // Generate an auth URL to set the state
        let _ = rt.block_on(async { client.generate_auth_url().await });

        // Try with a different state
        let params = AuthCallbackParams {
            code: Some("test_code".to_string()),
            state: Some("invalid_state".to_string()),
            error: None,
            error_description: None,
        };

        let result = rt.block_on(async { client.handle_auth_callback(params).await });

        assert!(result.is_err(), "Expected error but got success");
        match result {
            Err(FortnoxError::OAuthStateMismatch) => (),
            _ => panic!("Expected OAuthStateMismatch error but got: {:?}", result),
        }

        teardown(test_name);
    }

    #[test]
    fn test_auth_callback_missing_code() {
        let test_name = "auth_callback_missing_code";
        setup(test_name);

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        // Generate an auth URL to set the state
        let auth_url = rt
            .block_on(async { client.generate_auth_url().await })
            .unwrap();

        // Extract the state from the URL
        let url_parts: Vec<&str> = auth_url.split("state=").collect();
        let state_with_more: Vec<&str> = url_parts[1].split('&').collect();
        let state = state_with_more[0];

        // Try with a missing code
        let params = AuthCallbackParams {
            code: None,
            state: Some(state.to_string()),
            error: None,
            error_description: None,
        };

        let result = rt.block_on(async { client.handle_auth_callback(params).await });

        assert!(result.is_err(), "Expected error but got success");
        match result {
            Err(FortnoxError::MissingAuthCode) => (),
            _ => panic!("Expected MissingAuthCode error but got: {:?}", result),
        }

        teardown(test_name);
    }

    #[test]
    fn test_auth_callback_with_error() {
        let test_name = "auth_callback_with_error";
        setup(test_name);

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        // Generate an auth URL to set the state
        let auth_url = rt
            .block_on(async { client.generate_auth_url().await })
            .unwrap();

        // Extract the state from the URL
        let url_parts: Vec<&str> = auth_url.split("state=").collect();
        let state_with_more: Vec<&str> = url_parts[1].split('&').collect();
        let state = state_with_more[0];

        // Try with an error from Fortnox
        let params = AuthCallbackParams {
            code: None,
            state: Some(state.to_string()),
            error: Some("access_denied".to_string()),
            error_description: Some("User denied access".to_string()),
        };

        let result = rt.block_on(async { client.handle_auth_callback(params).await });

        assert!(result.is_err(), "Expected error but got success");
        match result {
            Err(FortnoxError::ApiError { .. }) => (),
            _ => panic!("Expected ApiError but got: {:?}", result),
        }

        teardown(test_name);
    }

    // Tests below require a valid token. They'll be skipped if FORTNOX_RUN_API_TESTS=1 is not set

    #[test]
    fn test_get_token_status() {
        let test_name = "get_token_status";
        setup(test_name);

        if env::var("FORTNOX_RUN_API_TESTS").unwrap_or_default() != "1" {
            println!("Skipping API test. Set FORTNOX_RUN_API_TESTS=1 to run.");
            teardown(test_name);
            return;
        }

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        let status = rt
            .block_on(async { client.get_token_status().await })
            .unwrap();

        // We can only verify the structure returned, not specific values
        println!("Token status: {:?}", status);

        teardown(test_name);
    }

    #[test]
    fn test_get_employees() {
        let test_name = "get_employees";
        setup(test_name);

        if env::var("FORTNOX_RUN_API_TESTS").unwrap_or_default() != "1" {
            println!("Skipping API test. Set FORTNOX_RUN_API_TESTS=1 to run.");
            teardown(test_name);
            return;
        }

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        let result = rt.block_on(async { client.get_employees().await });

        match result {
            Ok(response) => {
                println!("Found {} employees", response.employees.len());
                // Don't assume there are employees - test might run on a new account
            }
            Err(e) => {
                if let FortnoxError::MissingToken = e {
                    println!("Test requires authentication. Please authenticate first.");
                } else {
                    panic!("API test failed: {:?}", e);
                }
            }
        }

        teardown(test_name);
    }

    #[test]
    fn test_get_employee() {
        let test_name = "get_employee";
        setup(test_name);

        if env::var("FORTNOX_RUN_API_TESTS").unwrap_or_default() != "1" {
            println!("Skipping API test. Set FORTNOX_RUN_API_TESTS=1 to run.");
            teardown(test_name);
            return;
        }

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        // First get all employees
        let employees = match rt.block_on(async { client.get_employees().await }) {
            Ok(resp) => resp.employees,
            Err(e) => {
                if let FortnoxError::MissingToken = e {
                    println!("Test requires authentication. Please authenticate first.");
                    teardown(test_name);
                    return;
                } else {
                    panic!("Failed to get employees: {:?}", e);
                }
            }
        };

        if employees.is_empty() {
            println!("No employees found to test with");
            teardown(test_name);
            return;
        }

        // Now test get_employee with the first employee's ID
        let employee_id = &employees[0].employee_id;
        let result = rt.block_on(async { client.get_employee(employee_id).await });

        match result {
            Ok(employee) => {
                assert_eq!(employee.employee_id, *employee_id, "Employee ID mismatch");
                println!("Got employee: {:?}", employee);
            }
            Err(e) => panic!("Failed to get employee: {:?}", e),
        }

        teardown(test_name);
    }

    #[test]
    fn test_get_customers() {
        let test_name = "get_customers";
        setup(test_name);

        if env::var("FORTNOX_RUN_API_TESTS").unwrap_or_default() != "1" {
            println!("Skipping API test. Set FORTNOX_RUN_API_TESTS=1 to run.");
            teardown(test_name);
            return;
        }

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        let result = rt.block_on(async { client.get_customers().await });

        match result {
            Ok(response) => {
                println!("Found {} customers", response.customers.len());
            }
            Err(e) => {
                if let FortnoxError::MissingToken = e {
                    println!("Test requires authentication. Please authenticate first.");
                } else {
                    panic!("API test failed: {:?}", e);
                }
            }
        }

        teardown(test_name);
    }

    #[test]
    fn test_get_customer() {
        let test_name = "get_customer";
        setup(test_name);

        if env::var("FORTNOX_RUN_API_TESTS").unwrap_or_default() != "1" {
            println!("Skipping API test. Set FORTNOX_RUN_API_TESTS=1 to run.");
            teardown(test_name);
            return;
        }

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        // First get all customers
        let customers = match rt.block_on(async { client.get_customers().await }) {
            Ok(resp) => resp.customers,
            Err(e) => {
                if let FortnoxError::MissingToken = e {
                    println!("Test requires authentication. Please authenticate first.");
                    teardown(test_name);
                    return;
                } else {
                    panic!("Failed to get customers: {:?}", e);
                }
            }
        };

        if customers.is_empty() {
            println!("No customers found to test with");
            teardown(test_name);
            return;
        }

        // Now test get_customer with the first customer's number
        let customer_id = &customers[0].customer_number;
        let result = rt.block_on(async { client.get_customer(customer_id).await });

        match result {
            Ok(customer) => {
                assert_eq!(
                    customer.customer_number, *customer_id,
                    "Customer number mismatch"
                );
                println!("Got customer: {:?}", customer);
            }
            Err(e) => panic!("Failed to get customer: {:?}", e),
        }

        teardown(test_name);
    }

    #[test]
    fn test_get_projects() {
        let test_name = "get_projects";
        setup(test_name);

        if env::var("FORTNOX_RUN_API_TESTS").unwrap_or_default() != "1" {
            println!("Skipping API test. Set FORTNOX_RUN_API_TESTS=1 to run.");
            teardown(test_name);
            return;
        }

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        let result = rt.block_on(async { client.get_projects().await });

        match result {
            Ok(response) => {
                println!("Found {} projects", response.projects.len());
            }
            Err(e) => {
                if let FortnoxError::MissingToken = e {
                    println!("Test requires authentication. Please authenticate first.");
                } else {
                    panic!("API test failed: {:?}", e);
                }
            }
        }

        teardown(test_name);
    }

    #[test]
    fn test_get_project() {
        let test_name = "get_project";
        setup(test_name);

        if env::var("FORTNOX_RUN_API_TESTS").unwrap_or_default() != "1" {
            println!("Skipping API test. Set FORTNOX_RUN_API_TESTS=1 to run.");
            teardown(test_name);
            return;
        }

        let rt = Runtime::new().unwrap();
        let client = create_test_client(test_name);

        // First get all projects
        let projects = match rt.block_on(async { client.get_projects().await }) {
            Ok(resp) => resp.projects,
            Err(e) => {
                if let FortnoxError::MissingToken = e {
                    println!("Test requires authentication. Please authenticate first.");
                    teardown(test_name);
                    return;
                } else {
                    panic!("Failed to get projects: {:?}", e);
                }
            }
        };

        if projects.is_empty() {
            println!("No projects found to test with");
            teardown(test_name);
            return;
        }

        // Now test get_project with the first project's number
        let project_id = &projects[0].project_number;
        let result = rt.block_on(async { client.get_project(project_id).await });

        match result {
            Ok(project) => {
                assert_eq!(
                    project.project_number, *project_id,
                    "Project number mismatch"
                );
                println!("Got project: {:?}", project);
            }
            Err(e) => panic!("Failed to get project: {:?}", e),
        }

        teardown(test_name);
    }
}
