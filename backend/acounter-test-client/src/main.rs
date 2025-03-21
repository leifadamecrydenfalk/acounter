// src/main.rs

use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::error::Error;

// Response types
#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct UserProfile {
    id: String,
    email: String,
}

#[derive(Debug, Deserialize)]
struct ProtectedData {
    message: String,
    timestamp: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let base_url = "http://localhost:3000";
    let client = Client::new();
    
    // Test 1: Health check
    println!("\n🔍 Testing health check endpoint...");
    let health_response = client
        .get(format!("{}/health", base_url))
        .send()
        .await?
        .json::<HealthResponse>()
        .await?;
    
    println!("Health check response: {:?}", health_response);
    
    // Test 2: Public endpoint
    println!("\n🔍 Testing public endpoint...");
    let public_response = client
        .get(base_url)
        .send()
        .await?;
    
    println!("Public endpoint status: {}", public_response.status());
    println!("Public endpoint body: {}", public_response.text().await?);
    
    // Note: For the actual Google OAuth flow, the user would need to visit
    // the /auth/google endpoint in a browser and complete the authentication.
    // For testing purposes, we'll simulate having a valid token:
    
    println!("\n⚠️ OAuth flow testing:");
    println!("To test the complete OAuth flow:");
    println!("1. Open a browser and navigate to: {}/auth/google", base_url);
    println!("2. Complete the Google authentication");
    println!("3. Copy the token from the response");
    
    // Uncomment and replace with an actual token for API testing
    let token = prompt_for_token()?;
    
    if !token.is_empty() {
        // Test 3: User profile with token
        println!("\n🔍 Testing user profile endpoint with token...");
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION, 
            header::HeaderValue::from_str(&format!("Bearer {}", token))?
        );
        
        let profile_response = client
            .get(format!("{}/api/me", base_url))
            .headers(headers.clone())
            .send()
            .await?;
        
        println!("Profile response status: {}", profile_response.status());
        
        if profile_response.status().is_success() {
            let profile = profile_response.json::<UserProfile>().await?;
            println!("User profile: {:?}", profile);
        } else {
            println!("Failed to get profile: {}", profile_response.text().await?);
        }
        
        // Test 4: Protected data with token
        println!("\n🔍 Testing protected data endpoint with token...");
        let data_response = client
            .get(format!("{}/api/data", base_url))
            .headers(headers)
            .send()
            .await?;
        
        println!("Protected data response status: {}", data_response.status());
        
        if data_response.status().is_success() {
            let data = data_response.json::<ProtectedData>().await?;
            println!("Protected data: {:?}", data);
        } else {
            println!("Failed to get protected data: {}", data_response.text().await?);
        }
    }
    
    // Test 5: Rate limiting (optional)
    println!("\n🔍 Testing rate limiting...");
    println!("Sending 65 requests to trigger rate limit...");
    
    let mut success_count = 0;
    let mut failure_count = 0;
    
    for i in 1..=65 {
        let response = client
            .get(format!("{}/health", base_url))
            .send()
            .await?;
        
        if response.status().is_success() {
            success_count += 1;
        } else {
            failure_count += 1;
            println!("Request {} failed with status: {}", i, response.status());
        }
    }
    
    println!("Rate limit test results:");
    println!("  Successful requests: {}", success_count);
    println!("  Failed requests (rate limited): {}", failure_count);
    
    println!("\n✅ Testing complete!");
    
    Ok(())
}

fn prompt_for_token() -> Result<String, Box<dyn Error>> {
    println!("Enter JWT token (press Enter to skip token-based tests):");
    let mut token = String::new();
    std::io::stdin().read_line(&mut token)?;
    Ok(token.trim().to_string())
}