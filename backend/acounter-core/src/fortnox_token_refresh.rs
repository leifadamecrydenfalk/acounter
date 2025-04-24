use crate::{convert_fortnox_error, FortnoxClient};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info}; // No need for target here

pub async fn run_fortnox_token_refresh(refresh_client: Arc<FortnoxClient>) {
    // The target will automatically be "acounter_core::background::token_refresh"
    // (or whatever your crate name is instead of acounter_core)
    info!("Starting background token refresh task");
    const CHECK_INTERVAL_SECS_DEFAULT: u64 = 300;
    let mut check_interval_secs = CHECK_INTERVAL_SECS_DEFAULT;

    loop {
        match refresh_client.get_token_status().await {
            Ok(status) => {
                if status.has_token {
                    if !status.is_valid || status.expires_in_secs < 600 {
                        info!(
                            "Token is invalid or expires soon (in {} seconds). Attempting refresh...",
                            status.expires_in_secs
                        );
                        match refresh_client.get_valid_access_token().await {
                            Ok(_) => info!("Token refreshed successfully"),
                            Err(e) => {
                                error!("Failed to refresh token: {}", convert_fortnox_error(e));
                                check_interval_secs = CHECK_INTERVAL_SECS_DEFAULT;
                            }
                        }
                    } else {
                        check_interval_secs = status.expires_in_secs + 10;
                        info!("Token is valid for {} more seconds", status.expires_in_secs);
                    }
                } else {
                    info!("No token available. Waiting for user authentication.");
                }
            }
            Err(e) => {
                error!("Failed to check token status: {}", e);
                check_interval_secs = CHECK_INTERVAL_SECS_DEFAULT;
            }
        }
        sleep(Duration::from_secs(check_interval_secs)).await;
    }
}
