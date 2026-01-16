//! Retry logic for network operations with exponential backoff.

use crate::core::error::{Error, Result};
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_attempts: u32,
    /// Initial delay between retries.
    pub initial_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Multiplier for exponential backoff.
    pub backoff_multiplier: f64,
    /// Whether to add jitter to delays.
    pub add_jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            add_jitter: true,
        }
    }
}

impl RetryConfig {
    /// Create a config with custom max attempts.
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Create a config with custom initial delay.
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Create a config for quick retries (shorter delays).
    pub fn quick() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
            backoff_multiplier: 2.0,
            add_jitter: true,
        }
    }

    /// Create a config for network operations (longer delays).
    pub fn network() -> Self {
        Self {
            max_attempts: 4,
            initial_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            add_jitter: true,
        }
    }

    /// Calculate the delay for a given attempt number.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base_delay = self.initial_delay.as_secs_f64()
            * self.backoff_multiplier.powi(attempt.saturating_sub(1) as i32);

        let delay_secs = base_delay.min(self.max_delay.as_secs_f64());

        let final_delay = if self.add_jitter {
            // Add up to 25% jitter
            let jitter = delay_secs * 0.25 * rand_jitter();
            delay_secs + jitter
        } else {
            delay_secs
        };

        Duration::from_secs_f64(final_delay)
    }
}

/// Simple pseudo-random jitter (0.0 to 1.0) without external dependencies.
fn rand_jitter() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 1000) as f64 / 1000.0
}

/// Result of a retry operation.
#[derive(Debug)]
pub struct RetryResult<T> {
    /// The successful result, if any.
    pub value: Option<T>,
    /// Number of attempts made.
    pub attempts: u32,
    /// Total time spent retrying.
    pub total_duration: Duration,
    /// Last error encountered (if failed).
    pub last_error: Option<String>,
}

impl<T> RetryResult<T> {
    /// Check if the operation succeeded.
    pub fn is_success(&self) -> bool {
        self.value.is_some()
    }
}

/// Execute an async operation with retries.
///
/// # Arguments
/// * `operation_name` - Name for logging/error messages
/// * `config` - Retry configuration
/// * `should_retry` - Function to determine if an error is retryable
/// * `operation` - The async operation to execute
///
/// # Example
/// ```ignore
/// let result = retry_async(
///     "fetch data",
///     RetryConfig::network(),
///     |e| e.is_retryable(),
///     || async { fetch_data().await },
/// ).await?;
/// ```
pub async fn retry_async<T, E, F, Fut, R>(
    operation_name: &str,
    config: RetryConfig,
    should_retry: R,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Display,
    R: Fn(&E) -> bool,
{
    let start = std::time::Instant::now();
    let mut last_error = String::new();

    for attempt in 1..=config.max_attempts {
        match operation().await {
            Ok(value) => {
                if attempt > 1 {
                    log::info!(
                        "{} succeeded on attempt {} after {:?}",
                        operation_name,
                        attempt,
                        start.elapsed()
                    );
                }
                return Ok(value);
            }
            Err(e) => {
                last_error = e.to_string();

                if attempt == config.max_attempts {
                    log::warn!(
                        "{} failed after {} attempts: {}",
                        operation_name,
                        attempt,
                        last_error
                    );
                    break;
                }

                if !should_retry(&e) {
                    log::debug!("{} failed with non-retryable error: {}", operation_name, e);
                    return Err(Error::Custom(format!("{}: {}", operation_name, e)));
                }

                let delay = config.delay_for_attempt(attempt);
                log::debug!(
                    "{} failed (attempt {}/{}), retrying in {:?}: {}",
                    operation_name,
                    attempt,
                    config.max_attempts,
                    delay,
                    e
                );

                sleep(delay).await;
            }
        }
    }

    Err(Error::network_retry_exhausted(
        operation_name,
        config.max_attempts,
        last_error,
    ))
}

/// Execute a synchronous operation with retries.
pub fn retry_sync<T, E, F, R>(
    operation_name: &str,
    config: RetryConfig,
    should_retry: R,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> std::result::Result<T, E>,
    E: std::fmt::Display,
    R: Fn(&E) -> bool,
{
    let mut last_error = String::new();

    for attempt in 1..=config.max_attempts {
        match operation() {
            Ok(value) => {
                return Ok(value);
            }
            Err(e) => {
                last_error = e.to_string();

                if attempt == config.max_attempts {
                    break;
                }

                if !should_retry(&e) {
                    return Err(Error::Custom(format!("{}: {}", operation_name, e)));
                }

                let delay = config.delay_for_attempt(attempt);
                std::thread::sleep(delay);
            }
        }
    }

    Err(Error::network_retry_exhausted(
        operation_name,
        config.max_attempts,
        last_error,
    ))
}

/// Helper trait for checking if an error is retryable.
pub trait Retryable {
    fn is_retryable(&self) -> bool;
}

impl Retryable for reqwest::Error {
    fn is_retryable(&self) -> bool {
        // Retry on timeouts, connection errors, and server errors
        self.is_timeout()
            || self.is_connect()
            || self.is_request()
            || self
                .status()
                .is_some_and(|s| s.is_server_error() || s == reqwest::StatusCode::TOO_MANY_REQUESTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_delay_calculation() {
        let config = RetryConfig {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            add_jitter: false,
            ..Default::default()
        };

        // First attempt: 1s
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
        // Second attempt: 2s
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(2));
        // Third attempt: 4s
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(4));
        // Fourth attempt: 8s
        assert_eq!(config.delay_for_attempt(4), Duration::from_secs(8));
        // Fifth attempt: capped at 10s
        assert_eq!(config.delay_for_attempt(5), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_retry_success_first_attempt() {
        let result: Result<i32> = retry_async(
            "test operation",
            RetryConfig::quick(),
            |_: &String| true,
            || async { Ok::<_, String>(42) },
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_exhausted() {
        let mut attempts = 0;
        let result: Result<i32> = retry_async(
            "failing operation",
            RetryConfig::quick().with_max_attempts(2),
            |_: &String| true,
            || {
                attempts += 1;
                async move { Err::<i32, _>("always fails".to_string()) }
            },
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempts, 2);
    }
}
