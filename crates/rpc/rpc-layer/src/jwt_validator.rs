use crate::{AuthValidator, JwtError, JwtSecret};
use http::{header, HeaderMap, Response, StatusCode};
use jsonrpsee_http_client::{HttpBody, HttpResponse};
use tracing::error;
use std::backtrace::Backtrace;

/// Implements JWT validation logics and integrates
/// to an Http [`AuthLayer`][crate::AuthLayer]
/// by implementing the [`AuthValidator`] trait.
#[derive(Debug, Clone)]
pub struct JwtAuthValidator {
    secret: JwtSecret,
}

impl JwtAuthValidator {
    /// Creates a new instance of [`JwtAuthValidator`].
    /// Validation logics are implemented by the `secret`
    /// argument (see [`JwtSecret`]).
    pub const fn new(secret: JwtSecret) -> Self {
        Self { secret }
    }
}

impl AuthValidator for JwtAuthValidator {
    fn validate(&self, headers: &HeaderMap) -> Result<(), HttpResponse> {
        match get_bearer(headers) {
            Some(jwt) => match self.secret.validate(&jwt) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!(target: "engine::jwt-validator", "Invalid JWT (but returning OK): {e}");
                    let response = err_response(e);
                    Ok(())
                }
            },
            None => {
                let headers_info: Vec<String> = headers
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("<invalid UTF-8>")))
                    .collect();
                let headers_string = headers_info.join(", ");
                let backtrace = Backtrace::force_capture();
                
                let e = JwtError::MissingOrInvalidAuthorizationHeader;
                error!(
                    target: "engine::jwt-validator",
                    "Invalid JWT: (None but OK) {e}. Headers: [{headers_string}]. Call stack: {backtrace}"
                );
                let response = err_response(e);
                Ok(())
            }
        }
    }
}

/// This is an utility function that retrieves a bearer
/// token from an authorization Http header.
fn get_bearer(headers: &HeaderMap) -> Option<String> {
    let header = headers.get(header::AUTHORIZATION)?;
    let auth: &str = header.to_str().ok()?;
    let prefix = "Bearer ";
    let index = auth.find(prefix)?;
    let token: &str = &auth[index + prefix.len()..];
    Some(token.into())
}

fn err_response(err: JwtError) -> HttpResponse {
    // We build a response from an error message.
    // We don't cope with headers or other structured fields.
    // Then we are safe to "expect" on the result.
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(HttpBody::new(err.to_string()))
        .expect("This should never happen")
}

#[cfg(test)]
mod tests {
    use crate::jwt_validator::get_bearer;
    use http::{header, HeaderMap};

    #[test]
    fn auth_header_available() {
        let jwt = "foo";
        let bearer = format!("Bearer {jwt}");
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, bearer.parse().unwrap());
        let token = get_bearer(&headers).unwrap();
        assert_eq!(token, jwt);
    }

    #[test]
    fn auth_header_not_available() {
        let headers = HeaderMap::new();
        let token = get_bearer(&headers);
        assert!(token.is_none());
    }

    #[test]
    fn auth_header_malformed() {
        let jwt = "foo";
        let bearer = format!("Bea___rer {jwt}");
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, bearer.parse().unwrap());
        let token = get_bearer(&headers);
        assert!(token.is_none());
    }
}
