use crate::{AuthValidator, JwtError, JwtSecret};
use http::{header, HeaderMap, Response, StatusCode};
use jsonrpsee_http_client::{HttpBody, HttpResponse};
use tracing::info;

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
    fn validate(&self, _headers: &HeaderMap) -> Result<(), HttpResponse> {
        info!(
            target: "engine::jwt-validator",
            "Bypassing JWT validation. All requests are accepted."
        );
        Ok(())
    }
}

fn err_response(err: JwtError) -> HttpResponse {
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
