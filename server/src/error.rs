//! Erreurs de l'API et conversion en réponses HTTP JSON.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden(String),
    NotFound,
    Conflict(String),
    TooLarge,
    TooManyRequests,
    Internal(anyhow::Error),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use auxipak_core::tr;
        let s = match self {
            ApiError::BadRequest(m) | ApiError::Forbidden(m) | ApiError::Conflict(m) => m.clone(),
            ApiError::Unauthorized => tr!("authentification requise", "authentication required"),
            ApiError::NotFound => tr!("ressource introuvable", "resource not found"),
            ApiError::TooLarge => tr!("contenu trop volumineux", "content too large"),
            ApiError::TooManyRequests => tr!(
                "trop de tentatives, réessayez plus tard",
                "too many attempts, try again later"
            ),
            ApiError::Internal(_) => tr!("erreur interne", "internal error"),
        };
        f.write_str(&s)
    }
}

impl std::error::Error for ApiError {}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(e)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => ApiError::NotFound,
            e => ApiError::Internal(e.into()),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::Internal(e.into())
    }
}

impl ApiError {
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::NotFound => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::TooLarge => "too_large",
            ApiError::TooManyRequests => "too_many_requests",
            ApiError::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(e) = &self {
            // Le détail interne est journalisé, jamais renvoyé au client.
            tracing::error!(error = %format!("{e:#}"), "{}", auxipak_core::tr!("erreur interne", "internal error"));
        }
        let body = serde_json::json!({ "error": self.code(), "message": self.to_string() });
        (self.status(), Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(msg.into())
}

pub fn forbidden(msg: impl Into<String>) -> ApiError {
    ApiError::Forbidden(msg.into())
}
