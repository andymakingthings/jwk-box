use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwkClientErr {
    #[error("Could not connect: {0}")]
    ConnectionError(#[from] reqwest::Error),

    #[error("An error occurred: {0}")]
    Other(String),

    #[error("Could not parse token: {0}")]
    ParseError(#[from] jwt_simple::Error),
}
