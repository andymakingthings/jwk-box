//! # A basic JWK client.
//!
//! Fetches public keys from a jwks_uri to validate JWT. Keys are refreshed automatically.

use std::collections::{HashMap, HashSet};

use jwt_simple::{
    algorithms::RSAPublicKeyLike,
    prelude::{
        Token,
        Serialize,
        VerificationOptions,
        RS256PublicKey,
        JWTClaims,
    },
};
use chrono::{Duration, DateTime, Utc};
use serde::Deserialize;
use serde_with::{
    serde_as,
    base64::{Base64, UrlSafe},
    formats::Unpadded,
};


mod error;
pub use error::JwkClientErr;

/// # Defaults
///
/// - If public keys are older than `auto_refresh_interval`, the keys are refreshed before token validation. Defaults to an hour.
/// - Reactively refreshes public keys and retries token validation on validation failure, limited to once per `retry_rate_limit`. Defaults to 5 minutes.
#[derive(Debug, Clone)]
pub struct JwkClient {
    jwks_uri: String,
    issuer: String,
    audience: String,
    public_keys: HashMap<String, PublicKey>, // `kid` -> PublicKey
    // how often JWK will be fetched proactively before token validation, i.e. how
    // long before JWK will be considered stale
    auto_refresh_interval: Duration,
    // limit how often JWK will be fetched reactively after failed token validation
    retry_rate_limit: Duration,
    // last time JWK were fetched proactively before token validation
    last_refresh: Option<DateTime<Utc>>,
    // last time JWK were fetched reactively after failed token validation
    last_retry: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
struct PublicKey {
    key: RS256PublicKey,
    not_before: Option<DateTime<Utc>>,
}

impl PublicKey {
    /// Check if key is valid (not_before is either None or in the past)
    /// Returns true if the key is currently valid
    fn is_valid(&self) -> bool {
        self.not_before.is_none_or(|nbf| nbf <= Utc::now())
    }

    /// Returns the key if it's currently valid, None otherwise
    fn valid_key(&self) -> Option<&RS256PublicKey> {
        self.is_valid().then_some(&self.key)
    }
}

impl JwkClient {
    pub fn new(
        jwks_uri: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            public_keys: HashMap::new(),
            auto_refresh_interval: Duration::hours(1),
            retry_rate_limit: Duration::minutes(5),
            last_refresh: None,
            last_retry: None,
        }
    }

    pub fn set_auto_refresh_interval(&mut self, duration: Duration) {
        self.auto_refresh_interval = duration;
    }

    pub fn set_retry_rate_limit(&mut self, duration: Duration) {
        self.retry_rate_limit = duration;
    }

    fn keys_are_stale(&self) -> bool {
        self.last_refresh
            .map(|t| Utc::now() - t > self.auto_refresh_interval)
            .unwrap_or(true)
    }

    fn can_retry_on_failure(&self) -> bool {
        self.last_retry
            .map(|t| Utc::now() - t > self.retry_rate_limit)
            .unwrap_or(true)
    }

    async fn refresh_public_keys(&mut self) -> Result<(), JwkClientErr> {
        let public_keys: Result<_, _> = reqwest::get(&self.jwks_uri)
            .await?
            .json::<JwkRawArray>()
            .await?
            .keys
            .into_iter()
            .map(|jwk| {
                let key = RS256PublicKey::from_components(&jwk.modulus, &jwk.exponent)?;
                Ok::<(std::string::String, PublicKey), JwkClientErr>((jwk.key_id, PublicKey {
                    key,
                    not_before: jwk.not_before,
                }))
            })
            .collect();

        self.public_keys = public_keys?;
        self.last_refresh = Some(Utc::now());

        Ok(())
    }

    fn get_valid_key(&self, key_id: &str) -> Option<&RS256PublicKey> {
        self.public_keys
            .get(key_id)?
            .valid_key()
    }

    pub async fn validate_token<T>(&mut self, token: &str) -> Result<JWTClaims<T>, JwkClientErr>
    where
        for<'de> T: Serialize + Deserialize<'de>,
    {
        if self.keys_are_stale() {
            self.refresh_public_keys().await?;
        }

        match self.validate_token_impl(token).await {
            // Retry if we haven't retried recently
            Err(_) if self.can_retry_on_failure() => {
                self.refresh_public_keys().await?;
                self.last_retry = Some(Utc::now());
                self.validate_token_impl(token).await
            },
            // Otherwise, return the first result
            result => result,
        }
    }

    async fn validate_token_impl<T>(
        &mut self,
        token: &str,
    ) -> Result<JWTClaims<T>, JwkClientErr>
    where
        for<'de> T: Serialize + Deserialize<'de>,
    {
        let verification_options = VerificationOptions {
            allowed_issuers: Some(HashSet::from([self.issuer.clone()])),
            allowed_audiences: Some(HashSet::from([self.audience.clone()])),
            ..Default::default()
        };

        let metadata = Token::decode_metadata(token)?;

        let key_id = metadata
            .key_id()
            .ok_or(JwkClientErr::Other("token is missing public key id `kid`".to_string()))?;

        let key = self.get_valid_key(key_id)
            .ok_or(JwkClientErr::Other("token's public key id `kid` not found".to_string()))?;

        key.verify_token::<T>(token, Some(verification_options))
            .map_err(JwkClientErr::from)
    }

}


#[derive(Debug, Deserialize)]
struct JwkRawArray {
    keys: Vec<JwkRaw>,
}

#[serde_as]
#[derive(Debug, Deserialize, Clone)]
struct JwkRaw {
    #[serde(rename = "kid")]
    key_id: String,

    // #[serde(rename = "use")]
    // key_use: String, // e.g. "sig"

    // #[serde(rename = "kty")]
    // key_type: String, // e.g. "RSA"

    #[serde(rename = "nbf", with = "chrono::serde::ts_seconds_option")]
    not_before: Option<DateTime<Utc>>,

    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    #[serde(rename = "e")]
    exponent: Vec<u8>,

    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    #[serde(rename = "n")]
    modulus: Vec<u8>,
}
