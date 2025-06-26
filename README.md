# jwk-box

A simple, async JWK (JSON Web Key) client for Rust that fetches public keys from a JWKS endpoint to validate JWT tokens with automatic key refresh.

## Features

- **Automatic key refresh**
- **Reactive key refresh**
- **JWT validation**

## Installation

Add this to your ```Cargo.toml```:

```toml
[dependencies]
jwk-box = "0.1.0"
```

## Usage

```rust
use jwk_box::JwkClient;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct CustomClaims {
    // your custom claims here
    some_custom_claim: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new JWK client
    let mut client = JwkClient::new(
        "https://your-auth-provider.com/.well-known/jwks.json",
        "https://your-auth-provider.com/", // issuer
        "your-audience" // audience
    );

    // Validate a JWT token
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...";
    let claims = client.validate_token::<CustomClaims>(token).await?;

    println!("Token is valid! Subject: {}", claims.custom.some_custom_claim);
    Ok(())
}
```

## Configuration

You can customize the refresh behavior:

```rust
use chrono::Duration;

let mut client = JwkClient::new(jwks_uri, issuer, audience);

// Set how long before keys are marked stale (default: 1 hour)
client.set_auto_refresh_interval(Duration::minutes(30));

// Set rate limit for reactive retries after validation failure (default: 5 minutes)
client.set_retry_rate_limit(Duration::minutes(2));
```

## How it Works

- **Proactive key refresh**: Keys are automatically refreshed before token validation if they haven't been refreshed within the `auto_refresh_interval` (default: 1 hour)
- **Reactive key refresh/retry**: If token validation fails, the client will refresh keys and retry once, but only if the last retry was longer ago than ```retry_rate_limit```
- **Key Validation**: Keys with an ```nbf``` (not before) claim are only used after that time has passed
- **JWT Validation**: Uses [jwt-simple](https://crates.io/crates/jwt-simple) for token parsing and verification

## API Documentation

[docs.rs/jwk-box](https://docs.rs/jwk-box/).

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Repository

[https://github.com/andymakingthings/jwk-box](https://github.com/andymakingthings/jwk-box)
