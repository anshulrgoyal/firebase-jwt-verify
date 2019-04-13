use failure::{format_err, Error};
use jsonwebtoken::Validation;
use serde::Deserialize;
use serde_json::Value;

mod key_provider;
use key_provider::GoogleKeyProvider;

#[derive(Deserialize, Debug, Clone)]
pub struct Claims {
    pub aud: String,
    pub auth_time: u64, // unix sec
    pub exp: u64,       // unix sec
    pub iat: u64,       // unix sec
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub provider_id: String,
    #[serde(default)]
    pub firebase: FirebaseClaim,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct FirebaseClaim {
    #[serde(default)]
    pub sign_in_provider: String,
}

pub struct Client {
    key_provider: GoogleKeyProvider,
}

impl Default for Client {
    fn default() -> Client {
        Client {
            key_provider: GoogleKeyProvider::new(),
        }
    }
}

impl Client {
    pub fn verify_id_token(&mut self, id_token: &str, iss: &str) -> Result<Claims, Error> {
        let header = jsonwebtoken::decode_header(id_token)?;
        let kid = header.kid.ok_or_else(|| format_err!("Token kid missing"))?;
        let validation = Validation::new(header.alg);
        let public_key = self.key_provider.get_key(&kid)?;
        let data = jsonwebtoken::decode::<Claims>(id_token, public_key, &validation)?;
        let expected_iss = &format!("https://securetoken.google.com/{}", iss);
        let token_iss = &data.claims.iss;
        if expected_iss == token_iss {
            Ok(data.claims)
        } else {
            Err(format_err!(
                "Token iss: {} != expected iss: {}",
                token_iss,
                expected_iss
            ))
        }
    }
}
