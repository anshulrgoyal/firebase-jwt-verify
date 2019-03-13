use failure::{format_err, Error};
use jsonwebtoken::Validation;
use serde::{Deserialize, Serialize};

mod key_provider;
use key_provider::GoogleKeyProvider;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub aud: String,
    pub auth_time: u64, // unix sec
    pub exp: u64,       // unix sec
    pub iat: u64,       // unix sec
    pub iss: String,
    pub sub: String,
    pub user_id: String,
}

pub struct Client {
    key_provider: GoogleKeyProvider,
}

impl Client {
    pub fn new() -> Client {
        Client {
            key_provider: GoogleKeyProvider::new(),
        }
    }

    pub fn verify_id_token(&mut self, id_token: &str, iss: &str) -> Result<Claims, Error> {
        let header = jsonwebtoken::decode_header(id_token)?;
        let kid = header.kid.ok_or(format_err!("Token kid missing"))?;
        let validation = Validation::new(header.alg);
        let public_key = self.key_provider.get_key(&kid)?;
        let data = jsonwebtoken::decode::<Claims>(id_token, public_key, &validation)?;
        let expected_iss = &format!("https://securetoken.google.com/{}", iss);
        let token_iss = &data.claims.iss;
        match expected_iss == token_iss {
            true => Ok(data.claims),
            false => Err(format_err!(
                "Token iss: {} != expected iss: {}",
                token_iss,
                expected_iss
            )),
        }
    }
}
