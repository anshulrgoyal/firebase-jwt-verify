use failure::{format_err, Error};
use openssl::x509::X509;
use reqwest::header::HeaderMap;
use reqwest::header::CACHE_CONTROL;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_AGE_DIRECTIVE: &str = "maxage";
const GOOGLE_KEYS_URL: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

#[derive(Deserialize, Default)]
pub struct GoogleKeys(HashMap<String, Vec<u8>>);

pub struct GoogleKeyProvider {
    cached_keys: Option<GoogleKeys>,
    cache_expiration: Instant,
}

impl GoogleKeyProvider {
    pub fn new() -> GoogleKeyProvider {
        GoogleKeyProvider {
            cached_keys: None,
            cache_expiration: Instant::now(),
        }
    }

    pub fn get_key(&mut self, kid: &str) -> Result<&Vec<u8>, Error> {
        let google_keys = self.get_keys()?;
        google_keys
            .0
            .get(kid)
            .ok_or_else(|| format_err!("Provided kid not found"))
    }

    fn get_keys(&mut self) -> Result<&GoogleKeys, Error> {
        if self.cache_expiration < Instant::now() {
            self.fetch_keys()
        } else {
            self.cached_keys
                .as_ref()
                .ok_or_else(|| format_err!("Internal error, key cache unexpectedly empty"))
        }
    }

    fn fetch_keys(&mut self) -> Result<&GoogleKeys, Error> {
        let mut result = reqwest::get(GOOGLE_KEYS_URL)?;
        let key_set = Self::extract_keys(&result.text()?)?;

        if let Some(cache_expiration) = Self::extract_expiration(result.headers()) {
            self.cache_expiration = cache_expiration;
        }

        self.cached_keys = Some(key_set);
        Ok(self.cached_keys.as_ref().unwrap())
    }

    fn extract_keys(text: &str) -> Result<GoogleKeys, Error> {
        let cert_map: HashMap<String, String> = serde_json::from_str(&text)?;
        let key_set = cert_map
            .into_iter()
            .map(|(kid, crt)| Self::extract_key(crt).map(|pkey| (kid, pkey)))
            .try_fold(
                GoogleKeys::default(),
                |mut keys, next| -> Result<GoogleKeys, Error> {
                    let (kid, pkey) = next?;
                    keys.0.insert(kid, pkey);
                    Ok(keys)
                },
            )?;

        Ok(key_set)
    }

    fn extract_key(cert_pem: String) -> Result<Vec<u8>, Error> {
        let cert = X509::from_pem(cert_pem.as_bytes())?;
        let pkey = cert.public_key()?;
        let rsa = pkey.rsa()?;
        let key = rsa.public_key_to_der_pkcs1()?;
        Ok(key)
    }

    fn extract_expiration(headers: &HeaderMap) -> Option<Instant> {
        let cache_header = headers.get(CACHE_CONTROL)?;
        let cache_header_str = cache_header.to_str().ok()?;
        let max_age_secs: u64 = cache_header_str
            .split(", ")
            .find(|part| part.to_lowercase().starts_with(MAX_AGE_DIRECTIVE))?
            .split('=')
            .last()?
            .parse()
            .ok()?;

        Some(Instant::now() + Duration::from_secs(max_age_secs))
    }
}
