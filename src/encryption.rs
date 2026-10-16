//! Decrypts Rails Active Record Encryption values, such as Mastodon 4.7+ `keypairs.private_key`:
//! AES-256-GCM with a key derived by PBKDF2-SHA256, or SHA-1 for older values.

use std::num::NonZeroU32;

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::pbkdf2;
use serde::Deserialize;

/// The values of the same names in Mastodon's `.env.production`.
pub struct Secrets {
    pub primary_key: String,
    pub key_derivation_salt: String,
}

/// `ActiveSupport::KeyGenerator`'s default.
const ITERATIONS: NonZeroU32 = NonZeroU32::new(1 << 16).unwrap();

/// Bounds what a corrupt compressed value can inflate to.
const MAX_PLAINTEXT_LEN: usize = 1 << 20;

#[derive(Deserialize)]
struct Message {
    p: String,
    h: Headers,
}

#[derive(Deserialize)]
struct Headers {
    iv: String,
    at: String,
    /// Zlib-compressed.
    #[serde(default)]
    c: bool,
}

pub fn decrypt(value: &str, secrets: &Secrets) -> Result<String> {
    let message: Message =
        serde_json::from_str(value).context("not an Active Record Encryption message")?;
    let base64 = |value: &str, name: &str| {
        STANDARD
            .decode(value)
            .with_context(|| format!("{name} is not base64"))
    };
    let ciphertext = base64(&message.p, "payload")?;
    let iv = base64(&message.h.iv, "iv")?;
    let tag = base64(&message.h.at, "auth tag")?;

    let plaintext = [pbkdf2::PBKDF2_HMAC_SHA256, pbkdf2::PBKDF2_HMAC_SHA1]
        .into_iter()
        .find_map(|algorithm| open(algorithm, secrets, &iv, &ciphertext, &tag))
        .context("wrong ACTIVE_RECORD_ENCRYPTION_* secrets or corrupt value")?;
    let plaintext = if message.h.c {
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&plaintext, MAX_PLAINTEXT_LEN)
            .map_err(|error| anyhow!("failed to decompress: {error:?}"))?
    } else {
        plaintext
    };
    String::from_utf8(plaintext).context("decrypted value is not UTF-8")
}

fn open(
    algorithm: pbkdf2::Algorithm,
    secrets: &Secrets,
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    let mut key = [0; 32];
    pbkdf2::derive(
        algorithm,
        ITERATIONS,
        secrets.key_derivation_salt.as_bytes(),
        secrets.primary_key.as_bytes(),
        &mut key,
    );
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).ok()?);
    let nonce = Nonce::try_assume_unique_for_key(iv).ok()?;
    // A wrong-length tag just fails authentication.
    let mut in_out = [ciphertext, tag].concat();
    let plaintext = key.open_in_place(nonce, Aad::empty(), &mut in_out).ok()?;
    Some(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Written by Ruby's OpenSSL and Zlib the way Rails 8.1's encryptor does.
    const SHA256_COMPRESSED: &str = r#"{"p":"2GmaOcxqV0q+04aSAYN8AR1oo5Q2z2X3xfvtEko0H0nY4L98Rnewe+XaTmY6RcaM3CZw","h":{"iv":"MDEyMzQ1Njc4OWFi","at":"KgBuT7rR/3QtFFAJ7w4p5A==","c":true}}"#;
    const SHA1_PLAIN: &str =
        r#"{"p":"TpEqptLInUORSWeW","h":{"iv":"YmE5ODc2NTQzMjEw","at":"B+4DqxIRHix3xiRE4DX0Sw=="}}"#;

    fn secrets(primary_key: &str) -> Secrets {
        Secrets {
            primary_key: primary_key.to_string(),
            key_derivation_salt: "test salt".to_string(),
        }
    }

    #[test]
    fn decrypts_a_compressed_sha256_message() {
        let expected = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            "QUJD".repeat(64)
        );
        let decrypted = decrypt(SHA256_COMPRESSED, &secrets("test primary key")).unwrap();
        assert_eq!(decrypted, expected);
    }

    #[test]
    fn decrypts_an_uncompressed_sha1_message() {
        let decrypted = decrypt(SHA1_PLAIN, &secrets("test primary key")).unwrap();
        assert_eq!(decrypted, "short secret");
    }

    #[test]
    fn rejects_the_wrong_secrets() {
        assert!(decrypt(SHA1_PLAIN, &secrets("another key")).is_err());
    }
}
