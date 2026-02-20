use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Verify an HMAC-SHA256 signature against a raw body and shared secret.
///
/// The `signature_header` is expected to be in `sha256=<hex_digest>` format,
/// which is the standard used by both GitHub (`X-Hub-Signature-256`) and
/// Atlassian products like Jira and Bitbucket (`X-Hub-Signature`).
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// Returns `true` if the signature is valid, `false` otherwise.
pub fn verify_hmac_sha256(secret: &str, body: &[u8], signature_header: &str) -> bool {
    // Parse the "sha256=<hex>" format
    let hex_digest = match signature_header.strip_prefix("sha256=") {
        Some(hex) => hex,
        None => return false,
    };

    // Decode the hex signature from the header
    let expected_bytes = match hex::decode(hex_digest) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Compute the HMAC-SHA256 of the body
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(body);

    // Constant-time comparison (via the hmac crate's verify_slice)
    mac.verify_slice(&expected_bytes).is_ok()
}

/// Compute an HMAC-SHA256 signature for a body and return it in `sha256=<hex>` format.
///
/// This is used for re-signing payloads (e.g., GitHub webhooks) before
/// forwarding them to n8n.
pub fn compute_hmac_sha256(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test data from Atlassian's Bitbucket Cloud documentation:
    /// https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/#Secure-webhooks
    const ATLASSIAN_TEST_SECRET: &str = "It's a Secret to Everybody";
    const ATLASSIAN_TEST_PAYLOAD: &str = "Hello World!";
    const ATLASSIAN_TEST_SIGNATURE: &str =
        "sha256=a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9";

    #[test]
    fn test_verify_valid_signature_atlassian_test_vector() {
        assert!(verify_hmac_sha256(
            ATLASSIAN_TEST_SECRET,
            ATLASSIAN_TEST_PAYLOAD.as_bytes(),
            ATLASSIAN_TEST_SIGNATURE,
        ));
    }

    #[test]
    fn test_verify_rejects_wrong_secret() {
        assert!(!verify_hmac_sha256(
            "wrong-secret",
            ATLASSIAN_TEST_PAYLOAD.as_bytes(),
            ATLASSIAN_TEST_SIGNATURE,
        ));
    }

    #[test]
    fn test_verify_rejects_tampered_body() {
        assert!(!verify_hmac_sha256(
            ATLASSIAN_TEST_SECRET,
            b"Tampered body",
            ATLASSIAN_TEST_SIGNATURE,
        ));
    }

    #[test]
    fn test_verify_rejects_missing_sha256_prefix() {
        // No "sha256=" prefix
        assert!(!verify_hmac_sha256(
            ATLASSIAN_TEST_SECRET,
            ATLASSIAN_TEST_PAYLOAD.as_bytes(),
            "a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9",
        ));
    }

    #[test]
    fn test_verify_rejects_invalid_hex() {
        assert!(!verify_hmac_sha256(
            ATLASSIAN_TEST_SECRET,
            ATLASSIAN_TEST_PAYLOAD.as_bytes(),
            "sha256=not-valid-hex!!!",
        ));
    }

    #[test]
    fn test_verify_rejects_empty_signature() {
        assert!(!verify_hmac_sha256(
            ATLASSIAN_TEST_SECRET,
            ATLASSIAN_TEST_PAYLOAD.as_bytes(),
            "",
        ));
    }

    #[test]
    fn test_verify_rejects_wrong_prefix() {
        assert!(!verify_hmac_sha256(
            ATLASSIAN_TEST_SECRET,
            ATLASSIAN_TEST_PAYLOAD.as_bytes(),
            "sha1=a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9",
        ));
    }

    #[test]
    fn test_compute_produces_valid_signature() {
        let signature =
            compute_hmac_sha256(ATLASSIAN_TEST_SECRET, ATLASSIAN_TEST_PAYLOAD.as_bytes());
        assert_eq!(signature, ATLASSIAN_TEST_SIGNATURE);
    }

    #[test]
    fn test_compute_and_verify_roundtrip() {
        let secret = "my-test-secret";
        let body = b"some webhook payload body";
        let signature = compute_hmac_sha256(secret, body);
        assert!(verify_hmac_sha256(secret, body, &signature));
    }

    #[test]
    fn test_compute_and_verify_roundtrip_with_empty_body() {
        let secret = "secret";
        let body = b"";
        let signature = compute_hmac_sha256(secret, body);
        assert!(verify_hmac_sha256(secret, body, &signature));
    }

    #[test]
    fn test_github_style_signature_verification() {
        // GitHub uses sha256=<hex> format for X-Hub-Signature-256
        let secret = "github-webhook-secret";
        let body = b"{\"action\":\"push\",\"ref\":\"refs/heads/main\"}";
        let signature = compute_hmac_sha256(secret, body);
        assert!(signature.starts_with("sha256="));
        assert!(verify_hmac_sha256(secret, body, &signature));
    }
}
