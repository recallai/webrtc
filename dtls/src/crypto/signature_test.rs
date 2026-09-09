use super::*;

const MESSAGE: &[u8] = include_bytes!("testdata/signatures/message.bin");
const P256: &[u8] = include_bytes!("testdata/signatures/p256.der");
const P384: &[u8] = include_bytes!("testdata/signatures/p384.der");

#[test]
fn test_ecdsa_curve_hash_combinations() {
    let cases: &[(&[u8], HashAlgorithm, &[u8])] = &[
        (
            P256,
            HashAlgorithm::Sha256,
            include_bytes!("testdata/signatures/p256-sha256.sig"),
        ),
        (
            P256,
            HashAlgorithm::Sha384,
            include_bytes!("testdata/signatures/p256-sha384.sig"),
        ),
        (
            P384,
            HashAlgorithm::Sha256,
            include_bytes!("testdata/signatures/p384-sha256.sig"),
        ),
        (
            P384,
            HashAlgorithm::Sha384,
            include_bytes!("testdata/signatures/p384-sha384.sig"),
        ),
    ];
    for &(cert, hash, signature) in cases {
        let algorithm = SignatureHashAlgorithm {
            hash,
            signature: SignatureAlgorithm::Ecdsa,
        };
        for insecure in [false, true] {
            // Both handshake call sites share this verifier.
            verify_key_signature(MESSAGE, &algorithm, signature, &[cert.to_vec()], insecure)
                .unwrap();
            verify_certificate_verify(MESSAGE, &algorithm, signature, &[cert.to_vec()], insecure)
                .unwrap();
            assert!(verify_key_signature(
                b"tampered",
                &algorithm,
                signature,
                &[cert.to_vec()],
                insecure
            )
            .is_err());
            let mut tampered_signature = signature.to_vec();
            *tampered_signature.last_mut().unwrap() ^= 1;
            assert!(verify_key_signature(
                MESSAGE,
                &algorithm,
                &tampered_signature,
                &[cert.to_vec()],
                insecure
            )
            .is_err());
            let wrong_cert = if cert == P256 { P384 } else { P256 };
            assert!(verify_key_signature(
                MESSAGE,
                &algorithm,
                signature,
                &[wrong_cert.to_vec()],
                insecure
            )
            .is_err());
            let wrong_hash = SignatureHashAlgorithm {
                hash: if hash == HashAlgorithm::Sha256 {
                    HashAlgorithm::Sha384
                } else {
                    HashAlgorithm::Sha256
                },
                signature: SignatureAlgorithm::Ecdsa,
            };
            assert!(verify_key_signature(
                MESSAGE,
                &wrong_hash,
                signature,
                &[cert.to_vec()],
                insecure
            )
            .is_err());
        }
    }
}

#[test]
fn test_teams_p384_sha256_server_key_exchange() {
    // Public handshake bytes from frames 1468/1470 of the 2026-09-09 incident.
    // The unpatched verifier returns ring::error::Unspecified for this valid signature.
    verify_key_signature(
        include_bytes!("testdata/signatures/teams-key-exchange.bin"),
        &SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Ecdsa,
        },
        include_bytes!("testdata/signatures/teams-p384-sha256.sig"),
        &[include_bytes!("testdata/signatures/teams-p384.der").to_vec()],
        false,
    )
    .unwrap();
}

#[test]
fn test_ecdsa_rejects_invalid_certificates_and_unsupported_hash() {
    let signature = include_bytes!("testdata/signatures/p384-sha256.sig");
    let algorithm = SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ecdsa,
    };
    for certificates in [vec![], vec![vec![]], vec![b"invalid DER".to_vec()]] {
        assert!(
            verify_key_signature(MESSAGE, &algorithm, signature, &certificates, false).is_err()
        );
    }
    let unsupported = SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha512,
        signature: SignatureAlgorithm::Ecdsa,
    };
    assert!(
        verify_key_signature(MESSAGE, &unsupported, signature, &[P384.to_vec()], false).is_err()
    );

    // An unsupported named curve must not fall back to a verifier based on key length.
    let mut unsupported_curve = P384.to_vec();
    let p384_oid = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    let offset = unsupported_curve
        .windows(p384_oid.len())
        .position(|v| v == p384_oid)
        .unwrap();
    unsupported_curve[offset + p384_oid.len() - 1] = 0x23; // secp521r1
    assert!(matches!(
        verify_key_signature(MESSAGE, &algorithm, signature, &[unsupported_curve], false),
        Err(Error::ErrKeySignatureVerifyUnimplemented)
    ));

    let ed25519 =
        Certificate::generate_self_signed_with_alg(vec!["localhost".into()], &rcgen::PKCS_ED25519)
            .unwrap();
    assert!(matches!(
        verify_key_signature(
            MESSAGE,
            &algorithm,
            signature,
            &[ed25519.certificate[0].to_vec()],
            false
        ),
        Err(Error::ErrKeySignatureVerifyUnimplemented)
    ));
}
