//! Run with: cargo test -p dtls --test openssl_interop -- --ignored --nocapture
//! Requires an OpenSSL CLI supporting DTLS 1.2 (tested with OpenSSL 3).

#![cfg(unix)]

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dtls::config::Config;
use dtls::conn::DTLSConn;
use dtls::crypto::Certificate;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
#[ignore = "requires OpenSSL CLI and local UDP sockets"]
async fn ecdsa_curve_hash_and_srtp_compatibility() {
    let dir = TempDir(std::env::temp_dir().join(format!(
        "dtls-openssl-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    )));
    std::fs::create_dir(&dir.0).unwrap();
    for curve in ["prime256v1", "secp384r1"] {
        let output = Command::new("openssl")
            .current_dir(&dir.0)
            .args(["req", "-x509", "-newkey", "ec", "-pkeyopt"])
            .arg(format!("ec_paramgen_curve:{curve}"))
            .args([
                "-nodes",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
                "-subj",
                "/CN=localhost",
                "-days",
                "1",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for hash in ["SHA256", "SHA384"] {
            for (profile_name, profile) in [
                (
                    "SRTP_AES128_CM_SHA1_80",
                    SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
                ),
                (
                    "SRTP_AEAD_AES_128_GCM",
                    SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
                ),
                (
                    "SRTP_AEAD_AES_256_GCM",
                    SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
                ),
            ] {
                let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                let address = reservation.local_addr().unwrap();
                drop(reservation);
                let mut server = Server(
                    Command::new("openssl")
                        .current_dir(&dir.0)
                        .args(["s_server", "-dtls1_2", "-quiet", "-accept"])
                        .arg(address.to_string())
                        .args(["-cert", "cert.pem", "-key", "key.pem", "-sigalgs"])
                        .arg(format!("ECDSA+{hash}"))
                        .args(["-use_srtp", profile_name])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::inherit())
                        .spawn()
                        .unwrap(),
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(
                    server.0.try_wait().unwrap().is_none(),
                    "OpenSSL exited before handshake"
                );
                let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                socket.connect(address).await.unwrap();
                let config = Config {
                    certificates: vec![
                        Certificate::generate_self_signed(vec!["localhost".into()]).unwrap()
                    ],
                    server_name: "localhost".into(),
                    insecure_skip_verify: true,
                    srtp_protection_profiles: vec![profile],
                    ..Default::default()
                };
                let conn = tokio::time::timeout(
                    Duration::from_secs(5),
                    DTLSConn::new(socket, config, true, None),
                )
                .await
                .expect("handshake timed out")
                .expect("handshake failed");
                assert_eq!(conn.selected_srtpprotection_profile(), profile);
                let message = b"DTLS compatibility test\n";
                conn.write(message, None).await.unwrap();
                // Receiving application data proves that OpenSSL also accepted Finished.
                let stdout = server.0.stdout.take().unwrap();
                let fd: std::os::fd::OwnedFd = stdout.into();
                let mut output = tokio::fs::File::from_std(std::fs::File::from(fd));
                let mut received = vec![0; message.len()];
                tokio::time::timeout(Duration::from_secs(5), output.read_exact(&mut received))
                    .await
                    .expect("application data timed out")
                    .unwrap();
                assert_eq!(received, message);
                conn.close().await.unwrap();
                println!("PASS {curve} / {hash} / {profile_name}");
            }
        }
    }
}
