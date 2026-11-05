//! Exercise the same ICE -> mux -> DTLS/SRTP/SCTP layering as a native capturer.
//! In particular, resolving an ICE role conflict must not change the DTLS role.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dtls::config::Config as DtlsConfig;
use dtls::conn::DTLSConn;
use dtls::crypto::Certificate;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use ice::agent::{agent_config::AgentConfig, Agent};
use ice::candidate::CandidateType;
use ice::mdns::MulticastDnsMode;
use ice::network_type::NetworkType;
use rtp::{header::Header, packet::Packet};
use sctp::association::{Association, Config as SctpConfig};
use sctp::chunk::chunk_payload_data::PayloadProtocolIdentifier;
use srtp::{config::Config as SrtpConfig, protection_profile::ProtectionProfile, session::Session};
use tokio::sync::mpsc;
use tokio::time::timeout;
use util::Conn;
use webrtc::mux::{mux_func, Config as MuxConfig, Mux};

async fn gather(agent: &Agent) {
    let (tx, mut rx) = mpsc::channel(1);
    agent.on_candidate(Box::new(move |candidate| {
        let tx = tx.clone();
        Box::pin(async move {
            if candidate.is_none() {
                tx.send(()).await.unwrap();
            }
        })
    }));
    agent.gather_candidates().unwrap();
    timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("ICE gathering timed out")
        .expect("ICE gathering did not complete");
}

async fn connect(agent: &Agent, peer: &Agent, controlling: bool) -> Arc<dyn Conn + Send + Sync> {
    let (ufrag, pwd) = peer.get_local_user_credentials().await;
    let (_cancel, rx) = mpsc::channel(1);
    if controlling {
        agent.dial(rx, ufrag, pwd).await.unwrap()
    } else {
        agent.accept(rx, ufrag, pwd).await.unwrap()
    }
}

async fn encrypted_transport(a_controlling: bool, b_controlling: bool, a_dtls_client: bool) {
    let mut agents = Vec::new();
    for _ in 0..2 {
        let agent = Agent::new(AgentConfig {
            network_types: vec![NetworkType::Udp4],
            candidate_types: vec![CandidateType::Host],
            multicast_dns_mode: MulticastDnsMode::Disabled,
            include_loopback: true,
            ip_filter: Arc::new(Some(Box::new(|ip| ip.is_loopback()))),
            ..Default::default()
        })
        .await
        .unwrap();
        gather(&agent).await;
        agents.push(agent);
    }
    for (agent, peer) in [(&agents[0], &agents[1]), (&agents[1], &agents[0])] {
        let candidates = peer.get_local_candidates().await.unwrap();
        assert!(!candidates.is_empty());
        for candidate in candidates {
            agent.add_remote_candidate(&candidate).unwrap();
        }
    }
    let (a, b) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            connect(&agents[0], &agents[1], a_controlling),
            connect(&agents[1], &agents[0], b_controlling)
        )
    })
    .await
    .expect("ICE did not resolve the initial roles");
    let mut muxes: Vec<_> = [a, b]
        .into_iter()
        .map(|conn| {
            Mux::new(MuxConfig {
                conn,
                buffer_size: 8192,
            })
        })
        .collect();
    let mut endpoints = Vec::new();
    let mut configs = Vec::new();
    for mux in &muxes {
        endpoints.push(mux.new_endpoint(Box::new(mux_func::match_dtls)).await);
        configs.push(DtlsConfig {
            certificates: vec![Certificate::generate_self_signed(vec!["localhost".into()]).unwrap()],
            srtp_protection_profiles: vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
            insecure_skip_verify: true,
            ..Default::default()
        });
    }
    let config_b = configs.pop().unwrap();
    let config_a = configs.pop().unwrap();
    let (a, b) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            DTLSConn::new(endpoints[0].clone(), config_a, a_dtls_client, None),
            DTLSConn::new(endpoints[1].clone(), config_b, !a_dtls_client, None)
        )
    })
    .await
    .expect("DTLS handshake failed after ICE");
    let dtls = [Arc::new(a.unwrap()), Arc::new(b.unwrap())];

    let mut media = Vec::new();
    for (i, is_client) in [a_dtls_client, !a_dtls_client].into_iter().enumerate() {
        let mut config = SrtpConfig {
            profile: ProtectionProfile::Aes128CmHmacSha1_80,
            ..Default::default()
        };
        config
            .extract_session_keys_from_dtls(dtls[i].connection_state().await, is_client)
            .await
            .unwrap();
        media.push(
            Session::new(
                muxes[i].new_endpoint(Box::new(mux_func::match_srtp)).await,
                config,
                true,
            )
            .await
            .unwrap(),
        );
    }
    let sctp_config = |i: usize| SctpConfig {
        net_conn: dtls[i].clone(),
        max_receive_buffer_size: 0,
        max_message_size: 0,
        name: format!("role-conflict-{i}"),
        local_port: 5000,
        remote_port: 5000,
    };
    let (a, b) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            Association::client(sctp_config(0)),
            Association::server(sctp_config(1))
        )
    })
    .await
    .expect("SCTP handshake failed after DTLS");
    let associations = [a.unwrap(), b.unwrap()];

    // Preserve the established DTLS/SRTP/SCTP sessions through a real ICE restart.
    for generation in 0..2 {
        if generation != 0 {
            for agent in &agents {
                agent.restart(String::new(), String::new()).await.unwrap();
                gather(agent).await;
            }
            for (agent, peer) in [(&agents[0], &agents[1]), (&agents[1], &agents[0])] {
                let (ufrag, pwd) = peer.get_local_user_credentials().await;
                agent.set_remote_credentials(ufrag, pwd).await.unwrap();
                for candidate in peer.get_local_candidates().await.unwrap() {
                    agent.add_remote_candidate(&candidate).unwrap();
                }
            }
            timeout(Duration::from_secs(5), async {
                while agents
                    .iter()
                    .any(|agent| agent.get_selected_candidate_pair().is_none())
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("ICE did not reconnect after restart");
        }
        for (sender, receiver) in [(0, 1), (1, 0)] {
            let packet = Packet {
                header: Header {
                    version: 2,
                    payload_type: 111,
                    sequence_number: generation + 1,
                    ssrc: 42,
                    ..Default::default()
                },
                payload: Bytes::from_static(b"encrypted media after role conflict"),
            };
            let stream = media[receiver].open(packet.header.ssrc).await;
            media[sender].write_rtp(&packet).await.unwrap();
            let mut buf = [0; 2048];
            let received = timeout(Duration::from_secs(2), stream.read_rtp(&mut buf))
                .await
                .expect("SRTP packet failed authentication or delivery")
                .unwrap();
            assert_eq!(received, packet);

            let stream = associations[sender]
                .open_stream(
                    generation * 2 + sender as u16,
                    PayloadProtocolIdentifier::Binary,
                )
                .await
                .unwrap();
            let payload = Bytes::from_static(b"SCTP data after role conflict");
            stream
                .write_sctp(&payload, PayloadProtocolIdentifier::Binary)
                .await
                .unwrap();
            let incoming = timeout(
                Duration::from_secs(2),
                associations[receiver].accept_stream(),
            )
            .await
            .expect("SCTP stream was not delivered")
            .unwrap();
            let (n, ppi) = timeout(Duration::from_secs(2), incoming.read_sctp(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], payload.as_ref());
            assert_eq!(ppi, PayloadProtocolIdentifier::Binary);
        }
    }
    for session in media {
        session.close().await.unwrap();
    }
    let (a, b) = tokio::join!(associations[0].close(), associations[1].close());
    a.unwrap();
    b.unwrap();
    for mux in &mut muxes {
        mux.close().await;
    }
    for agent in agents {
        agent.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_ice_roles_preserve_encrypted_media_and_data() {
    for controlling in [true, false] {
        for dtls_client in [true, false] {
            timeout(
                Duration::from_secs(20),
                encrypted_transport(controlling, controlling, dtls_client),
            )
            .await
            .expect("transport did not complete or shut down");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complementary_ice_roles_preserve_encrypted_media_and_data() {
    for controlling in [true, false] {
        timeout(
            Duration::from_secs(20),
            encrypted_transport(controlling, !controlling, true),
        )
        .await
        .expect("transport did not complete or shut down");
    }
}
