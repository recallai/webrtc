use stun::error_code::{ErrorCodeAttribute, CODE_ROLE_CONFLICT};
use stun::textattrs::Username;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use util::Conn;

use super::*;
use crate::candidate::candidate_base::CandidateBaseConfig;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::control::{AttrControlled, AttrControlling};
use crate::priority::PriorityAttr;
use crate::use_candidate::UseCandidateAttr;

const LOCAL_PASSWORD: &str = "local-password-for-role-tests";
const REMOTE_PASSWORD: &str = "remote-password-for-role-tests";
// Tie-breakers from a Teams lobby-to-conference transition that repeatedly failed.
const LOCAL_TIE: u64 = 337371320262117544;
const REMOTE_TIE: u64 = 8926384601593918423;

struct Fixture {
    agent: Agent,
    local: Arc<dyn Candidate + Send + Sync>,
    remote: Arc<dyn Candidate + Send + Sync>,
    peer: UdpSocket,
    pair: Arc<CandidatePair>,
}

fn candidate(socket: Arc<UdpSocket>, priority: u32) -> Arc<dyn Candidate + Send + Sync> {
    let addr = socket.local_addr().unwrap();
    Arc::new(
        CandidateHostConfig {
            base_config: CandidateBaseConfig {
                network: "udp".into(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                priority,
                conn: Some(socket),
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap(),
    )
}

impl Fixture {
    async fn new(controlling: bool, tie_breaker: u64) -> Self {
        let agent = Agent::new(AgentConfig {
            is_controlling: controlling,
            local_ufrag: "local".into(),
            local_pwd: LOCAL_PASSWORD.into(),
            multicast_dns_mode: MulticastDnsMode::Disabled,
            ..Default::default()
        })
        .await
        .unwrap();
        agent
            .set_remote_credentials("remote".into(), REMOTE_PASSWORD.into())
            .await
            .unwrap();
        agent
            .internal
            .tie_breaker
            .store(tie_breaker, Ordering::SeqCst);
        let local = candidate(Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), 100);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap();
        let remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
            CandidateHostConfig {
                base_config: CandidateBaseConfig {
                    network: "udp".into(),
                    address: addr.ip().to_string(),
                    port: addr.port(),
                    component: 1,
                    priority: 200,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap(),
        );
        agent.internal.add_remote_candidate(&remote).await;
        agent.internal.add_pair(local.clone(), remote.clone()).await;
        let pair = agent.internal.find_pair(&local, &remote).await.unwrap();
        Self {
            agent,
            local,
            remote,
            peer,
            pair,
        }
    }

    async fn receive(&self) -> Message {
        let mut raw = vec![0; 2048];
        let (n, _) = timeout(Duration::from_secs(1), self.peer.recv_from(&mut raw))
            .await
            .unwrap()
            .unwrap();
        raw.truncate(n);
        let mut message = Message {
            raw,
            ..Default::default()
        };
        message.decode().unwrap();
        message
    }

    async fn deliver(&self, message: &mut Message) {
        self.agent
            .internal
            .handle_inbound(message, &self.local, self.remote.addr())
            .await;
    }

    async fn send_check(&self) -> Message {
        self.agent
            .internal
            .ping_candidate(&self.local, &self.remote)
            .await;
        self.receive().await
    }
}

fn request(controlling: bool, tie_breaker: u64, password: &str, nominate: bool) -> Message {
    let role: Box<dyn Setter> = if controlling {
        Box::new(AttrControlling(tie_breaker))
    } else {
        Box::new(AttrControlled(tie_breaker))
    };
    let mut attrs: Vec<Box<dyn Setter>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, "local:remote".into())),
        role,
        Box::new(PriorityAttr(200)),
    ];
    if nominate {
        attrs.push(Box::<UseCandidateAttr>::default());
    }
    attrs.push(Box::new(MessageIntegrity::new_short_term_integrity(
        password.into(),
    )));
    attrs.push(Box::new(FINGERPRINT));
    let mut message = Message::new();
    message.build(&attrs).unwrap();
    message
}

fn conflict_response(request: &Message, password: &str) -> Message {
    let mut response = Message::new();
    response
        .build(&[
            Box::new(request.clone()),
            Box::new(BINDING_ERROR),
            Box::new(CODE_ROLE_CONFLICT),
            Box::new(MessageIntegrity::new_short_term_integrity(password.into())),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    response
}

async fn connect(
    f: &Fixture,
    controlling: bool,
    cancel: mpsc::Receiver<()>,
) -> Arc<dyn Conn + Send + Sync> {
    if controlling {
        f.agent
            .dial(cancel, "local".into(), LOCAL_PASSWORD.into())
            .await
            .unwrap()
    } else {
        f.agent
            .accept(cancel, "local".into(), LOCAL_PASSWORD.into())
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn test_role_conflict_requests() {
    for (controlling, local_tie, peer_tie, expected_role, rejected) in [
        (true, LOCAL_TIE, REMOTE_TIE, false, false),
        (true, REMOTE_TIE, LOCAL_TIE, true, true),
        (true, LOCAL_TIE, LOCAL_TIE, true, true),
        (false, LOCAL_TIE, REMOTE_TIE, false, true),
        (false, REMOTE_TIE, LOCAL_TIE, true, false),
        (false, LOCAL_TIE, LOCAL_TIE, true, false),
    ] {
        let f = Fixture::new(controlling, local_tie).await;
        let mut req = request(controlling, peer_tie, LOCAL_PASSWORD, false);
        f.deliver(&mut req).await;
        let mut response = f.receive().await;
        assert_eq!(response.transaction_id, req.transaction_id);
        assert_eq!(
            response.typ,
            if rejected {
                BINDING_ERROR
            } else {
                BINDING_SUCCESS
            }
        );
        MessageIntegrity::new_short_term_integrity(LOCAL_PASSWORD.into())
            .check(&mut response)
            .unwrap();
        FINGERPRINT.check(&response).unwrap();
        if rejected {
            let mut error = ErrorCodeAttribute::default();
            error.get_from(&response).unwrap();
            assert_eq!(error.code.0, CODE_ROLE_CONFLICT.0);
        }
        assert_eq!(
            f.agent.internal.is_controlling.load(Ordering::SeqCst),
            expected_role
        );
        assert_eq!(
            f.pair.ice_role_controlling.load(Ordering::SeqCst),
            expected_role
        );
        assert_eq!(
            f.agent.internal.tie_breaker.load(Ordering::SeqCst),
            local_tie
        );
        f.agent.close().await.unwrap();
    }
}

#[tokio::test]
async fn test_role_conflict_487_retries_in_new_role() {
    for controlling in [true, false] {
        let f = Fixture::new(controlling, LOCAL_TIE).await;
        let old_priority = f.pair.priority();
        let check = f.send_check().await;
        let mut response = conflict_response(&check, REMOTE_PASSWORD);
        f.pair
            .state
            .store(CandidatePairState::Failed as u8, Ordering::SeqCst);
        f.pair
            .binding_request_count
            .store(u16::MAX, Ordering::SeqCst);
        f.pair.nominated.store(true, Ordering::SeqCst);
        f.pair
            .nominate_on_binding_success
            .store(true, Ordering::SeqCst);
        *f.agent.internal.nominated_pair.lock().await = Some(f.pair.clone());
        f.deliver(&mut response).await;
        assert_eq!(
            f.agent.internal.is_controlling.load(Ordering::SeqCst),
            !controlling
        );
        assert_ne!(
            f.agent.internal.tie_breaker.load(Ordering::SeqCst),
            LOCAL_TIE
        );
        assert_ne!(f.pair.priority(), old_priority);
        assert_eq!(
            f.pair.state.load(Ordering::SeqCst),
            CandidatePairState::Waiting as u8
        );
        assert_eq!(f.pair.binding_request_count.load(Ordering::SeqCst), 0);
        assert!(!f.pair.nominated.load(Ordering::SeqCst));
        assert!(!f.pair.nominate_on_binding_success.load(Ordering::SeqCst));
        assert!(f.agent.internal.nominated_pair.lock().await.is_none());
        f.agent.internal.contact_candidates().await;
        let retry = f.receive().await;
        assert_ne!(retry.transaction_id, check.transaction_id);
        assert!(retry.contains(if controlling {
            ATTR_ICE_CONTROLLED
        } else {
            ATTR_ICE_CONTROLLING
        }));
        assert!(!retry.contains(ATTR_USE_CANDIDATE));
        let mut tie = crate::control::TieBreaker::default();
        tie.get_from_as(
            &retry,
            if controlling {
                ATTR_ICE_CONTROLLED
            } else {
                ATTR_ICE_CONTROLLING
            },
        )
        .unwrap();
        assert_eq!(tie.0, f.agent.internal.tie_breaker.load(Ordering::SeqCst));
        let epoch = f.agent.internal.role_epoch.load(Ordering::SeqCst);
        f.deliver(&mut response).await;
        assert_eq!(f.agent.internal.role_epoch.load(Ordering::SeqCst), epoch);
        assert!(f.agent.internal.triggered_checks.lock().await.is_empty());
        f.agent.close().await.unwrap();
    }
}

#[tokio::test]
async fn test_role_conflict_authentication_and_transaction_matching() {
    let f = Fixture::new(true, LOCAL_TIE).await;
    let mut bad_request = request(true, REMOTE_TIE, "incorrect-password", false);
    f.deliver(&mut bad_request).await;
    let check = f.send_check().await;
    let mut bad_response = conflict_response(&check, "incorrect-password");
    f.deliver(&mut bad_response).await;
    let mut unknown = conflict_response(
        &request(true, LOCAL_TIE, LOCAL_PASSWORD, false),
        REMOTE_PASSWORD,
    );
    f.deliver(&mut unknown).await;
    let mut valid = conflict_response(&check, REMOTE_PASSWORD);
    let other_local = candidate(Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), 100);
    f.agent
        .internal
        .handle_inbound(&mut valid, &other_local, f.remote.addr())
        .await;
    let other_remote = candidate(Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), 200);
    f.agent.internal.add_remote_candidate(&other_remote).await;
    f.agent
        .internal
        .handle_inbound(&mut valid, &f.local, other_remote.addr())
        .await;
    assert!(f.agent.internal.is_controlling.load(Ordering::SeqCst));
    assert_eq!(
        f.agent.internal.pending_binding_requests.lock().await.len(),
        1
    );
    f.deliver(&mut valid).await;
    assert!(!f.agent.internal.is_controlling.load(Ordering::SeqCst));
    f.agent.close().await.unwrap();
}

#[tokio::test]
async fn test_role_conflict_request_before_487_does_not_switch_back() {
    let f = Fixture::new(true, LOCAL_TIE).await;
    let check = f.send_check().await;
    let mut req = request(true, REMOTE_TIE, LOCAL_PASSWORD, true);
    f.deliver(&mut req).await;
    assert!(!f.agent.internal.is_controlling.load(Ordering::SeqCst));
    assert!(f.pair.nominate_on_binding_success.load(Ordering::SeqCst));
    let epoch = f.agent.internal.role_epoch.load(Ordering::SeqCst);
    f.deliver(&mut conflict_response(&check, REMOTE_PASSWORD))
        .await;
    assert_eq!(f.agent.internal.role_epoch.load(Ordering::SeqCst), epoch);
    assert!(f.pair.nominate_on_binding_success.load(Ordering::SeqCst));
    assert!(f.agent.internal.triggered_checks.lock().await.is_empty());
    f.agent.close().await.unwrap();
}

#[tokio::test]
async fn test_role_conflict_ignores_attributes_after_integrity() {
    let f = Fixture::new(true, LOCAL_TIE).await;
    let mut req = Message::new();
    req.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, "local:remote".into())),
        Box::new(MessageIntegrity::new_short_term_integrity(
            LOCAL_PASSWORD.into(),
        )),
        Box::new(AttrControlling(REMOTE_TIE)),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    MessageIntegrity::new_short_term_integrity(LOCAL_PASSWORD.into())
        .check(&mut req)
        .unwrap();
    f.deliver(&mut req).await;
    assert!(f.agent.internal.is_controlling.load(Ordering::SeqCst));

    let check = f.send_check().await;
    let mut response = Message::new();
    response
        .build(&[
            Box::new(check),
            Box::new(BINDING_ERROR),
            Box::new(MessageIntegrity::new_short_term_integrity(
                REMOTE_PASSWORD.into(),
            )),
            Box::new(CODE_ROLE_CONFLICT),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    MessageIntegrity::new_short_term_integrity(REMOTE_PASSWORD.into())
        .check(&mut response)
        .unwrap();
    f.deliver(&mut response).await;
    assert!(f.agent.internal.is_controlling.load(Ordering::SeqCst));
    assert_eq!(
        f.agent.internal.pending_binding_requests.lock().await.len(),
        1
    );
    f.agent.close().await.unwrap();
}

#[tokio::test]
async fn test_role_conflict_stale_response_after_two_switches() {
    let f = Fixture::new(true, LOCAL_TIE).await;
    let old_check = f.send_check().await;
    // A controlling peer wins, then a controlled peer loses, returning us to
    // the original role. Comparing only the role boolean would accept old_check.
    f.deliver(&mut request(true, REMOTE_TIE, LOCAL_PASSWORD, false))
        .await;
    f.deliver(&mut request(false, 1, LOCAL_PASSWORD, false))
        .await;
    let epoch = f.agent.internal.role_epoch.load(Ordering::SeqCst);
    assert_eq!(epoch, 2);
    f.deliver(&mut conflict_response(&old_check, REMOTE_PASSWORD))
        .await;
    assert!(f.agent.internal.is_controlling.load(Ordering::SeqCst));
    assert_eq!(f.agent.internal.role_epoch.load(Ordering::SeqCst), epoch);
    f.agent.close().await.unwrap();
}

#[tokio::test]
async fn test_role_conflict_restart_clears_triggered_checks() {
    let f = Fixture::new(true, LOCAL_TIE).await;
    let check = f.send_check().await;
    f.deliver(&mut conflict_response(&check, REMOTE_PASSWORD))
        .await;
    assert_eq!(f.agent.internal.triggered_checks.lock().await.len(), 1);
    f.agent.restart(String::new(), String::new()).await.unwrap();
    assert!(f.agent.internal.triggered_checks.lock().await.is_empty());
    assert!(f
        .agent
        .internal
        .pending_binding_requests
        .lock()
        .await
        .is_empty());
    f.agent.close().await.unwrap();
}

#[tokio::test]
async fn test_role_conflict_expired_response_is_ignored() {
    let f = Fixture::new(true, LOCAL_TIE).await;
    let check = f.send_check().await;
    f.agent.internal.pending_binding_requests.lock().await[0].timestamp =
        Instant::now() - MAX_BINDING_REQUEST_TIMEOUT - Duration::from_secs(1);
    f.deliver(&mut conflict_response(&check, REMOTE_PASSWORD))
        .await;
    assert!(f.agent.internal.is_controlling.load(Ordering::SeqCst));
    assert_eq!(
        f.agent.internal.tie_breaker.load(Ordering::SeqCst),
        LOCAL_TIE
    );
    assert!(f
        .agent
        .internal
        .pending_binding_requests
        .lock()
        .await
        .is_empty());
    assert!(f.agent.internal.triggered_checks.lock().await.is_empty());
    f.agent.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_role_conflict_connects_and_transfers_data() {
    for controlling in [true, false] {
        for equal_ties in [false, true] {
            let a = Fixture::new(controlling, LOCAL_TIE).await;
            let b =
                Fixture::new(controlling, if equal_ties { LOCAL_TIE } else { REMOTE_TIE }).await;
            // Use the fixtures' local sockets as real receiving candidates; the
            // fixture peer sockets are only used by the packet-level tests above.
            a.agent.internal.agent_conn.checklist.lock().await.clear();
            b.agent.internal.agent_conn.checklist.lock().await.clear();
            a.agent.internal.remote_candidates.lock().await.clear();
            b.agent.internal.remote_candidates.lock().await.clear();
            a.agent.internal.add_candidate(&a.local).await.unwrap();
            b.agent.internal.add_candidate(&b.local).await.unwrap();
            a.agent.internal.add_remote_candidate(&b.local).await;
            b.agent.internal.add_remote_candidate(&a.local).await;
            let (cancel_a, rx_a) = mpsc::channel(1);
            let (cancel_b, rx_b) = mpsc::channel(1);
            let connections = async {
                tokio::join!(
                    connect(&a, controlling, rx_a),
                    connect(&b, controlling, rx_b)
                )
            };
            let (conn_a, conn_b) = timeout(Duration::from_secs(5), connections).await.unwrap();
            assert_ne!(
                a.agent.internal.is_controlling.load(Ordering::SeqCst),
                b.agent.internal.is_controlling.load(Ordering::SeqCst)
            );
            for (sender, receiver) in [(&conn_a, &conn_b), (&conn_b, &conn_a)] {
                sender.send(b"role conflict recovered").await.unwrap();
                let mut data = [0; 128];
                let n = timeout(Duration::from_secs(1), receiver.recv(&mut data))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&data[..n], b"role conflict recovered");
            }
            drop((cancel_a, cancel_b));
            a.agent.close().await.unwrap();
            b.agent.close().await.unwrap();
        }
    }
}
