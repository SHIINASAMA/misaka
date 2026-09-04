use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version of the authenticated Iroh session handshake.
pub const AUTH_SESSION_PROTOCOL_VERSION: u16 = 1;

/// Current version of the encrypted wire envelope.
pub const PROTOCOL_VERSION: u16 = 3;
/// Service preamble for the v0 file-transfer stream.
pub const TRANSFER_MAGIC: &[u8; 4] = b"MTR0";
/// Service preamble for the resumable file-transfer stream.
pub const TRANSFER_V1_MAGIC: &[u8; 4] = b"MTR1";
/// Service preamble for the opt-in parallel-chunk transfer stream.
pub const TRANSFER_V2_MAGIC: &[u8; 4] = b"MTR2";
/// Service preamble for the v0 TCP tunnel stream.
pub const TUNNEL_MAGIC: &[u8; 4] = b"MTN0";
/// Fixed v1 chunk size used by the resumable transfer protocol.
pub const TRANSFER_V1_CHUNK_SIZE: u32 = 64 * 1024;

const TRANSFER_DIGEST_PRIME: u64 = 0x100000001b3;

/// Update the v0 transfer integrity digest. This is an integrity checksum,
/// not cryptographic authentication; secure streams rely on TLS for that.
pub fn update_transfer_digest(state: &mut [u64; 4], bytes: &[u8]) {
    for byte in bytes.iter().copied() {
        for lane in state.iter_mut() {
            *lane ^= u64::from(byte);
            *lane = (*lane).wrapping_mul(TRANSFER_DIGEST_PRIME);
        }
    }
}

pub fn finalize_transfer_digest(state: [u64; 4]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (index, lane) in state.iter().enumerate() {
        digest[index * 8..(index + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    digest
}

pub fn transfer_digest(bytes: &[u8]) -> [u8; 32] {
    let mut state = [
        0xcbf29ce484222325,
        0x84222325cbf29ce4,
        0x9e3779b185ebca87,
        0xd6e8feb86659fd93,
    ];
    update_transfer_digest(&mut state, bytes);
    finalize_transfer_digest(state)
}

/// Return the cryptographic content identifier used by Transfer v1.
pub fn transfer_content_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// 消息类型枚举 (对等网络，无主从之分)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Hello = 0x01,       // 握手：交换身份
    Heartbeat = 0x02,   // 心跳
    State = 0x03,       // 状态上报
    Job = 0x04,         // 下发任务
    JobRequest = 0x05,  // 请求任务 (Work Stealing)
    JobResponse = 0x06, // 任务结果返回
    Ack = 0x07,         // 通用确认
    Ping = 0x08,        // 无副作用的 reachability probe
    Pong = 0x09,        // Ping response
    PeerRecords = 0x0A, // Signed network knowledge exchange
}

/// 网络层封装的消息 (对等)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Namespace of the independent Misaka Network.
    #[serde(default)]
    pub network_id: super::identity::NetworkId,
    pub protocol_version: u16,
    pub msg_type: MessageType,
    pub from: u64,     // 发送方 Sister ID
    pub to: u64,       // 接收方 Sister ID (0 = 广播)
    pub data: Vec<u8>, // bincode 序列化后的具体 payload
}

impl Envelope {
    pub fn new(
        network_id: super::identity::NetworkId,
        msg_type: MessageType,
        from: u64,
        to: u64,
        data: Vec<u8>,
    ) -> Self {
        Self {
            network_id,
            protocol_version: PROTOCOL_VERSION,
            msg_type,
            from,
            to,
            data,
        }
    }
}

/// 握手 payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloData {
    /// Namespace of the independent Misaka Network.
    pub network_id: super::identity::NetworkId,
    pub identity: super::identity::SisterIdentity,
    /// 发送方自己声明的监听地址，用于建 peer 表 (不要用 TCP 源地址)
    pub listen_addr: String,
    /// Optional candidate address for the long-lived stream listener.
    pub stream_addr: Option<String>,
    /// Optional DER certificate used to pin the secure stream peer.
    pub stream_certificate: Option<Vec<u8>>,
}

/// Small, signed peer knowledge exchange carried by the control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecordsData {
    pub network_id: super::identity::NetworkId,
    pub records: Vec<super::identity::PeerRecord>,
}

/// 状态 payload —— Sister 上报自身局部状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateData {
    /// Namespace of the independent Misaka Network.
    pub network_id: super::identity::NetworkId,
    pub identity: super::identity::SisterIdentity,
    /// 发送方自己声明的监听地址，用于建 peer 表 (不要用 TCP 源地址)
    pub listen_addr: String,
    /// Optional candidate address for the long-lived stream listener.
    pub stream_addr: Option<String>,
    /// Optional DER certificate used to pin the secure stream peer.
    pub stream_certificate: Option<Vec<u8>>,
    pub cpu_usage: f32,
    pub memory_total: u64,
    pub memory_used: u64,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub uptime_secs: u64,
    pub capabilities: Vec<String>,
}

/// First message in an authenticated Iroh logical stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticatedClientHello {
    pub protocol_version: u16,
    pub network_id: super::identity::NetworkId,
    pub sister_id: super::identity::SisterId,
    pub sister_public_key: super::identity::SisterPublicKey,
    pub membership_certificate: super::identity::MembershipCertificate,
    pub transport_binding: super::identity::TransportBinding,
    pub nonce: [u8; 32],
    pub signature: super::identity::SisterSignature,
}

#[derive(Serialize)]
struct AuthenticatedClientHelloUnsigned<'a> {
    protocol_version: u16,
    network_id: super::identity::NetworkId,
    sister_id: &'a super::identity::SisterId,
    sister_public_key: super::identity::SisterPublicKey,
    membership_certificate: &'a super::identity::MembershipCertificate,
    transport_binding: &'a super::identity::TransportBinding,
    nonce: [u8; 32],
}

impl AuthenticatedClientHello {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        network_id: super::identity::NetworkId,
        sister_id: u64,
        sister_public_key: super::identity::SisterPublicKey,
        membership_certificate: super::identity::MembershipCertificate,
        transport_binding: super::identity::TransportBinding,
        nonce: [u8; 32],
        key: &super::identity::SisterKeyPair,
    ) -> Self {
        let mut hello = Self {
            protocol_version: AUTH_SESSION_PROTOCOL_VERSION,
            network_id,
            sister_id: super::identity::SisterId(sister_id),
            sister_public_key,
            membership_certificate,
            transport_binding,
            nonce,
            signature: super::identity::SisterSignature::from_bytes([0; 64]),
        };
        hello.signature = key.sign(&hello.signing_bytes());
        hello
    }

    pub fn verify_signature(&self) -> bool {
        self.sister_public_key
            .verify(&self.signing_bytes(), &self.signature)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&AuthenticatedClientHelloUnsigned {
            protocol_version: self.protocol_version,
            network_id: self.network_id,
            sister_id: &self.sister_id,
            sister_public_key: self.sister_public_key,
            membership_certificate: &self.membership_certificate,
            transport_binding: &self.transport_binding,
            nonce: self.nonce,
        })
        .expect("authenticated client hello fields are serializable")
    }
}

/// Server response in an authenticated Iroh logical stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticatedServerHello {
    pub protocol_version: u16,
    pub network_id: super::identity::NetworkId,
    pub sister_id: super::identity::SisterId,
    pub sister_public_key: super::identity::SisterPublicKey,
    pub membership_certificate: super::identity::MembershipCertificate,
    pub transport_binding: super::identity::TransportBinding,
    pub client_nonce: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: super::identity::SisterSignature,
}

#[derive(Serialize)]
struct AuthenticatedServerHelloUnsigned<'a> {
    protocol_version: u16,
    network_id: super::identity::NetworkId,
    sister_id: &'a super::identity::SisterId,
    sister_public_key: super::identity::SisterPublicKey,
    membership_certificate: &'a super::identity::MembershipCertificate,
    transport_binding: &'a super::identity::TransportBinding,
    client_nonce: [u8; 32],
    nonce: [u8; 32],
}

impl AuthenticatedServerHello {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        network_id: super::identity::NetworkId,
        sister_id: u64,
        sister_public_key: super::identity::SisterPublicKey,
        membership_certificate: super::identity::MembershipCertificate,
        transport_binding: super::identity::TransportBinding,
        client_nonce: [u8; 32],
        nonce: [u8; 32],
        key: &super::identity::SisterKeyPair,
    ) -> Self {
        let mut hello = Self {
            protocol_version: AUTH_SESSION_PROTOCOL_VERSION,
            network_id,
            sister_id: super::identity::SisterId(sister_id),
            sister_public_key,
            membership_certificate,
            transport_binding,
            client_nonce,
            nonce,
            signature: super::identity::SisterSignature::from_bytes([0; 64]),
        };
        hello.signature = key.sign(&hello.signing_bytes());
        hello
    }

    pub fn verify_signature(&self) -> bool {
        self.sister_public_key
            .verify(&self.signing_bytes(), &self.signature)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&AuthenticatedServerHelloUnsigned {
            protocol_version: self.protocol_version,
            network_id: self.network_id,
            sister_id: &self.sister_id,
            sister_public_key: self.sister_public_key,
            membership_certificate: &self.membership_certificate,
            transport_binding: &self.transport_binding,
            client_nonce: self.client_nonce,
            nonce: self.nonce,
        })
        .expect("authenticated server hello fields are serializable")
    }
}

#[cfg(test)]
mod network_id_tests {
    use super::{HelloData, StateData};
    use crate::{NetworkId, SisterIdentity};

    fn identity() -> SisterIdentity {
        SisterIdentity::new(
            7,
            "alpha".into(),
            "host".into(),
            "test".into(),
            "0.1".into(),
            31700,
        )
    }

    #[test]
    fn hello_roundtrips_network_id() {
        let value = HelloData {
            network_id: NetworkId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap(),
            identity: identity(),
            listen_addr: "127.0.0.1:31700".into(),
            stream_addr: None,
            stream_certificate: None,
        };
        let decoded: HelloData =
            bincode::deserialize(&bincode::serialize(&value).unwrap()).unwrap();
        assert_eq!(decoded.network_id, value.network_id);
    }

    #[test]
    fn state_roundtrips_network_id() {
        let value = StateData {
            network_id: NetworkId::generate(),
            identity: identity(),
            listen_addr: "127.0.0.1:31700".into(),
            stream_addr: None,
            stream_certificate: None,
            cpu_usage: 0.0,
            memory_total: 1,
            memory_used: 1,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 1,
            capabilities: vec![],
        };
        let decoded: StateData =
            bincode::deserialize(&bincode::serialize(&value).unwrap()).unwrap();
        assert_eq!(decoded.network_id, value.network_id);
    }

    #[test]
    fn hello_rejects_missing_network_id() {
        let value = HelloData {
            network_id: NetworkId::generate(),
            identity: identity(),
            listen_addr: "127.0.0.1:31700".into(),
            stream_addr: None,
            stream_certificate: None,
        };
        let mut json = serde_json::to_value(value).unwrap();
        json.as_object_mut().unwrap().remove("network_id");
        assert!(serde_json::from_value::<HelloData>(json).is_err());
    }

    #[test]
    fn state_rejects_missing_network_id() {
        let value = StateData {
            network_id: NetworkId::generate(),
            identity: identity(),
            listen_addr: "127.0.0.1:31700".into(),
            stream_addr: None,
            stream_certificate: None,
            cpu_usage: 0.0,
            memory_total: 1,
            memory_used: 1,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 1,
            capabilities: vec![],
        };
        let mut json = serde_json::to_value(value).unwrap();
        json.as_object_mut().unwrap().remove("network_id");
        assert!(serde_json::from_value::<StateData>(json).is_err());
    }
}

#[cfg(test)]
mod authenticated_session_tests {
    use super::{AuthenticatedClientHello, AuthenticatedServerHello};
    use crate::{
        IrohEndpointId, MembershipCertificate, NetworkAuthority, NetworkId, SisterKeyPair,
        TransportBinding,
    };

    fn fixture() -> (
        NetworkId,
        SisterKeyPair,
        MembershipCertificate,
        TransportBinding,
        NetworkAuthority,
    ) {
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let sister_key = SisterKeyPair::generate();
        let certificate = MembershipCertificate::issue(
            &authority,
            &authority_key,
            sister_key.public_key(),
            7,
            1,
            None,
            1,
        );
        let binding = TransportBinding::sign(
            network_id,
            7,
            IrohEndpointId::from_bytes([8u8; 32]),
            0,
            &sister_key,
        );
        (network_id, sister_key, certificate, binding, authority)
    }

    #[test]
    fn authenticated_hello_signatures_cover_nonce_and_contracts() {
        let (network_id, key, certificate, binding, authority) = fixture();
        let client = AuthenticatedClientHello::sign(
            network_id,
            7,
            key.public_key(),
            certificate.clone(),
            binding.clone(),
            [1u8; 32],
            &key,
        );
        assert!(client.verify_signature());
        assert!(client.membership_certificate.verify(&authority));
        assert!(client.transport_binding.verify());

        let server = AuthenticatedServerHello::sign(
            network_id,
            7,
            key.public_key(),
            certificate,
            binding,
            client.nonce,
            [2u8; 32],
            &key,
        );
        assert!(server.verify_signature());

        let mut tampered = server;
        tampered.client_nonce = [9u8; 32];
        assert!(!tampered.verify_signature());
    }
}

/// 任务 payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobData {
    pub id: String,
    pub creator: u64,
    /// 预期执行者 (0 = 由接收方自行决定)
    pub executor: u64,
    pub creator_addr: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub created_at: u64,
    /// Optional human authorization. `None` is retained only for the legacy
    /// local/test compatibility mode; authenticated deployments should set it.
    #[serde(default)]
    pub authorization: Option<super::identity::CommandAuthorization>,
}

impl JobData {
    pub fn full_command(&self) -> String {
        if self.arguments.is_empty() {
            self.command.clone()
        } else {
            format!("{} {}", self.command, self.arguments.join(" "))
        }
    }
}

/// 任务结果 payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResultData {
    pub job_id: String,
    pub creator: u64,
    pub executor: u64,
    pub output: String,
    pub exit_code: i32,
    pub success: bool,
    pub started_at: u64,
    pub finished_at: u64,
}

/// Header for the v0 file-transfer service carried over a NetworkStream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferRequest {
    pub destination: String,
    pub size: u64,
    pub digest: [u8; 32],
    /// Human authorization for the file.send operation.
    #[serde(default)]
    pub authorization: Option<super::identity::CommandAuthorization>,
}

/// Completion result for a v0 file-transfer service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferResult {
    pub success: bool,
    pub bytes_written: u64,
    pub digest: [u8; 32],
    pub error: Option<String>,
}

/// Header for a resumable file transfer. The payload is sent as separately
/// framed chunks so a receiver can commit progress at chunk boundaries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferV1Request {
    pub destination: String,
    pub size: u64,
    pub digest: [u8; 32],
    pub chunk_size: u32,
    /// Human authorization for the file.send operation.
    #[serde(default)]
    pub authorization: Option<super::identity::CommandAuthorization>,
}

/// Receiver's durable progress for a resumable transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferV1Resume {
    pub offset: u64,
    pub complete: bool,
    pub error: Option<String>,
}

/// Metadata preceding one bounded transfer chunk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferV1Chunk {
    pub index: u64,
    pub offset: u64,
    pub len: u32,
    pub digest: [u8; 32],
}

/// Receiver acknowledgement after committing one chunk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferV1Ack {
    pub next_offset: u64,
    pub complete: bool,
    pub error: Option<String>,
}

/// Operation carried by one Transfer v2 control or worker stream.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferV2Operation {
    Prepare,
    Chunk,
    Finalize,
}

/// Request for the opt-in parallel-chunk transfer protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferV2Request {
    pub operation: TransferV2Operation,
    pub destination: String,
    pub size: u64,
    pub digest: [u8; 32],
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub index: u64,
    pub offset: u64,
    pub len: u32,
    pub chunk_digest: [u8; 32],
    /// Human authorization for the file.send operation.
    #[serde(default)]
    pub authorization: Option<super::identity::CommandAuthorization>,
}

/// Durable completed chunk indexes returned by a Transfer v2 prepare request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferV2Resume {
    pub completed_indices: Vec<u64>,
    pub complete: bool,
    pub error: Option<String>,
}

/// Acknowledgement for one Transfer v2 worker or finalize request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferV2Ack {
    pub index: u64,
    pub accepted: bool,
    pub complete: bool,
    pub error: Option<String>,
}

/// Request for a v0 TCP tunnel to a service reachable by the remote Sister.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelRequest {
    pub remote: String,
    /// Human authorization for tunnel.open or shell.open.
    #[serde(default)]
    pub authorization: Option<super::identity::CommandAuthorization>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrips_bincode() {
        use crate::NetworkId;
        let network_id = NetworkId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let env = Envelope::new(network_id, MessageType::State, 10032, 0, vec![1, 2, 3]);
        let bytes = bincode::serialize(&env).unwrap();
        let back: Envelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.protocol_version, PROTOCOL_VERSION);
        assert_eq!(back.network_id, network_id);
        assert_eq!(back.msg_type, MessageType::State);
        assert_eq!(back.from, 10032);
        assert_eq!(back.data, vec![1, 2, 3]);
    }

    #[test]
    fn job_data_full_command() {
        let j = JobData {
            id: "j1".into(),
            creator: 1,
            executor: 0,
            creator_addr: "127.0.0.1:1".into(),
            command: "echo".into(),
            arguments: vec!["a".into(), "b".into()],
            created_at: 0,
            authorization: None,
        };
        assert_eq!(j.full_command(), "echo a b");
    }

    #[test]
    fn transfer_contract_roundtrips_bincode() {
        let request = TransferRequest {
            destination: "/tmp/result.bin".into(),
            size: 3,
            digest: [7; 32],
            authorization: None,
        };
        let encoded = bincode::serialize(&request).unwrap();
        let decoded: TransferRequest = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn resumable_transfer_contract_roundtrips_bincode() {
        let request = TransferV1Request {
            destination: "/tmp/result.bin".into(),
            size: 131072,
            digest: [7; 32],
            chunk_size: TRANSFER_V1_CHUNK_SIZE,
            authorization: None,
        };
        let encoded = bincode::serialize(&request).unwrap();
        let decoded: TransferV1Request = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, request);

        let ack = TransferV1Ack {
            next_offset: 65536,
            complete: false,
            error: None,
        };
        let encoded = bincode::serialize(&ack).unwrap();
        assert_eq!(
            bincode::deserialize::<TransferV1Ack>(&encoded).unwrap(),
            ack
        );
    }

    #[test]
    fn transfer_digest_is_independent_of_chunking() {
        let input = b"chunk-safe transfer digest";
        let whole = transfer_digest(input);
        let mut state = [
            0xcbf29ce484222325,
            0x84222325cbf29ce4,
            0x9e3779b185ebca87,
            0xd6e8feb86659fd93,
        ];
        update_transfer_digest(&mut state, &input[..7]);
        update_transfer_digest(&mut state, &input[7..]);
        assert_eq!(finalize_transfer_digest(state), whole);
    }

    #[test]
    fn transfer_content_digest_uses_sha256() {
        assert_eq!(
            transfer_content_digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn transfer_v2_contract_roundtrips_bincode() {
        let requests = [
            TransferV2Request {
                operation: TransferV2Operation::Prepare,
                destination: "/tmp/file".into(),
                size: 131_072,
                digest: [7; 32],
                chunk_size: TRANSFER_V1_CHUNK_SIZE,
                chunk_count: 2,
                index: 0,
                offset: 0,
                len: 0,
                chunk_digest: [0; 32],
                authorization: None,
            },
            TransferV2Request {
                operation: TransferV2Operation::Chunk,
                destination: "/tmp/file".into(),
                size: 131_072,
                digest: [7; 32],
                chunk_size: TRANSFER_V1_CHUNK_SIZE,
                chunk_count: 2,
                index: 1,
                offset: 65_536,
                len: 65_536,
                chunk_digest: [8; 32],
                authorization: None,
            },
            TransferV2Request {
                operation: TransferV2Operation::Finalize,
                destination: "/tmp/file".into(),
                size: 131_072,
                digest: [7; 32],
                chunk_size: TRANSFER_V1_CHUNK_SIZE,
                chunk_count: 2,
                index: 0,
                offset: 0,
                len: 0,
                chunk_digest: [0; 32],
                authorization: None,
            },
        ];
        for request in requests {
            let encoded = bincode::serialize(&request).unwrap();
            let decoded: TransferV2Request = bincode::deserialize(&encoded).unwrap();
            assert_eq!(decoded, request);
        }

        let resume = TransferV2Resume {
            completed_indices: vec![0, 3],
            complete: false,
            error: None,
        };
        let encoded = bincode::serialize(&resume).unwrap();
        assert_eq!(
            bincode::deserialize::<TransferV2Resume>(&encoded).unwrap(),
            resume
        );

        let ack = TransferV2Ack {
            index: 1,
            accepted: true,
            complete: false,
            error: None,
        };
        let encoded = bincode::serialize(&ack).unwrap();
        assert_eq!(
            bincode::deserialize::<TransferV2Ack>(&encoded).unwrap(),
            ack
        );
    }

    #[test]
    fn tunnel_contract_roundtrips_bincode() {
        let request = TunnelRequest {
            remote: "127.0.0.1:22".into(),
            authorization: None,
        };
        let encoded = bincode::serialize(&request).unwrap();
        assert_eq!(
            bincode::deserialize::<TunnelRequest>(&encoded).unwrap(),
            request
        );
    }
}
