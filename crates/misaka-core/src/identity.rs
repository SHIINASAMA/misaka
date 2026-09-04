use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// Stable namespace identifier for one independent Misaka Network.
///
/// This is deliberately separate from both the display-oriented `SisterId`
/// and any backend transport identity such as an Iroh endpoint key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId(uuid::Uuid);

impl NetworkId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn parse(value: &str) -> Result<Self, uuid::Error> {
        uuid::Uuid::parse_str(value).map(Self)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(uuid::Uuid::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for NetworkId {
    fn default() -> Self {
        Self(uuid::Uuid::nil())
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for NetworkId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// 稳定身份，重启不变
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SisterId(pub u64);

impl SisterId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SisterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

const SISTER_PUBLIC_KEY_LEN: usize = 32;
const SISTER_SIGNATURE_LEN: usize = 64;

/// The stable cryptographic identity of one Sister.
///
/// The key is intentionally separate from `SisterId`: the numeric ID is a
/// display/routing handle, while this public key is used for authentication
/// and signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SisterPublicKey([u8; SISTER_PUBLIC_KEY_LEN]);

impl SisterPublicKey {
    pub fn from_bytes(bytes: [u8; SISTER_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; SISTER_PUBLIC_KEY_LEN] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; SISTER_PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn verify(&self, message: &[u8], signature: &SisterSignature) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        key.verify(message, &signature.as_dalek()).is_ok()
    }

    pub fn verify_challenge(
        &self,
        challenge: &KeyPossessionChallenge,
        signature: &SisterSignature,
    ) -> bool {
        self.verify(&challenge.signing_bytes(), signature)
    }
}

impl std::fmt::Display for SisterPublicKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_hex(&self.0, formatter)
    }
}

/// An Ed25519 signature carried by a Misaka contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SisterSignature([u8; SISTER_SIGNATURE_LEN]);

impl SisterSignature {
    pub fn from_bytes(bytes: [u8; SISTER_SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; SISTER_SIGNATURE_LEN] {
        self.0
    }

    fn as_dalek(&self) -> ed25519_dalek::Signature {
        ed25519_dalek::Signature::from_bytes(&self.0)
    }
}

impl Serialize for SisterSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SisterSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let bytes: [u8; SISTER_SIGNATURE_LEN] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            D::Error::custom(format!(
                "invalid Sister signature length: expected {SISTER_SIGNATURE_LEN}, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self(bytes))
    }
}

/// The private key for a Sister. It is not serializable and its `Debug`
/// representation never includes key material.
#[derive(Clone)]
pub struct SisterKeyPair(SigningKey);

impl std::fmt::Debug for SisterKeyPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SisterKeyPair(REDACTED)")
    }
}

impl SisterKeyPair {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> SisterPublicKey {
        SisterPublicKey(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> SisterSignature {
        SisterSignature(self.0.sign(message).to_bytes())
    }

    pub fn sign_challenge(&self, challenge: &KeyPossessionChallenge) -> SisterSignature {
        self.sign(&challenge.signing_bytes())
    }
}

/// Public key of the Network Authority. This is deliberately a separate type
/// from `SisterPublicKey`: authority governance is not a Sister runtime role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorityPublicKey([u8; SISTER_PUBLIC_KEY_LEN]);

impl AuthorityPublicKey {
    pub fn from_bytes(bytes: [u8; SISTER_PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; SISTER_PUBLIC_KEY_LEN] {
        self.0
    }

    pub fn verify(&self, message: &[u8], signature: &AuthoritySignature) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        key.verify(message, &signature.as_dalek()).is_ok()
    }
}

impl std::fmt::Display for AuthorityPublicKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_hex(&self.0, formatter)
    }
}

/// An Ed25519 signature made by a Network Authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthoritySignature([u8; SISTER_SIGNATURE_LEN]);

impl AuthoritySignature {
    fn as_dalek(&self) -> ed25519_dalek::Signature {
        ed25519_dalek::Signature::from_bytes(&self.0)
    }
}

impl Serialize for AuthoritySignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for AuthoritySignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let bytes: [u8; SISTER_SIGNATURE_LEN] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            D::Error::custom(format!(
                "invalid authority signature length: expected {SISTER_SIGNATURE_LEN}, got {}",
                bytes.len()
            ))
        })?;
        Ok(Self(bytes))
    }
}

/// The private governance key for one Network. It is never part of a Sister
/// runtime protocol message.
#[derive(Clone)]
pub struct AuthorityKeyPair(SigningKey);

impl std::fmt::Debug for AuthorityKeyPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuthorityKeyPair(REDACTED)")
    }
}

impl AuthorityKeyPair {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> AuthorityPublicKey {
        AuthorityPublicKey(self.0.verifying_key().to_bytes())
    }

    fn sign(&self, message: &[u8]) -> AuthoritySignature {
        AuthoritySignature(self.0.sign(message).to_bytes())
    }
}

/// Stable public descriptor of a Network's trust root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAuthority {
    pub network_id: NetworkId,
    pub authority_public_key: AuthorityPublicKey,
}

impl NetworkAuthority {
    pub fn generate(network_id: NetworkId) -> (Self, AuthorityKeyPair) {
        let key = AuthorityKeyPair::generate();
        (
            Self {
                network_id,
                authority_public_key: key.public_key(),
            },
            key,
        )
    }
}

/// Authority-signed proof that one Sister is a member of a Network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCertificate {
    pub network_id: NetworkId,
    pub sister_public_key: SisterPublicKey,
    pub sister_id: SisterId,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub serial: u64,
    pub authority_signature: AuthoritySignature,
}

#[derive(Serialize)]
struct MembershipCertificateUnsigned<'a> {
    network_id: NetworkId,
    sister_public_key: SisterPublicKey,
    sister_id: &'a SisterId,
    issued_at: u64,
    expires_at: Option<u64>,
    serial: u64,
}

impl MembershipCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        authority: &NetworkAuthority,
        authority_key: &AuthorityKeyPair,
        sister_public_key: SisterPublicKey,
        sister_id: u64,
        issued_at: u64,
        expires_at: Option<u64>,
        serial: u64,
    ) -> Self {
        let mut certificate = Self {
            network_id: authority.network_id,
            sister_public_key,
            sister_id: SisterId(sister_id),
            issued_at,
            expires_at,
            serial,
            authority_signature: AuthoritySignature([0; SISTER_SIGNATURE_LEN]),
        };
        certificate.authority_signature = authority_key.sign(&certificate.signing_bytes());
        certificate
    }

    pub fn verify(&self, authority: &NetworkAuthority) -> bool {
        self.network_id == authority.network_id
            && authority
                .authority_public_key
                .verify(&self.signing_bytes(), &self.authority_signature)
    }

    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        self.issued_at <= timestamp
            && self
                .expires_at
                .map(|expires_at| timestamp <= expires_at)
                .unwrap_or(true)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&MembershipCertificateUnsigned {
            network_id: self.network_id,
            sister_public_key: self.sister_public_key,
            sister_id: &self.sister_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            serial: self.serial,
        })
        .expect("membership certificate fields are serializable")
    }
}

/// Authority-signed revocation of a membership serial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub network_id: NetworkId,
    pub membership_serial: u64,
    pub revoked_at: u64,
    pub reason: String,
    pub authority_signature: AuthoritySignature,
}

#[derive(Serialize)]
struct RevocationRecordUnsigned<'a> {
    network_id: NetworkId,
    membership_serial: u64,
    revoked_at: u64,
    reason: &'a str,
}

impl RevocationRecord {
    pub fn issue(
        authority: &NetworkAuthority,
        authority_key: &AuthorityKeyPair,
        membership_serial: u64,
        revoked_at: u64,
        reason: String,
    ) -> Self {
        let mut record = Self {
            network_id: authority.network_id,
            membership_serial,
            revoked_at,
            reason,
            authority_signature: AuthoritySignature([0; SISTER_SIGNATURE_LEN]),
        };
        record.authority_signature = authority_key.sign(&record.signing_bytes());
        record
    }

    pub fn verify(&self, authority: &NetworkAuthority) -> bool {
        self.network_id == authority.network_id
            && authority
                .authority_public_key
                .verify(&self.signing_bytes(), &self.authority_signature)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&RevocationRecordUnsigned {
            network_id: self.network_id,
            membership_serial: self.membership_serial,
            revoked_at: self.revoked_at,
            reason: &self.reason,
        })
        .expect("revocation record fields are serializable")
    }
}

/// An Iroh endpoint identity represented without making `misaka-core` depend
/// on the Iroh transport crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IrohEndpointId([u8; 32]);

impl IrohEndpointId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Display for IrohEndpointId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_hex(&self.0, formatter)
    }
}

/// A signed assertion that an Iroh endpoint belongs to a Sister identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportBinding {
    pub network_id: NetworkId,
    pub sister_id: SisterId,
    pub sister_public_key: SisterPublicKey,
    pub iroh_endpoint_id: IrohEndpointId,
    pub sequence: u64,
    pub signature_by_sister_key: SisterSignature,
}

#[derive(Serialize)]
struct TransportBindingUnsigned<'a> {
    network_id: NetworkId,
    sister_id: &'a SisterId,
    sister_public_key: SisterPublicKey,
    iroh_endpoint_id: IrohEndpointId,
    sequence: u64,
}

impl TransportBinding {
    pub fn sign(
        network_id: NetworkId,
        sister_id: u64,
        iroh_endpoint_id: IrohEndpointId,
        sequence: u64,
        key: &SisterKeyPair,
    ) -> Self {
        let sister_public_key = key.public_key();
        let mut binding = Self {
            network_id,
            sister_id: SisterId(sister_id),
            sister_public_key,
            iroh_endpoint_id,
            sequence,
            signature_by_sister_key: SisterSignature([0; SISTER_SIGNATURE_LEN]),
        };
        binding.signature_by_sister_key = key.sign(&binding.signing_bytes());
        binding
    }

    pub fn verify(&self) -> bool {
        self.sister_public_key
            .verify(&self.signing_bytes(), &self.signature_by_sister_key)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&TransportBindingUnsigned {
            network_id: self.network_id,
            sister_id: &self.sister_id,
            sister_public_key: self.sister_public_key,
            iroh_endpoint_id: self.iroh_endpoint_id,
            sequence: self.sequence,
        })
        .expect("transport binding fields are serializable")
    }
}

/// A Sister-signed, transport-specific locator for another Sister.
///
/// The endpoint is kept as an opaque string in `misaka-core`; transport
/// parsing belongs to `misaka-network`. The signed binding still ties the
/// advertised endpoint identity to the Sister key and sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub network_id: NetworkId,
    pub sister_id: SisterId,
    pub sister_public_key: SisterPublicKey,
    pub endpoint_addr: String,
    pub transport_binding: TransportBinding,
    pub sequence: u64,
    pub updated_at: u64,
    pub sister_signature: SisterSignature,
}

#[derive(Serialize)]
struct PeerRecordUnsigned<'a> {
    network_id: NetworkId,
    sister_id: &'a SisterId,
    sister_public_key: SisterPublicKey,
    endpoint_addr: &'a str,
    transport_binding: &'a TransportBinding,
    sequence: u64,
    updated_at: u64,
}

impl PeerRecord {
    pub fn issue(
        network_id: NetworkId,
        sister_id: u64,
        endpoint_addr: String,
        transport_binding: TransportBinding,
        updated_at: u64,
        key: &SisterKeyPair,
    ) -> Self {
        let mut record = Self {
            network_id,
            sister_id: SisterId(sister_id),
            sister_public_key: key.public_key(),
            endpoint_addr,
            sequence: transport_binding.sequence,
            transport_binding,
            updated_at,
            sister_signature: SisterSignature([0; SISTER_SIGNATURE_LEN]),
        };
        record.sister_signature = key.sign(&record.signing_bytes());
        record
    }

    pub fn verify(&self) -> bool {
        self.network_id == self.transport_binding.network_id
            && self.sister_id == self.transport_binding.sister_id
            && self.sister_public_key == self.transport_binding.sister_public_key
            && self.sequence == self.transport_binding.sequence
            && self.transport_binding.verify()
            && self
                .sister_public_key
                .verify(&self.signing_bytes(), &self.sister_signature)
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&PeerRecordUnsigned {
            network_id: self.network_id,
            sister_id: &self.sister_id,
            sister_public_key: self.sister_public_key,
            endpoint_addr: &self.endpoint_addr,
            transport_binding: &self.transport_binding,
            sequence: self.sequence,
            updated_at: self.updated_at,
        })
        .expect("peer record fields are serializable")
    }
}

/// Authority-signed, portable Network bootstrap artifact.
///
/// A v0 invite may include a certificate for a pre-identified Sister. The
/// authority private key is never embedded in the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInvite {
    pub network_id: NetworkId,
    pub authority: NetworkAuthority,
    pub bootstrap_records: Vec<PeerRecord>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub invite_id: [u8; 16],
    pub membership: Option<MembershipCertificate>,
    pub authority_signature: AuthoritySignature,
}

#[derive(Serialize)]
struct NetworkInviteUnsigned<'a> {
    network_id: NetworkId,
    authority: NetworkAuthority,
    bootstrap_records: &'a [PeerRecord],
    issued_at: u64,
    expires_at: u64,
    invite_id: [u8; 16],
    membership: &'a Option<MembershipCertificate>,
}

impl NetworkInvite {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        authority: NetworkAuthority,
        authority_key: &AuthorityKeyPair,
        bootstrap_records: Vec<PeerRecord>,
        issued_at: u64,
        expires_at: u64,
        invite_id: [u8; 16],
        membership: Option<MembershipCertificate>,
    ) -> Self {
        let mut invite = Self {
            network_id: authority.network_id,
            authority,
            bootstrap_records,
            issued_at,
            expires_at,
            invite_id,
            membership,
            authority_signature: AuthoritySignature([0; SISTER_SIGNATURE_LEN]),
        };
        invite.authority_signature = authority_key.sign(&invite.signing_bytes());
        invite
    }

    pub fn verify(&self, now: u64) -> bool {
        self.network_id == self.authority.network_id
            && self.issued_at <= self.expires_at
            && self.issued_at <= now
            && now <= self.expires_at
            && self
                .authority
                .authority_public_key
                .verify(&self.signing_bytes(), &self.authority_signature)
            && self
                .bootstrap_records
                .iter()
                .all(|record| record.network_id == self.network_id && record.verify())
            && self.membership.as_ref().is_none_or(|membership| {
                membership.network_id == self.network_id
                    && membership.verify(&self.authority)
                    && membership.is_valid_at(now)
            })
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&NetworkInviteUnsigned {
            network_id: self.network_id,
            authority: self.authority,
            bootstrap_records: &self.bootstrap_records,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            invite_id: self.invite_id,
            membership: &self.membership,
        })
        .expect("network invite fields are serializable")
    }
}

/// A nonce scoped to one Misaka Network for proving possession of a Sister
/// private key during a future authenticated session handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPossessionChallenge {
    pub network_id: NetworkId,
    pub nonce: [u8; 32],
}

impl KeyPossessionChallenge {
    pub fn new(network_id: NetworkId, nonce: [u8; 32]) -> Self {
        Self { network_id, nonce }
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("challenge fields are serializable")
    }
}

fn write_hex(bytes: &[u8], formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// 用户可修改的显示名，与稳定 ID 分离
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Nickname(pub String);

impl Nickname {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Nickname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

/// 一个 Sister 的稳定身份。
///
/// 只包含领域数据；hostname 探测、文件系统持久化等 OS 行为在运行时层处理。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SisterIdentity {
    pub id: SisterId,
    pub nickname: Nickname,
    pub hostname: String,
    pub platform: String,
    pub version: String,
    pub listen_port: u16,
}

impl SisterIdentity {
    pub fn new(
        id: u64,
        nickname: String,
        hostname: String,
        platform: String,
        version: String,
        listen_port: u16,
    ) -> Self {
        Self {
            id: SisterId(id),
            nickname: Nickname(nickname),
            hostname,
            platform,
            version,
            listen_port,
        }
    }

    /// 友好的显示名称
    pub fn display_name(&self) -> String {
        format!("{} {}", self.id, self.nickname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_roundtrips_as_a_stable_uuid_string() {
        let id = NetworkId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(id.to_string(), "01234567-89ab-cdef-0123-456789abcdef");

        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"01234567-89ab-cdef-0123-456789abcdef\"");
        let decoded: NetworkId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn generated_network_ids_are_not_the_same_default_namespace() {
        let first = NetworkId::generate();
        let second = NetworkId::generate();
        assert_ne!(first, NetworkId::default());
        assert_ne!(first, second);
    }

    #[test]
    fn identity_roundtrips_json() {
        let id = SisterIdentity::new(
            10032,
            "Railgun".to_string(),
            "MacBook".to_string(),
            "macos aarch64".to_string(),
            "0.1.0".to_string(),
            31700,
        );
        let json = serde_json::to_string(&id).unwrap();
        let back: SisterIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
        assert_eq!(back.id.as_u64(), 10032);
        assert_eq!(back.nickname.as_str(), "Railgun");
    }

    #[test]
    fn display_name_formats_id_and_nick() {
        let id = SisterIdentity::new(
            10032,
            "Railgun".to_string(),
            "MacBook".to_string(),
            "macos aarch64".to_string(),
            "0.1.0".to_string(),
            31700,
        );
        assert_eq!(id.display_name(), "#10032 \"Railgun\"");
    }

    #[test]
    fn sister_key_signatures_verify_and_reject_tampering() {
        let key = SisterKeyPair::generate();
        let message = b"misaka sister challenge";
        let signature = key.sign(message);

        assert!(key.public_key().verify(message, &signature));
        assert!(!key.public_key().verify(b"tampered", &signature));
        assert_eq!(key.public_key().to_bytes().len(), 32);
        assert_eq!(signature.to_bytes().len(), 64);
    }

    #[test]
    fn sister_key_roundtrips_from_persisted_secret_bytes() {
        let first = SisterKeyPair::generate();
        let second = SisterKeyPair::from_bytes(first.to_bytes());

        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn transport_binding_signs_canonical_identity_data() {
        let network_id = NetworkId::generate();
        let key = SisterKeyPair::generate();
        let endpoint_id = IrohEndpointId::from_bytes([9u8; 32]);
        let binding = TransportBinding::sign(network_id, 42, endpoint_id, 0, &key);

        assert_eq!(binding.sister_public_key, key.public_key());
        assert!(binding.verify());

        let mut tampered = binding.clone();
        tampered.sequence = 1;
        assert!(!tampered.verify());
    }

    #[test]
    fn peer_record_is_signed_and_binds_transport_sequence() {
        let network_id = NetworkId::generate();
        let key = SisterKeyPair::generate();
        let binding = TransportBinding::sign(
            network_id,
            42,
            IrohEndpointId::from_bytes([9u8; 32]),
            3,
            &key,
        );
        let record =
            PeerRecord::issue(network_id, 42, "iroh://endpoint".into(), binding, 100, &key);
        assert!(record.verify());

        let mut tampered = record.clone();
        tampered.endpoint_addr = "iroh://different".into();
        assert!(!tampered.verify());

        let mut mismatched = record;
        mismatched.sequence = 4;
        assert!(!mismatched.verify());
    }

    #[test]
    fn key_possession_challenge_is_bound_to_network_and_nonce() {
        let network_id = NetworkId::generate();
        let key = SisterKeyPair::generate();
        let challenge = KeyPossessionChallenge::new(network_id, [3u8; 32]);
        let signature = key.sign_challenge(&challenge);

        assert!(key.public_key().verify_challenge(&challenge, &signature));
        assert!(!key.public_key().verify_challenge(
            &KeyPossessionChallenge::new(network_id, [4u8; 32]),
            &signature,
        ));
    }

    #[test]
    fn membership_certificate_verifies_only_for_its_authority_and_time_window() {
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let sister_key = SisterKeyPair::generate();
        let certificate = MembershipCertificate::issue(
            &authority,
            &authority_key,
            sister_key.public_key(),
            42,
            100,
            Some(200),
            7,
        );

        assert!(certificate.verify(&authority));
        assert!(certificate.is_valid_at(100));
        assert!(certificate.is_valid_at(200));
        assert!(!certificate.is_valid_at(99));
        assert!(!certificate.is_valid_at(201));

        let (other_authority, _) = NetworkAuthority::generate(NetworkId::generate());
        assert!(!certificate.verify(&other_authority));
    }

    #[test]
    fn revocation_record_is_signed_and_matches_membership_serial() {
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let record = RevocationRecord::issue(
            &authority,
            &authority_key,
            7,
            300,
            "operator request".into(),
        );

        assert!(record.verify(&authority));
        assert_eq!(record.membership_serial, 7);
        assert!(!record.verify(&NetworkAuthority::generate(NetworkId::generate()).0));
    }

    #[test]
    fn network_invite_binds_bootstrap_records_and_membership_to_authority() {
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let sister_key = SisterKeyPair::generate();
        let binding = TransportBinding::sign(
            network_id,
            42,
            IrohEndpointId::from_bytes([8u8; 32]),
            1,
            &sister_key,
        );
        let record = PeerRecord::issue(
            network_id,
            42,
            "iroh://bootstrap".into(),
            binding,
            100,
            &sister_key,
        );
        let membership = MembershipCertificate::issue(
            &authority,
            &authority_key,
            sister_key.public_key(),
            42,
            100,
            Some(200),
            1,
        );
        let invite = NetworkInvite::issue(
            authority,
            &authority_key,
            vec![record],
            100,
            200,
            [4u8; 16],
            Some(membership),
        );

        assert!(invite.verify(100));
        assert!(invite.verify(200));
        assert!(!invite.verify(99));
        assert!(!invite.verify(201));

        let mut tampered = invite.clone();
        tampered.bootstrap_records[0].endpoint_addr = "iroh://forged".into();
        assert!(!tampered.verify(100));

        let mut wrong_network = invite;
        wrong_network.network_id = NetworkId::generate();
        assert!(!wrong_network.verify(100));
    }
}
