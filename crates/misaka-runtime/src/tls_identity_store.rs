use misaka_network::tls::TlsIdentity;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsIdentityStoreError {
    #[error("TLS identity I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS identity generation failed: {0}")]
    Generate(String),
}

/// Filesystem persistence for a Sister's TLS identity.
///
/// Certificate and private key material is kept separate from the numeric
/// `SisterIdentity` JSON so the transport credential can evolve independently.
pub struct TlsIdentityStore;

impl TlsIdentityStore {
    pub fn load_or_init(
        directory: &Path,
        server_name: &str,
    ) -> Result<TlsIdentity, TlsIdentityStoreError> {
        let certificate_path = directory.join("stream-cert.der");
        let private_key_path = directory.join("stream-key.der");
        let certificate_exists = certificate_path.exists();
        let private_key_exists = private_key_path.exists();

        match (certificate_exists, private_key_exists) {
            (true, true) => Ok(TlsIdentity::from_der(
                std::fs::read(certificate_path)?,
                std::fs::read(private_key_path)?,
            )),
            (false, false) => {
                std::fs::create_dir_all(directory)?;
                let generated =
                    rcgen::generate_simple_self_signed(vec![server_name.to_string()])
                        .map_err(|error| TlsIdentityStoreError::Generate(error.to_string()))?;
                let certificate = generated.cert.der().to_vec();
                let private_key = generated.key_pair.serialize_der();
                std::fs::write(&certificate_path, &certificate)?;
                write_private_key(&private_key_path, &private_key)?;
                Ok(TlsIdentity::from_der(certificate, private_key))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLS certificate and private key must either both exist or both be absent",
            )
            .into()),
        }
    }
}

fn write_private_key(path: &PathBuf, key: &[u8]) -> Result<(), std::io::Error> {
    std::fs::write(path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::TlsIdentityStore;

    #[test]
    fn generated_tls_identity_is_stable_in_a_data_directory() {
        let directory =
            std::env::temp_dir().join(format!("misaka-tls-identity-{}", uuid::Uuid::new_v4()));

        let first = TlsIdentityStore::load_or_init(&directory, "sister-42").unwrap();
        let certificate = first.certificate_der().to_vec();
        let second = TlsIdentityStore::load_or_init(&directory, "sister-42").unwrap();

        assert_eq!(second.certificate_der(), certificate.as_slice());
        assert!(directory.join("stream-cert.der").exists());
        assert!(directory.join("stream-key.der").exists());
        let _ = std::fs::remove_dir_all(directory);
    }
}
