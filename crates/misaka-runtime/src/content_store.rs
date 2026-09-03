use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Filesystem-only content-addressed storage for verified transfer payloads.
#[derive(Debug, Clone)]
pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn object_path(&self, digest: [u8; 32]) -> PathBuf {
        self.root.join(hex_digest(digest))
    }

    pub async fn contains(&self, digest: [u8; 32]) -> std::io::Result<bool> {
        let object = self.object_path(digest);
        if !tokio::fs::try_exists(&object).await? {
            return Ok(false);
        }
        Ok(hash_file(&object).await? == digest)
    }

    /// Verify a partial file, then make it available under its digest path.
    /// The source is removed only after the canonical object is safe.
    pub async fn commit_verified_file(
        &self,
        partial: &Path,
        digest: [u8; 32],
    ) -> std::io::Result<PathBuf> {
        if hash_file(partial).await? != digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "content store digest mismatch",
            ));
        }
        tokio::fs::create_dir_all(&self.root).await?;
        let object = self.object_path(digest);
        if tokio::fs::try_exists(&object).await? {
            if hash_file(&object).await? == digest {
                tokio::fs::remove_file(partial).await?;
                return Ok(object);
            }
            tokio::fs::remove_file(&object).await?;
        }

        let temp = self.root.join(format!(
            ".{}.tmp-{}",
            hex_digest(digest),
            uuid::Uuid::new_v4()
        ));
        tokio::fs::copy(partial, &temp).await?;
        match tokio::fs::rename(&temp, &object).await {
            Ok(()) => {
                tokio::fs::remove_file(partial).await?;
                Ok(object)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing_is_valid = hash_file(&object).await? == digest;
                let _ = tokio::fs::remove_file(&temp).await;
                if existing_is_valid {
                    tokio::fs::remove_file(partial).await?;
                    Ok(object)
                } else {
                    tokio::fs::remove_file(&object).await?;
                    Err(error)
                }
            }
            Err(error) => {
                let _ = tokio::fs::remove_file(&temp).await;
                Err(error)
            }
        }
    }

    /// Copy a canonical object to a requested destination using a same-directory
    /// temporary file so readers never observe a half-materialized destination.
    pub async fn materialize(&self, digest: [u8; 32], destination: &Path) -> std::io::Result<u64> {
        let object = self.object_path(digest);
        if hash_file(&object).await? != digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "content store object digest mismatch",
            ));
        }
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temp = PathBuf::from(format!(
            "{}.misaka-materialize-{}",
            destination.display(),
            uuid::Uuid::new_v4()
        ));
        let bytes = tokio::fs::copy(&object, &temp).await?;
        match tokio::fs::rename(&temp, destination).await {
            Ok(()) => Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                tokio::fs::remove_file(destination).await?;
                tokio::fs::rename(temp, destination).await?;
                Ok(bytes)
            }
            Err(error) => {
                let _ = tokio::fs::remove_file(&temp).await;
                Err(error)
            }
        }
    }
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::ContentStore;
    use misaka_core::protocol::transfer_content_digest;

    #[tokio::test]
    async fn commits_deduplicates_and_materializes_content() {
        let directory =
            std::env::temp_dir().join(format!("misaka-content-store-{}", uuid::Uuid::new_v4()));
        let partial = directory.join("incoming.part");
        let first_destination = directory.join("nested/first.bin");
        let second_destination = directory.join("nested/second.bin");
        let payload = b"content-addressed transfer payload".repeat(4096);
        tokio::fs::create_dir_all(&directory).await.unwrap();
        tokio::fs::write(&partial, &payload).await.unwrap();
        let digest = transfer_content_digest(&payload);
        let store = ContentStore::new(directory.join("objects"));

        let object = store.commit_verified_file(&partial, digest).await.unwrap();
        assert_eq!(object, store.object_path(digest));
        assert!(object.exists());
        assert!(!partial.exists());

        let second_partial = directory.join("incoming-again.part");
        tokio::fs::write(&second_partial, &payload).await.unwrap();
        let duplicate = store
            .commit_verified_file(&second_partial, digest)
            .await
            .unwrap();
        assert_eq!(duplicate, object);
        assert!(!second_partial.exists());

        assert_eq!(
            store.materialize(digest, &first_destination).await.unwrap(),
            payload.len() as u64
        );
        store
            .materialize(digest, &second_destination)
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(first_destination).await.unwrap(), payload);
        assert_eq!(tokio::fs::read(second_destination).await.unwrap(), payload);
        let _ = tokio::fs::remove_dir_all(directory).await;
    }
}
