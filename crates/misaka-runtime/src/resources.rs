//! Resource observation services.
//!
//! Resource providers keep nondeterministic OS measurements out of scheduling
//! and state-management tests. Production uses `SysinfoResourceProvider`; tests
//! can inject `FixedResourceProvider` snapshots.

use misaka_core::ResourceSnapshot;

/// Source of a Sister's current resource snapshot.
pub trait ResourceProvider: Send {
    fn snapshot(&mut self) -> ResourceSnapshot;
}

/// Production resource provider backed by `sysinfo`.
pub struct SysinfoResourceProvider {
    system: sysinfo::System,
}

impl SysinfoResourceProvider {
    pub fn new() -> Self {
        Self {
            system: sysinfo::System::new(),
        }
    }
}

impl Default for SysinfoResourceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceProvider for SysinfoResourceProvider {
    fn snapshot(&mut self) -> ResourceSnapshot {
        self.system.refresh_cpu();
        self.system.refresh_memory();
        ResourceSnapshot {
            cpu_usage: self.system.global_cpu_info().cpu_usage(),
            memory_total: self.system.total_memory(),
            memory_used: self.system.used_memory(),
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: sysinfo::System::uptime(),
            capabilities: detect_capabilities(),
        }
    }
}

/// Deterministic provider for scheduler/component tests.
#[derive(Debug, Clone)]
pub struct FixedResourceProvider {
    snapshot: ResourceSnapshot,
}

impl FixedResourceProvider {
    pub fn new(snapshot: ResourceSnapshot) -> Self {
        Self { snapshot }
    }
}

impl ResourceProvider for FixedResourceProvider {
    fn snapshot(&mut self) -> ResourceSnapshot {
        self.snapshot.clone()
    }
}

/// Capabilities available to commands executed by this runtime.
pub fn detect_capabilities() -> Vec<String> {
    let mut capabilities = Vec::new();
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        capabilities.push("posix-shell".to_string());
    }
    capabilities.push("unknown".to_string());
    capabilities
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_provider_returns_deterministic_snapshot() {
        let expected = ResourceSnapshot {
            cpu_usage: 12.5,
            memory_total: 100,
            memory_used: 25,
            running_jobs: 1,
            queued_jobs: 2,
            uptime_secs: 3,
            capabilities: vec!["test".to_string()],
        };
        let mut provider = FixedResourceProvider::new(expected.clone());
        assert_eq!(provider.snapshot().cpu_usage, expected.cpu_usage);
        assert_eq!(provider.snapshot().queued_jobs, expected.queued_jobs);
    }
}
