use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Command not found: {0}")]
    NotFound(String),
    #[error("Execution error: {0}")]
    Execution(String),
}

/// 基础命令执行器
pub struct CommandExecutor;

impl CommandExecutor {
    /// 执行单个命令并返回输出 (stdout + stderr)
    pub fn execute(cmd: &str) -> Result<CommandResult, CommandError> {
        // 在 Unix 上使用 sh -c，Windows 使用 cmd /C
        #[cfg(unix)]
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .map_err(|e| CommandError::Execution(e.to_string()))?;

        #[cfg(windows)]
        let output = Command::new("cmd")
            .arg("/C")
            .arg(cmd)
            .output()
            .map_err(|e| CommandError::Execution(e.to_string()))?;

        Ok(CommandResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }

    /// 执行 pwd 命令
    pub fn pwd() -> Result<CommandResult, CommandError> {
        Self::execute("pwd")
    }

    /// 执行 ls 命令
    pub fn ls(path: Option<&str>) -> Result<CommandResult, CommandError> {
        let cmd = if let Some(p) = path {
            format!("ls -la {}", p)
        } else {
            "ls -la".to_string()
        };
        Self::execute(&cmd)
    }

    /// 执行 cat 命令读取文件
    pub fn cat(path: &str) -> Result<CommandResult, CommandError> {
        Self::execute(&format!("cat {}", path))
    }

    /// 执行 ps 命令查看进程
    pub fn ps() -> Result<CommandResult, CommandError> {
        #[cfg(unix)]
        let cmd = "ps aux";

        #[cfg(windows)]
        let cmd = "tasklist";

        Self::execute(cmd)
    }

    /// 执行 whoami 命令
    pub fn whoami() -> Result<CommandResult, CommandError> {
        Self::execute("whoami")
    }

    /// 执行 uname -a 获取系统信息
    pub fn uname() -> Result<CommandResult, CommandError> {
        Self::execute("uname -a")
    }

    /// 执行 uptime 命令
    pub fn uptime() -> Result<CommandResult, CommandError> {
        #[cfg(unix)]
        let cmd = "uptime";

        #[cfg(windows)]
        let cmd = "systeminfo | findstr /C:\"System Uptime\"";

        Self::execute(cmd)
    }
}

/// 命令执行结果
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl CommandResult {
    /// 合并 stdout 和 stderr 为完整输出
    pub fn full_output(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }

    /// 判断命令是否成功执行
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whoami() {
        let result = CommandExecutor::whoami().unwrap();
        assert!(!result.stdout.trim().is_empty());
    }

    #[test]
    fn test_pwd() {
        let result = CommandExecutor::pwd().unwrap();
        assert!(result.success());
    }
}
