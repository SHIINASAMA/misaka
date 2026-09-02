use crate::commands::{CommandExecutor, CommandResult};
use crate::state::LocalJob;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct JobQueue {
    inner: Arc<Mutex<VecDeque<LocalJob>>>,
}

impl JobQueue {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn push(&self, job: LocalJob) {
        self.inner.lock().unwrap().push_back(job);
    }

    pub fn pop(&self) -> Option<LocalJob> {
        self.inner.lock().unwrap().pop_front()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// 在本地同步执行一个任务并返回结果
    pub fn execute_locally(&self, job: &LocalJob) -> CommandResult {
        CommandExecutor::execute(&job.command).unwrap_or_else(|e| CommandResult {
            stdout: format!("Error: {}", e),
            stderr: String::new(),
            exit_code: -1,
        })
    }
}

impl Default for JobQueue {
    fn default() -> Self {
        Self::new()
    }
}
