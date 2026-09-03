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
}

impl Default for JobQueue {
    fn default() -> Self {
        Self::new()
    }
}
