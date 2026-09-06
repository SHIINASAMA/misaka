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

    /// Remove and return the first job satisfying `predicate`, leaving all others
    /// in order. Lets the work-stealing path take only jobs a requester is
    /// actually allowed to run, without dequeuing (and losing) others.
    pub fn pop_where(&self, predicate: impl Fn(&LocalJob) -> bool) -> Option<LocalJob> {
        let mut queue = self.inner.lock().unwrap();
        let index = queue.iter().position(predicate)?;
        queue.remove(index)
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
