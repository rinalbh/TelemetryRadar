use super::{Error, Result, v1::*};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{broadcast, oneshot};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequest {
    pub request_id: u64,
    pub request: RequestPermissionRequest,
}

struct Pending {
    request: RequestPermissionRequest,
    response: oneshot::Sender<RequestPermissionOutcome>,
}

#[derive(Default)]
struct State {
    pending: HashMap<u64, Pending>,
    cancelled: HashSet<SessionId>,
}

#[derive(Clone)]
pub(super) struct Permissions {
    state: Arc<Mutex<State>>,
    next_id: Arc<AtomicU64>,
    events: broadcast::Sender<PermissionRequest>,
}

impl Permissions {
    pub fn new() -> Self {
        Self {
            state: Arc::default(),
            next_id: Arc::default(),
            events: broadcast::channel(32).0,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PermissionRequest> {
        self.events.subscribe()
    }

    pub fn begin_turn(&self, session: &SessionId) {
        self.state.lock().unwrap().cancelled.remove(session);
    }

    pub fn cancel(&self, session: &SessionId) {
        let mut state = self.state.lock().unwrap();
        state.cancelled.insert(session.clone());
        // Dropping the senders answers all outstanding requests as cancelled.
        state
            .pending
            .retain(|_, pending| &pending.request.session_id != session);
    }

    pub async fn request(&self, request: RequestPermissionRequest) -> RequestPermissionOutcome {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (response, receive) = oneshot::channel();
        {
            let mut state = self.state.lock().unwrap();
            if state.cancelled.contains(&request.session_id) {
                return RequestPermissionOutcome::Cancelled;
            }
            state.pending.insert(
                request_id,
                Pending {
                    request: request.clone(),
                    response,
                },
            );
        }
        let _guard = PendingGuard {
            permissions: self.clone(),
            request_id,
        };
        if self
            .events
            .send(PermissionRequest {
                request_id,
                request,
            })
            .is_err()
        {
            return RequestPermissionOutcome::Cancelled;
        }
        receive.await.unwrap_or(RequestPermissionOutcome::Cancelled)
    }

    pub fn respond(&self, request_id: u64, option: Option<PermissionOptionId>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let pending = state
            .pending
            .get(&request_id)
            .ok_or(Error::Permission("request is no longer pending"))?;
        if let Some(id) = &option
            && !pending
                .request
                .options
                .iter()
                .any(|option| &option.option_id == id)
        {
            return Err(Error::Permission("option was not offered by the agent"));
        }
        let pending = state.pending.remove(&request_id).unwrap();
        let outcome = option.map_or(RequestPermissionOutcome::Cancelled, |id| {
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(id))
        });
        pending
            .response
            .send(outcome)
            .map_err(|_| Error::Permission("request has ended"))
    }
}

struct PendingGuard {
    permissions: Permissions,
    request_id: u64,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.permissions
            .state
            .lock()
            .unwrap()
            .pending
            .remove(&self.request_id);
    }
}
