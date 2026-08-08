use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;

use crate::config::ConfigStore;
use crate::resource::{LocalSnap, NetHist, TabStatuses};
use crate::sftp::{SftpHandles, SftpLastCwd};
use crate::ssh::{CredentialResponder, HostKeyResponder, MfaResponder, SessionHandle};
use crate::terminal::{RenderGates, TermBuffers};
use crate::ui::AppWindow;

/// Shared dependencies for starting or reconnecting a session tab.
pub(crate) struct ConnectCtx {
    pub(crate) weak: slint::Weak<AppWindow>,
    pub(crate) runtime: Arc<Runtime>,
    pub(crate) handles: Rc<RefCell<HashMap<String, SessionHandle>>>,
    pub(crate) sftp_handles: SftpHandles,
    pub(crate) sftp_last_cwd: SftpLastCwd,
    pub(crate) bufs: TermBuffers,
    pub(crate) render_gates: RenderGates,
    pub(crate) tab_statuses: TabStatuses,
    pub(crate) local_snap: LocalSnap,
    pub(crate) local_net_hist: NetHist,
    pub(crate) last_term_size: Arc<Mutex<(u32, u32)>>,
    pub(crate) sftp_follow_cd: Arc<AtomicBool>,
    pub(crate) store: Rc<RefCell<ConfigStore>>,
}

pub(crate) struct PendingHostKey {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) changed: bool,
    pub(crate) title: String,
    pub(crate) message: String,
    pub(crate) detail: String,
    pub(crate) confirm_label: String,
    pub(crate) responders: Vec<HostKeyResponder>,
}

pub(crate) struct PendingCred {
    pub(crate) session_id: String,
    pub(crate) host: String,
    pub(crate) user: String,
    pub(crate) need_user: bool,
    pub(crate) need_password: bool,
    pub(crate) responders: Vec<CredentialResponder>,
}

pub(crate) struct PendingMfa {
    pub(crate) session_id: String,
    pub(crate) host: String,
    pub(crate) prompt: String,
    pub(crate) echo: bool,
    pub(crate) responders: Vec<MfaResponder>,
}
