use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::resource::system::SystemSnapshot;
use crate::ssh::{ProcInfo, SystemDetails};

#[derive(Clone, Default)]
pub(crate) struct LocalHardwareInfo {
    pub(crate) os: String,
    pub(crate) kernel: String,
    pub(crate) kernel_version: String,
    pub(crate) arch: String,
    pub(crate) hostname: String,
    pub(crate) cpu_name: String,
    pub(crate) cpu_vendor: String,
    pub(crate) cpu_cores: String,
    pub(crate) cpu_frequency: String,
    pub(crate) gpus: Vec<LocalGpuInfo>,
}

#[derive(Clone, Default)]
pub(crate) struct LocalGpuInfo {
    pub(crate) name: String,
    pub(crate) vendor: String,
    pub(crate) driver: String,
    pub(crate) memory: String,
}

#[derive(Clone, Default)]
pub(crate) struct TabStatus {
    pub(crate) host: String,
    pub(crate) user: String,
    pub(crate) session_id: String,
    pub(crate) state: u8,
    pub(crate) cpu: f32,
    pub(crate) mem_used_kib: u64,
    pub(crate) mem_total_kib: u64,
    pub(crate) swap_used_kib: u64,
    pub(crate) swap_total_kib: u64,
    pub(crate) net: Vec<(String, u64, u64)>,
    pub(crate) selected_iface: String,
    pub(crate) net_hist: Vec<f32>,
    pub(crate) disks: Vec<(String, u64, u64)>,
    pub(crate) procs: Vec<ProcInfo>,
    pub(crate) sys: SystemDetails,
    /// Remote host uptime in seconds (from the fast monitor sample). `None`
    /// until a sample carries it, or when the host can't report it.
    pub(crate) uptime_secs: Option<f64>,
}

pub(crate) type TabStatuses = Arc<Mutex<HashMap<String, TabStatus>>>;
pub(crate) type LocalSnap = Arc<Mutex<SystemSnapshot>>;
pub(crate) type NetHist = Arc<Mutex<Vec<f32>>>;
