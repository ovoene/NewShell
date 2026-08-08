#[path = "struct/resource_struct.rs"]
mod resource_struct;
#[path = "impls/system_impl.rs"]
pub(crate) mod system;

// LocalGpuInfo is only consumed by the Windows registry-based GPU enumeration
// (src/app.rs, cfg(target_os = "windows")), so re-export it conditionally to
// keep non-Windows builds warning-free.
pub(crate) use resource_struct::{
    LocalHardwareInfo, LocalSnap, NetHist, TabStatus, TabStatuses,
};
#[cfg(target_os = "windows")]
pub(crate) use resource_struct::LocalGpuInfo;
