// ╔════════════════════════════════════════════════════════════════════════════╗
// ║  OPT-IN STARTUP DIAGNOSTICS — OFF BY DEFAULT.                              ║
// ║  Settings → Interface → Diagnostics (设置 → 界面 → 诊断)                    ║
// ╚════════════════════════════════════════════════════════════════════════════╝
//
// Why this exists
// ---------------
// NewShell records no logs; that is a deliberate product decision. But a silent
// startup crash is impossible to diagnose from the field: `panic = "abort"`
// (Cargo.toml) kills the process instantly and `windows_subsystem = "windows"`
// (main.rs) means there is no console for the panic message to reach. That is
// exactly how the Windows 10 "taskbar icon appears, nothing paints, gone after
// ~5 s" failure stayed invisible — it turned out to be a re-entrant `RefCell`
// borrow inside Slint's AccessKit bridge, and only a written log could show it.
//
// So the machinery stays in the tree permanently, wired to a switch that is OFF
// by default. When something breaks, the user turns the switch on in a launch
// that still works, reproduces, and sends the file. Nobody has to re-instrument
// the code to chase the next one.
//
// What it writes (only while enabled)
// -----------------------------------
// One append-only text file, `newshell-diag.log`, next to the executable
// (falling back to %TEMP% when the exe directory is not writable):
//   * a header block per launch: version, OS build, console-vs-RDP session,
//     AC-vs-battery, the LIVE display-adapter list, SLINT_BACKEND;
//   * a timestamped breadcrumb per startup milestone, flushed immediately so it
//     survives `abort()`;
//   * every `tracing` event — which, via tracing-subscriber's log bridge, also
//     captures winit / glutin / femtovg messages;
//   * a `!! PANIC` line from a panic hook. Panic hooks DO still run under
//     `panic = "abort"`: abort skips unwinding, not the hook.
//
// Cost when disabled
// ------------------
// Zero I/O and no file is ever created. `mark` starts with one relaxed atomic
// load and returns; `TracingWriter` allocates nothing and discards its bytes.
//
// How to read it
// --------------
// Compare a failing launch against a good one. The last breadcrumb before the
// process disappears is the death point; a `!! PANIC` line names the exact
// source location. No panic line at all means the process died in native code
// (an SEH access violation), which a Rust panic hook cannot observe —
// cross-check Event Viewer → Windows Logs → Application.
//
// Lifecycle
// ---------
// * `install_panic_hook()` — called from `main` before anything else can fail.
// * `configure(on)`        — called from `app::run` once the config is loaded;
//                            flushes the breadcrumbs buffered until that point.
// * `set_enabled(on)`      — the UI switch; takes effect immediately.
//
// Escape hatch: `NEWSHELL_DIAG=1` forces logging on for one run even when the
// switch is off (or when the config itself is what fails to load); `=0` / `off`
// forces it off. The env var only decides the *startup* state — an explicit
// click on the switch always wins afterwards.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

/// Log file name, written next to the executable when possible.
const FILE_NAME: &str = "newshell-diag.log";
/// Start the file over once it passes this size, so repeated launches on a
/// user's machine can never fill the disk.
const MAX_BYTES: u64 = 1 << 20; // 1 MiB
/// Upper bound on breadcrumbs held in memory before the switch is known. Enough
/// for the whole startup path many times over; the cap only exists so a stall
/// before `configure` cannot grow without limit.
const MAX_PENDING: usize = 256;

struct Sink {
    file: File,
    /// The file actually opened — reported to the UI, which needs to show a
    /// path even when that path is the %TEMP% fallback.
    path: PathBuf,
}

/// The open log. `None` means logging is off, which is the default state.
static SINK: Mutex<Option<Sink>> = Mutex::new(None);
/// Lock-free mirror of `SINK.is_some()` so the disabled path never takes a lock.
static ARMED: AtomicBool = AtomicBool::new(false);
/// Breadcrumbs recorded before [`configure`] resolves the switch. Flushed on
/// enable, dropped on disable — so a failure *during config load* is still
/// captured without diag having to parse the config itself.
static PENDING: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Set once [`configure`] has run; after that, breadcrumbs are no longer
/// buffered (they either go to the file or nowhere).
static DECIDED: AtomicBool = AtomicBool::new(false);
/// Process start, pinned on the first diag call. Kept outside `Sink` so the
/// `+NNNNms` stamps stay on one timeline across enable/disable.
static START: OnceLock<Instant> = OnceLock::new();

/// Recover from a poisoned mutex rather than dropping the line — the most
/// valuable line of all (the panic) is written while a panic is in flight,
/// which is exactly when poisoning happens.
fn lock_sink() -> MutexGuard<'static, Option<Sink>> {
    SINK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_pending() -> MutexGuard<'static, Vec<String>> {
    PENDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write and flush immediately: `panic = "abort"` gives us no chance to flush
/// later, so every line must already be handed to the OS. No-op when off.
fn write_raw(bytes: &[u8]) {
    let mut guard = lock_sink();
    if let Some(sink) = guard.as_mut() {
        let _ = sink.file.write_all(bytes);
        let _ = sink.file.flush();
    }
}

/// `NEWSHELL_DIAG` as a tri-state: forced on, forced off, or unset.
fn env_override() -> Option<bool> {
    let value = std::env::var("NEWSHELL_DIAG").ok()?;
    let value = value.trim();
    if value == "0" || value.eq_ignore_ascii_case("off") || value.eq_ignore_ascii_case("false") {
        Some(false)
    } else if value.is_empty() {
        None
    } else {
        Some(true)
    }
}

/// Where the log goes: beside the executable, or %TEMP% when that directory
/// cannot be written (Program Files on a locked-down box, a mounted archive).
fn candidate_paths() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(FILE_NAME));
        }
    }
    candidates.push(std::env::temp_dir().join(FILE_NAME));
    candidates
}

fn open_file() -> Option<(File, PathBuf)> {
    for path in candidate_paths() {
        let oversized = fs::metadata(&path)
            .map(|meta| meta.len() > MAX_BYTES)
            .unwrap_or(false);
        let opened = OpenOptions::new()
            .create(true)
            .write(true)
            .append(!oversized)
            .truncate(oversized)
            .open(&path);
        if let Ok(file) = opened {
            return Some((file, path));
        }
    }
    None
}

/// Open the log (writing a fresh header) and flush anything buffered so far.
/// Idempotent: enabling an already-enabled sink does nothing.
fn enable(reason: &str) {
    {
        let mut guard = lock_sink();
        if guard.is_some() {
            return;
        }
        let Some((file, path)) = open_file() else {
            return;
        };
        let mut sink = Sink { file, path };
        // Written through the guard, not `write_raw`: std mutexes are not
        // re-entrant, and we are already holding this one.
        let block = header(&sink.path, reason);
        let _ = sink.file.write_all(block.as_bytes());
        let _ = sink.file.flush();
        *guard = Some(sink);
        ARMED.store(true, Ordering::Relaxed);
    }
    // Outside the guard: `write_raw` takes it again.
    let buffered = std::mem::take(&mut *lock_pending());
    for line in buffered {
        write_raw(line.as_bytes());
    }
}

/// Close the log. Anything written after this goes nowhere until re-enabled.
fn disable() {
    // Clear the flag first so concurrent `mark`s bail out before the lock.
    ARMED.store(false, Ordering::Relaxed);
    let mut guard = lock_sink();
    if let Some(sink) = guard.as_mut() {
        let _ = sink.file.write_all(b"---- diagnostics switched off ----\n\n");
        let _ = sink.file.flush();
    }
    *guard = None; // drops the File
}

/// Install the panic hook. Call as early as possible in `main`: it costs
/// nothing while logging is off, and it is what turns a silent `abort()` into a
/// named source location once logging is on.
///
/// Also honours `NEWSHELL_DIAG=1` right here, so a crash that happens *before*
/// the config is readable can still be captured.
pub(crate) fn install_panic_hook() {
    let _ = START.get_or_init(Instant::now);
    if env_override() == Some(true) {
        enable("forced on by NEWSHELL_DIAG");
    }
    install_hook();
}

/// Resolve the switch once the config has been loaded, and flush (or drop) the
/// breadcrumbs buffered until now. `NEWSHELL_DIAG` overrides the stored value
/// for this run.
pub(crate) fn configure(enabled_in_config: bool) {
    let on = env_override().unwrap_or(enabled_in_config);
    if on {
        enable("enabled in settings");
    } else {
        disable();
    }
    DECIDED.store(true, Ordering::Relaxed);
    lock_pending().clear();
}

/// The UI switch. Takes effect immediately — no restart needed to start
/// capturing a *runtime* problem (a startup crash still needs the switch left
/// on across a relaunch, which is what the settings page explains).
pub(crate) fn set_enabled(on: bool) {
    if on {
        enable("switched on from settings");
    } else {
        disable();
    }
}

pub(crate) fn is_enabled() -> bool {
    ARMED.load(Ordering::Relaxed)
}

/// The log file's path, for display in the settings page. Reports the file
/// actually open when there is one, otherwise the path that would be used.
pub(crate) fn log_path() -> String {
    let guard = lock_sink();
    if let Some(sink) = guard.as_ref() {
        return sink.path.display().to_string();
    }
    drop(guard);
    candidate_paths()
        .first()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| FILE_NAME.to_owned())
}

/// The directory holding the log, for the settings page's "open folder" button.
pub(crate) fn log_dir() -> PathBuf {
    let path = PathBuf::from(log_path());
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn format_line(message: &str) -> String {
    let mut line = String::with_capacity(message.len() + 32);
    let _ = writeln!(
        line,
        "[{} +{:>6}ms] {}",
        chrono::Local::now().format("%H:%M:%S%.3f"),
        START.get_or_init(Instant::now).elapsed().as_millis(),
        message
    );
    line
}

/// Append one timestamped breadcrumb. `+NNNNms` is measured from process start,
/// which is how you confirm a report like "~5 seconds and it quits".
///
/// Before [`configure`] has run the line is buffered in memory instead, so
/// enabling the switch still yields a log that starts at the very first
/// milestone. After that, a disabled sink drops the line for one atomic load.
pub(crate) fn mark(message: &str) {
    if ARMED.load(Ordering::Relaxed) {
        write_raw(format_line(message).as_bytes());
    } else if !DECIDED.load(Ordering::Relaxed) {
        let mut pending = lock_pending();
        if pending.len() < MAX_PENDING {
            pending.push(format_line(message));
        }
    }
}

fn install_hook() {
    let previous = std::panic::take_hook();
    // No parameter type annotation: this closure has to compile against both
    // `&PanicInfo` (older toolchains) and `&PanicHookInfo` (1.81+).
    std::panic::set_hook(Box::new(move |info| {
        // While logging is off, do nothing at all and let the default hook run:
        // no formatting, no backtrace walk, no file. This is the shipping path.
        if is_enabled() {
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_owned());
            let location = info
                .location()
                .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
                .unwrap_or_else(|| "<unknown location>".to_owned());
            let thread = std::thread::current()
                .name()
                .unwrap_or("<unnamed>")
                .to_owned();

            mark(&format!(
                "!! PANIC on thread '{thread}' at {location} :: {payload}"
            ));
            // Only captured when RUST_BACKTRACE is set. Note that the release
            // profile uses `strip = "symbols"`, so frames are bare addresses
            // unless you also build with `strip = "none"` / `debug = 1`.
            let backtrace = std::backtrace::Backtrace::capture();
            if matches!(
                backtrace.status(),
                std::backtrace::BacktraceStatus::Captured
            ) {
                mark(&format!("!! backtrace:\n{backtrace}"));
            }
            mark("!! aborting now (release profile sets panic = \"abort\")");
        }

        previous(info);
    }));
}

// ── Header ──────────────────────────────────────────────────────────────────

fn header(path: &Path, reason: &str) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "\n═══════════════ NewShell startup diagnostics ═══════════════"
    );
    let _ = writeln!(
        s,
        "when     : {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f %:z")
    );
    let _ = writeln!(s, "version  : {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(s, "log      : {}", path.display());
    let _ = writeln!(
        s,
        "started  : {reason} (+{}ms into the process)",
        START.get_or_init(Instant::now).elapsed().as_millis()
    );
    if let Ok(exe) = std::env::current_exe() {
        let _ = writeln!(s, "exe      : {}", exe.display());
    }
    let _ = writeln!(
        s,
        "os       : {} (kernel {})",
        sysinfo::System::long_os_version().unwrap_or_else(|| "?".to_owned()),
        sysinfo::System::kernel_version().unwrap_or_else(|| "?".to_owned())
    );
    let _ = writeln!(s, "arch     : {}", std::env::consts::ARCH);
    let _ = writeln!(
        s,
        "env      : SLINT_BACKEND={}  RUST_LOG={}",
        std::env::var("SLINT_BACKEND").unwrap_or_else(|_| "<unset>".to_owned()),
        std::env::var("RUST_LOG").unwrap_or_else(|_| "<unset>".to_owned())
    );
    #[cfg(windows)]
    windows_header(&mut s);
    s
}

/// Windows-only facts that separate "works on the server" from "sometimes dies
/// on the laptop": remote-vs-console session, power source (hybrid GPUs behave
/// differently on battery) and the live adapter list.
#[cfg(windows)]
fn windows_header(s: &mut String) {
    let _ = writeln!(
        s,
        "session  : {}",
        if is_remote_session() {
            "REMOTE (RDP / terminal services)"
        } else {
            "local console"
        }
    );
    let _ = writeln!(s, "power    : {}", power_summary());

    let adapters = display_adapters();
    if adapters.is_empty() {
        let _ = writeln!(s, "adapters : <none reported>");
    } else {
        for (i, adapter) in adapters.iter().enumerate() {
            let label = if i == 0 { "adapters :" } else { "          " };
            let _ = writeln!(s, "{label} {adapter}");
        }
    }
}

#[cfg(windows)]
fn is_remote_session() -> bool {
    #[link(name = "user32")]
    extern "system" {
        fn GetSystemMetrics(index: i32) -> i32;
    }
    const SM_REMOTESESSION: i32 = 0x1000;
    unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 }
}

#[cfg(windows)]
fn power_summary() -> String {
    // Layout must match Win32 SYSTEM_POWER_STATUS; the trailing fields are part
    // of the ABI even though we only read the first three.
    #[allow(dead_code)]
    #[repr(C)]
    struct SystemPowerStatus {
        ac_line_status: u8,
        battery_flag: u8,
        battery_life_percent: u8,
        system_status_flag: u8,
        battery_life_time: u32,
        battery_full_life_time: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemPowerStatus(status: *mut SystemPowerStatus) -> i32;
    }

    let mut status = SystemPowerStatus {
        ac_line_status: 255,
        battery_flag: 255,
        battery_life_percent: 255,
        system_status_flag: 0,
        battery_life_time: 0,
        battery_full_life_time: 0,
    };
    if unsafe { GetSystemPowerStatus(&mut status) } == 0 {
        return "<unavailable>".to_owned();
    }

    let source = match status.ac_line_status {
        0 => "on battery",
        1 => "AC",
        _ => "unknown source",
    };
    // 0x80 = "no system battery" (desktop / server). 255 means unknown and has
    // that bit set too, so exclude it explicitly.
    if status.battery_flag != 255 && status.battery_flag & 0x80 != 0 {
        return format!("{source}, no battery");
    }
    if status.battery_life_percent <= 100 {
        return format!("{source}, battery {}%", status.battery_life_percent);
    }
    source.to_owned()
}

/// Enumerate display adapters via user32 — an instant call, unlike the
/// PowerShell/CIM query used for the Settings GPU panel, so it is safe on the
/// startup path. Reports what the OS sees *right now*, which is the point: on a
/// hybrid-GPU laptop this list changes with power state and dGPU parking.
#[cfg(windows)]
fn display_adapters() -> Vec<String> {
    // Layout must match Win32 DISPLAY_DEVICEW; `cb` is validated by the OS, so
    // every field has to be present even though we only read two of them.
    #[allow(dead_code)]
    #[repr(C)]
    struct DisplayDeviceW {
        cb: u32,
        device_name: [u16; 32],
        device_string: [u16; 128],
        state_flags: u32,
        device_id: [u16; 128],
        device_key: [u16; 128],
    }
    #[link(name = "user32")]
    extern "system" {
        fn EnumDisplayDevicesW(
            device: *const u16,
            device_num: u32,
            out: *mut DisplayDeviceW,
            flags: u32,
        ) -> i32;
    }
    const DISPLAY_DEVICE_ATTACHED_TO_DESKTOP: u32 = 0x0000_0001;
    const DISPLAY_DEVICE_PRIMARY_DEVICE: u32 = 0x0000_0004;

    fn wide_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end]).trim().to_owned()
    }

    let mut out = Vec::new();
    for index in 0..16u32 {
        let mut device: DisplayDeviceW = unsafe { std::mem::zeroed() };
        device.cb = std::mem::size_of::<DisplayDeviceW>() as u32;
        // Null device name → enumerate adapters rather than monitors.
        if unsafe { EnumDisplayDevicesW(std::ptr::null(), index, &mut device, 0) } == 0 {
            break;
        }
        let name = wide_to_string(&device.device_string);
        if name.is_empty() {
            continue;
        }
        let mut tags: Vec<&str> = Vec::new();
        if device.state_flags & DISPLAY_DEVICE_PRIMARY_DEVICE != 0 {
            tags.push("primary");
        }
        tags.push(
            if device.state_flags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP != 0 {
                "attached"
            } else {
                "not attached"
            },
        );
        out.push(format!("#{index} {name} [{}]", tags.join(", ")));
    }
    out
}

// ── tracing sink ────────────────────────────────────────────────────────────

/// Buffers one formatted event and commits it to the log in a single write on
/// drop, so concurrent events can never interleave mid-line.
///
/// `armed` is sampled once per event: while logging is off the bytes are dropped
/// as they arrive, so no buffer is ever allocated.
pub(crate) struct TracingWriter {
    buf: Vec<u8>,
    armed: bool,
}

impl io::Write for TracingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.armed {
            self.buf.extend_from_slice(buf);
        }
        // Always report success: a "failed" write would make the fmt layer
        // complain on stderr, which is the opposite of what a disabled log wants.
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TracingWriter {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        write_raw(&self.buf);
    }
}

pub(crate) struct MakeTracingWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeTracingWriter {
    type Writer = TracingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TracingWriter {
            buf: Vec::new(),
            armed: is_enabled(),
        }
    }
}
