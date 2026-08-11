//! Session / application configuration.
//!
//! Persists a simple JSON file in the app's data directory. Resolution is
//! **portable-only**: all user data lives in a single `config/` folder next to
//! the executable and nowhere else. Nothing is ever written to the per-user OS
//! profile (`%APPDATA%`, `~/.config`, …). This keeps the app truly green —
//! delete the exe (and its `config/` folder) and no trace is left behind.
//!
//! The trade-off is deliberate: if the executable sits in a read-only location
//! (e.g. a per-machine install under `Program Files`, a write-protected USB
//! stick), settings cannot be saved. In that case [`ConfigStore::load`] returns
//! an error explaining that the program must be moved to a writable folder,
//! rather than silently scattering config into a hidden per-user directory.
//! See [`data_dir`].
//!
//! ## Password encryption
//!
//! There are **two independent layers**, and which one is active is decided
//! structurally when the file is read — never by a trusted boolean flag:
//!
//! ### 1. Per-field encryption (always on, plaintext track)
//!
//! Passwords are **not** stored in plaintext.  On first launch a random
//! 256-bit key is written to `secret.key` in the same config directory
//! (mode `0600` on Unix).  Every non-empty password is then encrypted with
//! **ChaCha20-Poly1305** (a random 96-bit nonce per value) and stored as
//!
//! ```text
//! enc:v1:<base64url(nonce_12_bytes || ciphertext)>
//! ```
//!
//! Legacy plaintext passwords (from older installs) are left untouched in
//! memory and silently re-encrypted the next time the config is saved.
//!
//! ### 2. Whole-file encryption (optional startup password)
//!
//! When the user sets a startup password, the *entire* `sessions.json` becomes
//! an encrypted envelope (see [`EncryptedEnvelope`]) and the app requires the
//! password at launch. This is envelope encryption: the password is stretched
//! with **argon2id** into a key-encryption-key (KEK) that wraps a random
//! data-encryption-key (DEK); the DEK seals the whole config body. Changing the
//! password only re-wraps the DEK, so no data is ever re-encrypted or lost.
//! [`ConfigStore::load`] returns [`LoadedConfig::Locked`] for such a file; the
//! caller prompts for the password and calls [`LockedStore::unlock`].
//!
//! Users who never set a startup password keep the original plaintext behaviour
//! with zero change (the whole-file layer is simply inactive).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use rand::rngs::OsRng;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

// ── Data directory resolution (portable-only) ─────────────────────────────────
//
// All user data — sessions.json, secret.key, known_hosts — lives in
// ONE directory: a `config/` folder next to the executable. There is no
// per-user (`%APPDATA%`) fallback and no legacy migration: exactly one config
// location ever exists. `known_hosts` routes through here too.

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// The single directory holding all user data (sessions, encryption key,
/// known_hosts): a `config/` folder beside the executable. Resolved
/// once and cached.
///
/// This is the *intended* path even when the exe directory turns out to be
/// read-only — callers ([`ConfigStore::load`]) probe writability separately and
/// surface a clear error rather than redirecting writes elsewhere.
pub fn data_dir() -> PathBuf {
    DATA_DIR.get_or_init(resolve_data_dir).clone()
}

/// The one and only config location: a `config/` folder beside the executable.
/// Falls back to a literal `config` (relative to the current working dir) only
/// if the executable path can't be determined at all — a pathological case.
fn resolve_data_dir() -> PathBuf {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.join("config")))
        .unwrap_or_else(|| PathBuf::from("config"));
    // Best-effort create; writability is validated by the caller.
    let _ = fs::create_dir_all(&dir);
    tracing::info!("using portable config dir {}", dir.display());
    dir
}

/// True only if we can actually create and write a file in `dir` — some
/// locations (Program Files, read-only media) let the directory appear to exist
/// yet reject writes, so a real write probe is the reliable test.
fn dir_is_writable(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".write_probe_{}", std::process::id()));
    match fs::write(&probe, b"") {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// A secret string (e.g. a session password) whose heap buffer is zeroed when
/// it is dropped, so plaintext credentials don't survive in freed memory and
/// turn up in core dumps, a debugger, or `/proc/<pid>/mem`.  `Clone` makes an
/// independent copy that is likewise zeroed on its own drop, and `Debug` is
/// redacted so a password can never be logged by accident.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the contents in logs / debug output.
        f.write_str(if self.0.is_empty() {
            "Secret(\"\")"
        } else {
            "Secret(***)"
        })
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Secret(String::deserialize(d)?))
    }
}

/// Which transport a session uses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    /// SSH shell + SFTP (the original and default behaviour).
    #[default]
    Ssh,
    /// Local serial port (COM3 / /dev/ttyUSB0) for switches, routers, MCUs (#14).
    Serial,
    /// Plain Telnet over TCP, for legacy network gear (#17).
    Telnet,
    /// Local shell process on this machine (PowerShell/CMD/WSL/$SHELL).
    Local,
}

impl SessionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionKind::Ssh => "ssh",
            SessionKind::Serial => "serial",
            SessionKind::Telnet => "telnet",
            SessionKind::Local => "local",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "serial" => SessionKind::Serial,
            "telnet" => SessionKind::Telnet,
            "local" => SessionKind::Local,
            _ => SessionKind::Ssh,
        }
    }
}

fn default_baud() -> u32 {
    115_200
}
fn default_data_bits() -> u8 {
    8
}
fn default_stop_bits() -> u8 {
    1
}
fn default_parity() -> String {
    "none".to_string()
}
/// Ships with the "幻想 3048" sci-fi wallpaper on by default (a dark theme). New
/// installs and users upgrading from before the wallpaper feature get it; once
/// the user picks anything (including "无"/none, stored as ""), their choice is
/// saved and sticks.
fn default_wallpaper() -> String {
    // Serde default for the `wallpaper` field: kept at the old "幻想 3048" so an
    // *existing* config that predates the field stays on tech — `migrate_defaults`
    // then advances default-following users through the migration chain. Brand-new
    // installs get the current default straight from `fresh_config`.
    "builtin:tech".to_string()
}

/// Bump when `migrate_defaults` gains a new one-time default-layout change.
pub const DEFAULTS_REV: u32 = 4;

const PREVIOUS_DEFAULT_WALLPAPER_TRANSPARENCY: f32 = 0.38;
const PREVIOUS_DEFAULT_WALLPAPER_OVERLAY: f32 = 1.0 - PREVIOUS_DEFAULT_WALLPAPER_TRANSPARENCY;
const DEFAULT_WALLPAPER_TRANSPARENCY: f32 = 0.15;
const DEFAULT_WALLPAPER_OVERLAY: f32 = 1.0 - DEFAULT_WALLPAPER_TRANSPARENCY;

fn normalize_hex_color(value: &str) -> Option<String> {
    let digits = value.trim().strip_prefix('#').unwrap_or(value.trim());
    if digits.len() != 6 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("#{}", digits.to_ascii_uppercase()))
}

/// A brand-new config (no file yet, or the old one was corrupt). Seeds the
/// new-user default layout (#new-user-defaults): ms wallpaper, welcome page as
/// a left sidebar, resource panel docked right, 15% wallpaper transparency, and
/// marks the migration done so it isn't re-applied.
fn fresh_config() -> ConfigFile {
    ConfigFile {
        wallpaper: "builtin:dark".to_string(),
        // Quick-connect no longer sits permanently docked — it's reached via
        // the folder button next to "+ New session" in the tab row instead.
        // The resource/status panel takes over the vacated left column.
        welcome_as_sidebar: false,
        sidebar_dock: "left".to_string(),
        wallpaper_overlay: DEFAULT_WALLPAPER_OVERLAY,
        defaults_rev: DEFAULTS_REV,
        ..ConfigFile::default()
    }
}

/// One-time push of the new default layout to *existing* users — but only for
/// each item they're still leaving at the old default, so deliberate choices are
/// never clobbered. Runs once (gated by `defaults_rev`); returns whether anything
/// changed so the caller can persist it. (#new-user-defaults)
fn migrate_defaults(cfg: &mut ConfigFile) -> bool {
    if cfg.defaults_rev >= DEFAULTS_REV {
        return false;
    }
    // rev 1: miku / welcome-as-sidebar / right-docked resources / wallpaper overlay.
    if cfg.defaults_rev < 1 {
        // Old default wallpaper → miku. A custom path, "none" (""), or any other
        // built-in means the user chose it, so leave it.
        if cfg.wallpaper == "builtin:tech" {
            cfg.wallpaper = "builtin:miku".to_string();
        }
        // Overlay still unset -> current default.
        if cfg.wallpaper_overlay <= 0.0 {
            cfg.wallpaper_overlay = DEFAULT_WALLPAPER_OVERLAY;
        }
        // Never enabled the welcome sidebar → enable it.
        if !cfg.welcome_as_sidebar {
            cfg.welcome_as_sidebar = true;
        }
        // Never moved the resource panel (empty = the old left default) → right.
        if cfg.sidebar_dock.trim().is_empty() {
            cfg.sidebar_dock = "right".to_string();
        }
    }
    // rev 2: settings show wallpaper transparency, while rev 1 accidentally
    // stored the default as panel alpha 0.38, so it displayed as ~62%.
    if cfg.defaults_rev < 2
        && (cfg.wallpaper_overlay - PREVIOUS_DEFAULT_WALLPAPER_TRANSPARENCY).abs() < 0.005
    {
        cfg.wallpaper_overlay = DEFAULT_WALLPAPER_OVERLAY;
    }
    // rev 3: reduce the default transparency from 38% to 15%. Only advance
    // users still on the previous default; preserve every custom slider value.
    if cfg.defaults_rev < 3
        && (cfg.wallpaper_overlay - PREVIOUS_DEFAULT_WALLPAPER_OVERLAY).abs() < 0.005
    {
        cfg.wallpaper_overlay = DEFAULT_WALLPAPER_OVERLAY;
    }
    // rev 4: quick-connect moves out of the permanent left column into a
    // folder-popup next to "+ New session"; the resource/status panel takes
    // over that space by default. Only advance users still sitting on the
    // rev-1 defaults (welcome-as-sidebar on, resources docked right) —
    // anyone who has since dragged/toggled either setting keeps their choice.
    if cfg.defaults_rev < 4 && cfg.welcome_as_sidebar && cfg.sidebar_dock.trim() == "right" {
        cfg.welcome_as_sidebar = false;
        cfg.sidebar_dock = "left".to_string();
    }
    cfg.defaults_rev = DEFAULTS_REV;
    true
}
fn default_sidebar_width() -> f32 {
    220.0
}
fn default_sidebar_height() -> f32 {
    240.0
}
fn default_sftp_width() -> f32 {
    380.0
}
fn default_sftp_height() -> f32 {
    220.0
}

fn default_quick_panel_width() -> f32 {
    260.0
}

fn default_quick_panel_height() -> f32 {
    220.0
}
fn default_flow() -> String {
    "none".to_string()
}

/// How a session authenticates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    #[serde(rename = "keyboard-interactive")]
    KeyboardInteractive,
    Key,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Password => "password",
            AuthMethod::KeyboardInteractive => "keyboard-interactive",
            AuthMethod::Key => "key",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "keyboard-interactive" | "keyboard" | "interactive" => AuthMethod::KeyboardInteractive,
            "key" => AuthMethod::Key,
            _ => AuthMethod::Password,
        }
    }
}

/// A single saved SSH target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthMethod,
    #[serde(default)]
    pub password: Secret,
    #[serde(default)]
    pub private_key_path: String,
    #[serde(default)]
    pub private_key_inline: Secret,
    /// Optional outbound proxy, e.g. "socks5://127.0.0.1:1080" or
    /// "http://user:pass@host:8080". Empty = use $ALL_PROXY, else direct.
    #[serde(default)]
    pub proxy: String,
    /// Optional SSH jump host (bastion): the id of another saved SSH session to
    /// tunnel this connection through, like OpenSSH's ProxyJump. Empty = direct.
    /// Single hop only; the jump session supplies its own host/user/auth (#211).
    #[serde(default)]
    pub jump_session_id: String,
    #[serde(default)]
    pub last_used: Option<String>,
    /// Optional folder/group name to organize sessions in the list (#41).
    /// Empty = ungrouped. Sessions are grouped by this in Quick Connect.
    #[serde(default)]
    pub group: String,

    // --- Transport ----------------------------------------------------------
    /// SSH (default), Serial, or Telnet. Absent in old config files → Ssh.
    #[serde(default)]
    pub kind: SessionKind,

    // --- Serial-only fields (ignored unless kind == Serial) -----------------
    /// Serial device path, e.g. "COM3" (Windows) or "/dev/ttyUSB0" (Linux).
    #[serde(default)]
    pub serial_port: String,
    #[serde(default = "default_baud")]
    pub baud_rate: u32,
    #[serde(default = "default_data_bits")]
    pub data_bits: u8,
    #[serde(default = "default_stop_bits")]
    pub stop_bits: u8,
    /// "none" | "odd" | "even".
    #[serde(default = "default_parity")]
    pub parity: String,
    /// "none" | "hardware" | "software".
    #[serde(default = "default_flow")]
    pub flow_control: String,

    /// Skip the shell-integration setup (the cwd-follow PROMPT_COMMAND hook + the
    /// remote resource monitor). Those assume a POSIX shell; on a Windows server
    /// whose shell is pwsh/cmd the injected hook breaks the shell. Turn this on
    /// for such servers (#140).
    #[serde(default)]
    pub disable_shell_integration: bool,
    /// Force the SCP transfer backend even when the remote advertises a working
    /// `sftp` subsystem. Some boxes (notably 黑群晖 / certain BusyBox and
    /// restricted shells) open the sftp subsystem but misbehave on real ops; on
    /// others SFTP is simply flaky. This skips SFTP entirely and always uses the
    /// SCP fallback so file transfer stays reliable (#SCP-force).
    #[serde(default)]
    pub force_scp: bool,
    /// Free-form note for this session — somewhere to stash extra info (jump-host
    /// details, credentials hints, owner, etc.). Shown only in the edit dialog.
    /// (B站 suggestion)
    #[serde(default)]
    pub note: String,
    /// Date this session was added, "YYYY-MM-DD". Defaults to the creation day;
    /// user-editable in the new/edit dialog. Shown as a column in Quick Connect.
    #[serde(default)]
    pub added_date: String,
}

impl Session {
    pub fn new_empty() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: String::new(),
            host: String::new(),
            port: 22,
            user: "root".into(),
            auth: AuthMethod::Password,
            password: Secret::default(),
            private_key_path: String::new(),
            private_key_inline: Secret::default(),
            proxy: String::new(),
            jump_session_id: String::new(),
            last_used: None,
            group: String::new(),
            kind: SessionKind::Ssh,
            serial_port: String::new(),
            baud_rate: default_baud(),
            data_bits: default_data_bits(),
            stop_bits: default_stop_bits(),
            parity: default_parity(),
            flow_control: default_flow(),
            disable_shell_integration: false,
            force_scp: false,
            note: String::new(),
            added_date: String::new(),
        }
    }
}

/// A saved quick command (#55): a named snippet the user clicks to send to the
/// active terminal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QuickCommand {
    pub name: String,
    pub command: String,
    /// Optional group/folder name. Empty = the implicit "default" group (#55).
    #[serde(default)]
    pub group: String,
    /// Whether clicking the chip sends + executes (appends Return). `false` only
    /// drops the command into the input box to tweak first. Defaults to `true` so
    /// existing quick commands keep running on click. (B站 suggestion)
    #[serde(default = "default_true")]
    pub send_enter: bool,
}

/// One user-defined client-side terminal highlighting rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputHighlightRule {
    pub pattern: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub whole_line: bool,
    /// Stable palette id: red | yellow | green | cyan | magenta | gray.
    #[serde(default)]
    pub color: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

fn normalize_highlight_color(color: &str) -> &'static str {
    match color {
        "yellow" => "yellow",
        "green" => "green",
        "cyan" => "cyan",
        "magenta" => "magenta",
        "gray" => "gray",
        _ => "red",
    }
}

/// On-disk layout. Keep additive to ease forward-compat.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub sessions: Vec<Session>,
    /// Preset SFTP download directory. Empty = ask each time.
    #[serde(default)]
    pub download_dir: String,
    /// UI language code: "zh" (default) or "en".
    #[serde(default)]
    pub language: String,
    /// Theme preference: "system" (default) | "dark" | "light".
    #[serde(default)]
    pub theme_pref: String,
    /// Platform renderer preference. Windows uses software/auto/gpu; macOS uses
    /// femtovg/skia. Missing or foreign-platform values use the platform default.
    #[serde(default)]
    pub renderer_mode: String,
    /// Terminal font family. Empty = the built-in default ("NewShell Mono").
    #[serde(default)]
    pub font_family: String,
    /// Terminal font size in px. 0 = the built-in default.
    #[serde(default)]
    pub font_size: u32,
    /// **UI** (interface) font family — buttons, dialogs, menus, sidebar. This
    /// is kept entirely separate from `font_family`, which is the *terminal*
    /// font. Empty = follow the auto-resolved system UI font (on macOS the
    /// crisp CoreText system font; see `resolve_ui_font_family`). A non-empty
    /// value is a user override picked in Settings › Interface › Font.
    #[serde(default)]
    pub ui_font_family: String,
    /// Force regular terminal text to render with a bold face (#262).
    #[serde(default)]
    pub terminal_bold: bool,
    /// Terminal insertion cursor shape: block (default), bar, or underline (#275).
    #[serde(default)]
    pub terminal_cursor_style: String,
    /// Custom terminal cursor colour as #RRGGBB. Empty follows the theme (#275).
    #[serde(default)]
    pub terminal_cursor_color: String,
    /// Stored inverted so missing/legacy config keeps the automatic plain-text
    /// output highlighter enabled by default.
    #[serde(default)]
    pub output_highlight_disabled: bool,
    /// Built-in output highlight preset: "log" (default) or "devops".
    #[serde(default)]
    pub output_highlight_preset: String,
    /// User-defined rules applied before the selected built-in preset.
    #[serde(default)]
    pub output_highlight_rules: Vec<OutputHighlightRule>,
    /// Global UI scale in percent (#100). 0 = default (100%).
    #[serde(default)]
    pub ui_scale: u32,
    /// Immersive wallpaper id: "" = none, "builtin:light" / "builtin:dark" /
    /// "builtin:tech", or a filesystem path to a custom image. Drives the
    /// wallpaper + tinted theme. Defaults to the "幻想 3048" built-in.
    #[serde(default = "default_wallpaper")]
    pub wallpaper: String,
    /// Explicit session groups/folders (#41), including empty ones so a folder
    /// can exist before any session is moved into it. "default" is implicit and
    /// not stored here.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Quick Connect folders that were collapsed when the UI was last used.
    /// `None` is a legacy/new config and starts with every folder collapsed;
    /// `Some([])` means the user explicitly expanded every folder.
    #[serde(default)]
    pub collapsed_session_groups: Option<Vec<String>>,
    /// Stored inverted ("don't follow") so both serde and the Default derive
    /// yield `false` = the feature defaults to ON: the SFTP panel follows the
    /// terminal's cd (OSC 7) unless the user opts out in Interface settings.
    #[serde(default)]
    pub sftp_no_follow_cd: bool,
    /// Always prompt for the save location on each download instead of using the
    /// preset download dir. Defaults to false (#87).
    #[serde(default)]
    pub download_always_ask: bool,
    /// Saved quick commands (#55).
    #[serde(default)]
    pub quick_commands: Vec<QuickCommand>,
    /// Explicit quick-command group names — mirrors `groups` for sessions so that
    /// empty quick-command groups survive and can be renamed/deleted (#55).
    #[serde(default)]
    pub quick_groups: Vec<String>,
    /// Opt-in docked quick-command sidebar (#215). The command-bar popup remains
    /// available until the user actually drags it into the main dock layer.
    #[serde(default)]
    pub quick_commands_as_sidebar: bool,
    #[serde(default)]
    pub quick_panel_open: bool,
    #[serde(default)]
    pub quick_panel_collapsed: bool,
    #[serde(default = "default_quick_panel_width")]
    pub quick_panel_width: f32,
    #[serde(default = "default_quick_panel_height")]
    pub quick_panel_height: f32,
    #[serde(default)]
    pub quick_panel_dock: String,
    /// Recent commands sent from the command box, oldest first, capped (#55).
    #[serde(default)]
    pub command_history: Vec<String>,
    /// Collapse the left resource sidebar on startup (#78).
    #[serde(default)]
    pub collapse_sidebar_default: bool,
    /// Last resource-sidebar collapsed state. None means fall back to
    /// `collapse_sidebar_default` for older configs.
    #[serde(default)]
    pub sidebar_collapsed: Option<bool>,
    /// User-adjustable width of the left resource sidebar, in logical pixels.
    /// Persisted across restarts so the drag-resized width sticks.
    #[serde(default = "default_sidebar_width")]
    pub sidebar_width: f32,
    /// Resource-panel docking: size when docked top/bottom, and which edge it is
    /// docked to (left|right|top|bottom). Persisted so the layout sticks (#dock).
    #[serde(default = "default_sidebar_height")]
    pub sidebar_height: f32,
    #[serde(default)]
    pub sidebar_dock: String,
    /// SFTP-panel docking: extents (px) and docked edge, persisted (#dock).
    #[serde(default = "default_sftp_width")]
    pub sftp_panel_width: f32,
    #[serde(default = "default_sftp_height")]
    pub sftp_panel_height: f32,
    #[serde(default)]
    pub sftp_dock: String,
    /// Last window size in logical px (0 = unset → use the built-in default).
    /// Lets users keep their preferred window size across restarts.
    #[serde(default)]
    pub window_width: f32,
    #[serde(default)]
    pub window_height: f32,
    /// Collapse the bottom SFTP panel on startup (#78).
    #[serde(default)]
    pub collapse_sftp_default: bool,
    /// When session-sync is on, also mirror SFTP uploads to the other online
    /// sessions (same path, falling back to each panel's current dir).
    #[serde(default)]
    pub sync_upload: bool,
    /// Render the welcome page (session list) as a docked left sidebar instead of
    /// a "New tab" tab (v0.5). Persisted so the layout choice sticks.
    #[serde(default)]
    pub welcome_as_sidebar: bool,
    /// Width (logical px) of the welcome/session sidebar when docked (v0.5).
    #[serde(default)]
    pub welcome_sidebar_width: f32,
    /// Welcome/session sidebar dock edge (left|right|top|bottom).
    #[serde(default)]
    pub welcome_sidebar_dock: String,
    /// Welcome sidebar collapsed to the edge icon strip (IDEA-style) (v0.5).
    /// None means the user has not explicitly collapsed/expanded it yet.
    #[serde(default)]
    pub welcome_collapsed: Option<bool>,
    /// Frosted-panel opacity over a wallpaper (0.30–1.00); user-adjustable via the
    /// Interface › Wallpaper opacity slider. 0 = use the current default.
    #[serde(default)]
    pub wallpaper_overlay: f32,
    /// Settings-panel font scale, percent (80–160). 0 = 100% default (v0.5).
    #[serde(default)]
    pub panel_font: u32,
    /// Custom per-zone background colours (#custom-zone-colors). Each is #RRGGBB;
    /// empty follows the theme. The alpha fields are 0.0–1.0 background opacity
    /// (0 = use the theme default). Zones: sidebar (left), right-top (terminal
    /// output + command bar), right-bottom (SFTP directory panel). Only the
    /// background changes; borders and text keep following the global theme.
    #[serde(default)]
    pub zone_sidebar_color: String,
    #[serde(default)]
    pub zone_sidebar_alpha: f32,
    #[serde(default)]
    pub zone_right_top_color: String,
    #[serde(default)]
    pub zone_right_top_alpha: f32,
    #[serde(default)]
    pub zone_right_bottom_color: String,
    #[serde(default)]
    pub zone_right_bottom_alpha: f32,
    /// Custom per-zone *text* colours (#custom-zone-text). Each is #RRGGBB; empty
    /// follows the theme. Only the primary text colour is stored — the secondary
    /// and muted tiers are derived from it by lowering opacity (see theme.slint),
    /// so a single pick keeps the original浓/淡 hierarchy. Applied only while the
    /// zone's `*_enabled` flag is on, sharing the same toggle as the background.
    /// For the terminal zone this recolours only the terminal's own default
    /// input/output text and the command bar; script-driven ANSI colours are
    /// untouched.
    #[serde(default)]
    pub zone_sidebar_text_color: String,
    #[serde(default)]
    pub zone_right_top_text_color: String,
    #[serde(default)]
    pub zone_right_bottom_text_color: String,
    /// Per-zone enable flags (#custom-zone-colors). Kept separate from the colour
    /// so toggling a zone off remembers its last colour instead of clearing it.
    #[serde(default)]
    pub zone_sidebar_enabled: bool,
    #[serde(default)]
    pub zone_right_top_enabled: bool,
    #[serde(default)]
    pub zone_right_bottom_enabled: bool,
    /// Custom accent colour override (#custom-accent). When a wallpaper is active,
    /// the accent (buttons, folder icons, highlights) is normally *derived* from
    /// the wallpaper's average colour, which some photos turn into an ugly or
    /// low-contrast tint the user can't control. Enabling this pins the accent to
    /// a fixed user-chosen `#RRGGBB` instead, so switching wallpapers no longer
    /// changes the accent. Empty colour + disabled = original derive-from-wallpaper
    /// behaviour.
    #[serde(default)]
    pub custom_accent_enabled: bool,
    #[serde(default)]
    pub custom_accent_color: String,
    /// One-time default-layout migration marker (#new-user-defaults). 0 = config
    /// predates the migration. `migrate_defaults` bumps it to `DEFAULTS_REV` after
    /// pushing the new look (default wallpaper / welcome-as-sidebar / right-docked
    /// resource panel / wallpaper overlay) to users still sitting on old defaults.
    #[serde(default)]
    pub defaults_rev: u32,
}

/// Portable export file (issue #46): sessions with everything in plaintext
/// **except** the password, which is encrypted with a fixed key baked into the
/// binary so the file opens on *any* machine running newshell.
///
/// Security note: a built-in key in open-source code is **obfuscation, not real
/// security** — anyone with the source can derive it. It only stops a casual
/// over-the-shoulder read of the file, same level as FinalShell's export.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExportFile {
    /// Format marker / version so the schema can evolve later.
    newshell_export: u32,
    sessions: Vec<Session>,
    /// Quick commands (#55) carried alongside the sessions so a single export
    /// file is a complete backup. `default` on both fields keeps older export
    /// files (which lack these keys) importable — they just carry no snippets.
    #[serde(default)]
    quick_commands: Vec<QuickCommand>,
    #[serde(default)]
    quick_groups: Vec<String>,
}

/// The plaintext payload sealed inside an [`EncryptedExport`]. Older encrypted
/// exports sealed a bare `Vec<Session>`; the import path falls back to that shape
/// so those files keep opening (see `import_encrypted_json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedPayload {
    sessions: Vec<Session>,
    #[serde(default)]
    quick_commands: Vec<QuickCommand>,
    #[serde(default)]
    quick_groups: Vec<String>,
}

/// Password-protected portable export (startup-password track). Same envelope
/// shape as an encrypted `sessions.json`, but the sealed body is just the
/// session list. Sealed under the exporting store's DEK, which is carried
/// wrapped under the startup password — so it opens only with that password.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedExport {
    /// Format marker / version; structural encryption detection keys off this.
    newshell_export_enc: u32,
    kdf: String,
    kdf_params: KdfParams,
    salt: String,
    enc_dek: String,
    ciphertext: String,
}

/// Counts returned by an import so the UI can report both what came in and what
/// was skipped as a duplicate, for sessions *and* quick commands (#55).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub sessions_added: usize,
    pub sessions_skipped: usize,
    pub quick_added: usize,
    pub quick_skipped: usize,
}

// ── Whole-file encryption (optional startup password) ─────────────────────────
//
// When the user sets a startup password, `sessions.json` stops being plaintext
// JSON and becomes an *envelope*: a small plaintext header plus one AEAD-sealed
// blob holding the entire `ConfigFile`. Envelope encryption is used so the
// password can be changed without re-encrypting all the data:
//
//   password ──argon2id(salt)──▶ KEK ──unwraps──▶ DEK ──decrypts──▶ ConfigFile
//
// The DEK is a random 256-bit key generated once when encryption is enabled;
// only its *wrapped* form (sealed under the password-derived KEK) is stored.
// Changing the password re-wraps the same DEK, so the sealed body never has to
// be rewritten and no data is lost.
//
// Detection is **structural**, never a boolean flag: a file is treated as
// encrypted iff it parses as an envelope carrying a `ciphertext` string. This
// defeats a "flip encrypted:false" downgrade — there is no such field, and a
// forged envelope simply fails AEAD authentication on unlock. Either way the
// real data lives only inside the ciphertext, so a tampered header reveals
// nothing.

/// argon2id cost parameters, persisted in the envelope so a file sealed with
/// one set of costs still opens after the in-app defaults are re-tuned.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParams {
    /// Memory cost in KiB.
    m: u32,
    /// Time cost (iterations).
    t: u32,
    /// Parallelism (lanes).
    p: u32,
}

impl KdfParams {
    /// Interactive defaults: ~19 MiB, 2 passes — roughly 100–200 ms on a
    /// typical desktop, enough to make guessing a weak password expensive
    /// without a noticeable pause at every launch.
    fn interactive() -> Self {
        KdfParams {
            m: 19_456,
            t: 2,
            p: 1,
        }
    }
}

/// The on-disk shape of an encrypted `sessions.json`. Everything except
/// `ciphertext` is a plaintext header: `newshell_enc` + `ciphertext` drive
/// structural detection, `renderer_mode` is duplicated here so platform/backend
/// init can run *before* the unlock window is created (the real value inside the
/// ciphertext wins once unlocked), and the KDF fields let the password be turned
/// into the KEK. None of the header is secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedEnvelope {
    /// Format marker / version.
    newshell_enc: u32,
    /// Renderer preference, mirrored in plaintext so the backend can be chosen
    /// before the first (unlock) window. Not sensitive.
    #[serde(default)]
    renderer_mode: String,
    /// Non-secret display preferences, mirrored in plaintext so the unlock
    /// window can follow the user's theme/wallpaper before the config body is
    /// decrypted. None of these reveal session data.
    #[serde(default)]
    theme_pref: String,
    #[serde(default)]
    wallpaper: String,
    #[serde(default)]
    ui_scale: u32,
    #[serde(default)]
    ui_font_family: String,
    /// UI language ("zh"/"en"), mirrored in plaintext so the unlock window shows
    /// the user's chosen language before the body is decrypted. Not sensitive.
    #[serde(default)]
    language: String,
    /// KDF identifier; currently always "argon2id".
    kdf: String,
    kdf_params: KdfParams,
    /// argon2id salt, base64url (no padding).
    salt: String,
    /// The DEK sealed under the password-derived KEK: base64url(nonce_12 ||
    /// wrapped_key).
    enc_dek: String,
    /// The whole `ConfigFile` JSON sealed under the DEK: base64url(nonce_12 ||
    /// ciphertext).
    ciphertext: String,
}

/// In-memory encryption state for an *unlocked* store. Present only when a
/// startup password is set. Holds the DEK (to seal on every save) plus the
/// material needed to re-wrap it on a password change and to re-verify the
/// current password on disable — never the password or KEK themselves.
struct EncState {
    /// Data-encryption key (random, wraps the file body).
    dek: [u8; 32],
    /// Salt the current password was stretched with.
    salt: Vec<u8>,
    /// argon2id costs used for the current wrapping.
    params: KdfParams,
    /// The current wrapped-DEK blob (nonce_12 || wrapped_key), kept so an
    /// entered password can be verified without re-reading the file.
    wrapped_dek: Vec<u8>,
}

impl Drop for EncState {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

/// Result of [`ConfigStore::load`]. A plaintext (or brand-new) config is
/// [`Ready`](LoadedConfig::Ready) to use immediately; an encrypted one is
/// [`Locked`](LoadedConfig::Locked) until a password unlocks it.
pub enum LoadedConfig {
    Ready(ConfigStore),
    Locked(LockedStore),
}

impl LoadedConfig {
    /// Renderer preference, available in both states so platform/backend init
    /// can run before any window (including the unlock window) is built.
    pub fn renderer_mode(&self) -> &str {
        match self {
            LoadedConfig::Ready(store) => store.renderer_mode(),
            LoadedConfig::Locked(locked) => locked.renderer_mode(),
        }
    }
}

/// An encrypted config that has been read from disk but not yet decrypted.
/// Holds only the plaintext envelope; call [`unlock`](LockedStore::unlock) with
/// the startup password to obtain a usable [`ConfigStore`].
pub struct LockedStore {
    path: PathBuf,
    /// `secret.key` bytes, carried through so the unlocked store keeps the same
    /// plaintext-track field key it had before (harmless when encryption is on).
    key: [u8; 32],
    envelope: EncryptedEnvelope,
}

pub struct ConfigStore {
    path: PathBuf,
    cache: ConfigFile,
    /// ChaCha20-Poly1305 key loaded from (or freshly generated into)
    /// `secret.key` in the same directory as `sessions.json`. Used for the
    /// plaintext track's per-field password encryption (`enc:v1:`). Irrelevant
    /// while whole-file encryption is active — the sealed body is self-contained
    /// and never depends on `secret.key`.
    key: [u8; 32],
    /// `Some` when a startup password is set (whole-file encryption active);
    /// `None` for the original plaintext behaviour.
    enc: Option<EncState>,
}

/// Remove duplicate entries in place, keeping the *last* (most recent)
/// occurrence of each and preserving relative order (#113). The list is capped
/// at 200, so the quadratic scan is trivial.
fn dedup_keep_last(items: &mut Vec<String>) {
    let mut i = 0;
    while i < items.len() {
        if items[i + 1..].contains(&items[i]) {
            items.remove(i);
        } else {
            i += 1;
        }
    }
}

impl ConfigStore {
    /// The prefix that marks an encrypted password blob in sessions.json.
    const ENC_PREFIX: &'static str = "enc:v1:";

    /// Marks a password encrypted with the **portable export key** (issue #46).
    const EXPORT_PREFIX: &'static str = "enc:exp:v1:";

    /// Fixed 32-byte key for portable exports. Baked into the binary so an
    /// exported file decrypts on any machine. Obfuscation only — see `ExportFile`.
    const EXPORT_KEY: [u8; 32] = *b"newshell.export.portable.key.001";

    // ── Encryption helpers ────────────────────────────────────────────────

    /// Encrypt `plaintext` with ChaCha20-Poly1305 and return
    /// `"enc:v1:<base64url(nonce_12_bytes || ciphertext)>"`.
    fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<String> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 12 random bytes
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("password encrypt error: {e}"))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        Ok(format!(
            "{}{}",
            Self::ENC_PREFIX,
            URL_SAFE_NO_PAD.encode(&blob)
        ))
    }

    /// Try to decrypt a value produced by [`Self::encrypt`].
    /// Returns `None` if the string is not an encrypted blob (e.g. a legacy
    /// plaintext value, an empty string, or a tampered/corrupt blob).
    fn try_decrypt(key: &[u8; 32], s: &str) -> Option<String> {
        let b64 = s.strip_prefix(Self::ENC_PREFIX)?;
        let blob = URL_SAFE_NO_PAD.decode(b64).ok()?;
        if blob.len() < 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plain).ok()
    }

    // ── Whole-file envelope crypto (startup password) ─────────────────────

    /// Stretch `password` into a 256-bit key-encryption-key with argon2id.
    fn derive_kek(password: &str, salt: &[u8], params: &KdfParams) -> Result<[u8; 32]> {
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(params.m, params.t, params.p, Some(32))
                .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?,
        );
        let mut kek = [0u8; 32];
        argon
            .hash_password_into(password.as_bytes(), salt, &mut kek)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        Ok(kek)
    }

    /// AEAD-seal `plaintext` under `key`, returning `nonce_12 || ciphertext`.
    fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("seal error: {e}"))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// Reverse [`seal`]: authenticate and decrypt `nonce_12 || ciphertext`.
    /// `None` on any failure (wrong key, truncation, tampering).
    fn open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() < 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        cipher.decrypt(nonce, ciphertext).ok()
    }

    /// Build an [`EncryptedEnvelope`] from an [`EncState`] and the current
    /// plaintext `ConfigFile` — used by [`save`] whenever encryption is active.
    fn build_envelope(cfg: &ConfigFile, enc: &EncState) -> Result<EncryptedEnvelope> {
        let plain = serde_json::to_vec(cfg)?;
        let body = Self::seal(&enc.dek, &plain)?;
        Ok(EncryptedEnvelope {
            newshell_enc: 1,
            renderer_mode: cfg.renderer_mode.clone(),
            theme_pref: cfg.theme_pref.clone(),
            wallpaper: cfg.wallpaper.clone(),
            ui_scale: cfg.ui_scale,
            ui_font_family: cfg.ui_font_family.clone(),
            language: cfg.language.clone(),
            kdf: "argon2id".into(),
            kdf_params: enc.params.clone(),
            salt: URL_SAFE_NO_PAD.encode(&enc.salt),
            enc_dek: URL_SAFE_NO_PAD.encode(&enc.wrapped_dek),
            ciphertext: URL_SAFE_NO_PAD.encode(&body),
        })
    }

    // ── Key file management ───────────────────────────────────────────────

    /// Load the 32-byte key from `<config_dir>/secret.key`, or generate and
    /// persist a fresh one.  On Unix the key file is created with mode `0600`
    /// so other local accounts cannot read it.  On Windows files in `%APPDATA%`
    /// are already restricted to the owning user by default ACLs.
    fn load_or_create_key(config_dir: &Path) -> Result<[u8; 32]> {
        let key_path = config_dir.join("secret.key");

        if key_path.exists() {
            let bytes = fs::read(&key_path)
                .with_context(|| format!("failed to read {}", key_path.display()))?;
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                return Ok(key);
            }
            tracing::warn!("secret.key has wrong length — regenerating");
        }

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        fs::write(&key_path, &key)
            .with_context(|| format!("failed to write {}", key_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", key_path.display()))?;
        }
        tracing::info!("generated new encryption key at {}", key_path.display());
        Ok(key)
    }

    // ── Public API ────────────────────────────────────────────────────────

    /// Decrypt per-field passwords, clean duplicate history, and run the
    /// one-time default-layout migration. Shared by the plaintext load path and
    /// the post-unlock path so both behave identically. Returns whether the
    /// migration changed anything (so the caller can persist it once).
    fn post_process(cfg: &mut ConfigFile, key: &[u8; 32]) -> bool {
        // Decrypt any per-field encrypted passwords; leave legacy plaintext
        // values untouched (they will be encrypted on next save). In whole-file
        // encryption mode the body is sealed and fields are already plaintext,
        // so these calls simply no-op — kept for defensive uniformity.
        for session in &mut cfg.sessions {
            if let Some(plain) = Self::try_decrypt(key, session.password.as_str()) {
                session.password = Secret::new(plain);
            }
            if let Some(plain) = Self::try_decrypt(key, session.private_key_inline.as_str()) {
                session.private_key_inline = Secret::new(plain);
            }
        }
        // Clean up any duplicate history accumulated before #113, keeping the
        // last (most recent) occurrence of each command.
        dedup_keep_last(&mut cfg.command_history);
        // One-time push of the new default layout to existing users (only for
        // items they never changed). (#new-user-defaults)
        migrate_defaults(cfg)
    }

    /// Load (or initialise) the config file.
    ///
    /// Returns [`LoadedConfig::Locked`] when `sessions.json` is an encrypted
    /// envelope (a startup password is set) — the caller must prompt for the
    /// password and call [`LockedStore::unlock`]. Otherwise returns
    /// [`LoadedConfig::Ready`] with a usable store. On any parse error we back
    /// up the broken file and start fresh — losing saved sessions is better than
    /// crashing at launch.
    pub fn load() -> Result<LoadedConfig> {
        let path = Self::config_path()?;
        let config_dir = path
            .parent()
            .context("config path has no parent directory")?
            .to_path_buf();

        fs::create_dir_all(&config_dir)
            .with_context(|| format!("failed to create config dir {}", config_dir.display()))?;

        // Portable-only: the config folder lives beside the executable and is
        // the single source of truth. If that folder can't be written (e.g. the
        // program was installed under Program Files, or is running from
        // read-only media), fail loudly with actionable guidance instead of
        // silently redirecting data into a hidden per-user directory.
        if !dir_is_writable(&config_dir) {
            anyhow::bail!(
                "config directory {} is not writable — move the program to a \
                 folder you can write to (e.g. a subfolder of your Documents or \
                 a dedicated tools folder) and run it again",
                config_dir.display()
            );
        }

        let key = Self::load_or_create_key(&config_dir)?;

        // No file yet → brand-new plaintext config.
        if !path.exists() {
            return Ok(LoadedConfig::Ready(Self {
                path,
                cache: fresh_config(),
                key,
                enc: None,
            }));
        }

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        // Structural detection: a file is encrypted iff it parses as an envelope
        // carrying a `ciphertext`. We never trust a boolean flag, so flipping one
        // can't downgrade an encrypted file to plaintext.
        if let Some(envelope) = Self::detect_envelope(&raw) {
            return Ok(LoadedConfig::Locked(LockedStore {
                path,
                key,
                envelope,
            }));
        }

        // Plaintext track (original behaviour).
        let store = match serde_json::from_str::<ConfigFile>(&raw) {
            Ok(mut cfg) => {
                let migrated = Self::post_process(&mut cfg, &key);
                let store = Self {
                    path,
                    cache: cfg,
                    key,
                    enc: None,
                };
                // Persist the migration so it runs exactly once (and so a later
                // opt-out isn't reverted next launch).
                if migrated {
                    if let Err(e) = store.save() {
                        tracing::warn!("failed to persist default-layout migration: {e:#}");
                    }
                }
                store
            }
            Err(err) => {
                let backup = path.with_extension("json.broken");
                let _ = fs::rename(&path, &backup);
                tracing::warn!(
                    "config file was corrupt ({err}); backed up to {}",
                    backup.display()
                );
                Self {
                    path,
                    cache: fresh_config(),
                    key,
                    enc: None,
                }
            }
        };
        Ok(LoadedConfig::Ready(store))
    }

    /// Minimum decoded length of a `base64url(nonce_12 || ciphertext_with_tag)`
    /// AEAD blob: a 12-byte nonce plus the 16-byte Poly1305 tag. Anything shorter
    /// cannot possibly be a valid sealed value, so it fails detection outright.
    const MIN_SEALED_LEN: usize = 12 + 16;
    /// A wrapped DEK is `seal(kek, dek_32)` → nonce_12 + 32-byte key + 16-byte tag.
    const WRAPPED_DEK_LEN: usize = 12 + 32 + 16;
    /// Accepted salt lengths (bytes). We only ever emit 16, but keep a small
    /// window so a file written by a future/other build still opens.
    const MIN_SALT_LEN: usize = 8;
    const MAX_SALT_LEN: usize = 64;

    /// True iff `s` base64url-decodes to a byte slice whose length is in
    /// `[min, max]`. The workhorse of content-based detection: a copied file
    /// whose header was hand-edited (garbage in a field, truncated blob, a
    /// plaintext value pasted where a sealed one belongs) fails here instead of
    /// being mistaken for a real encrypted file.
    fn b64_len_in_range(s: &str, min: usize, max: usize) -> bool {
        match URL_SAFE_NO_PAD.decode(s.as_bytes()) {
            Ok(bytes) => bytes.len() >= min && bytes.len() <= max,
            Err(_) => false,
        }
    }

    /// Validate the sealed/KDF fields shared by both on-disk envelope shapes
    /// (`sessions.json` and the encrypted export). Detection is **content-based**,
    /// not header-trusting: every field that claims to hold cryptographic
    /// material is base64url-decoded and length-checked, and the KDF cost
    /// parameters must be sane. This is the second-pass check the user asked for —
    /// a marker byte alone is never enough to treat a file as encrypted.
    fn envelope_fields_valid(kdf: &str, params: &KdfParams, salt: &str, enc_dek: &str, ciphertext: &str) -> bool {
        // Only argon2id is understood; an unknown KDF is not our envelope.
        if kdf != "argon2id" {
            return false;
        }
        // Cost parameters must be within argon2's own accepted ranges, so a
        // tampered header can't drive the KDF into an error or a trivial cost.
        if params.m < Params::MIN_M_COST
            || params.m > Params::MAX_M_COST
            || params.t < Params::MIN_T_COST
            || params.t > Params::MAX_T_COST
            || params.p < Params::MIN_P_COST
            || params.p > Params::MAX_P_COST
        {
            return false;
        }
        Self::b64_len_in_range(salt, Self::MIN_SALT_LEN, Self::MAX_SALT_LEN)
            && Self::b64_len_in_range(enc_dek, Self::WRAPPED_DEK_LEN, Self::WRAPPED_DEK_LEN)
            && Self::b64_len_in_range(ciphertext, Self::MIN_SEALED_LEN, usize::MAX)
    }

    /// Parse `raw` as an encrypted envelope, returning it only if it is
    /// structurally *and* cryptographically well-formed: the marker is set and
    /// every sealed field decodes to a plausible byte length (see
    /// [`Self::envelope_fields_valid`]). A plaintext `ConfigFile` never carries a
    /// `ciphertext` field, and a hand-edited copy that merely bolts on the marker
    /// cannot forge valid sealed blobs — so this cleanly separates the two on-disk
    /// formats without ever trusting a boolean flag.
    fn detect_envelope(raw: &str) -> Option<EncryptedEnvelope> {
        let env: EncryptedEnvelope = serde_json::from_str(raw).ok()?;
        if env.newshell_enc == 0 {
            return None;
        }
        if !Self::envelope_fields_valid(
            &env.kdf,
            &env.kdf_params,
            &env.salt,
            &env.enc_dek,
            &env.ciphertext,
        ) {
            return None;
        }
        Some(env)
    }

    fn config_path() -> Result<PathBuf> {
        Ok(data_dir().join("sessions.json"))
    }

    pub fn sessions(&self) -> &[Session] {
        &self.cache.sessions
    }

    #[allow(dead_code)] // reserved for an upcoming reorder/drag-drop feature
    pub fn sessions_mut(&mut self) -> &mut Vec<Session> {
        &mut self.cache.sessions
    }

    pub fn upsert(&mut self, session: Session) {
        if let Some(existing) = self.cache.sessions.iter_mut().find(|s| s.id == session.id) {
            *existing = session;
        } else {
            self.cache.sessions.push(session);
        }
    }

    pub fn remove(&mut self, id: &str) {
        self.cache.sessions.retain(|s| s.id != id);
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.cache.sessions.iter().find(|s| s.id == id)
    }

    pub fn download_dir(&self) -> &str {
        &self.cache.download_dir
    }

    pub fn set_download_dir(&mut self, dir: String) {
        self.cache.download_dir = dir;
    }

    /// UI language code ("zh" default / "en").
    pub fn language(&self) -> &str {
        if self.cache.language.is_empty() {
            "zh"
        } else {
            &self.cache.language
        }
    }

    pub fn set_language(&mut self, lang: String) {
        self.cache.language = lang;
    }

    /// Theme preference: "system" (default) | "dark" | "light".
    pub fn theme_pref(&self) -> &str {
        if self.cache.theme_pref.is_empty() {
            "system"
        } else {
            &self.cache.theme_pref
        }
    }

    pub fn set_theme_pref(&mut self, pref: String) {
        self.cache.theme_pref = pref;
    }

    /// Renderer preference for the current platform.
    ///
    /// macOS default is **Skia** (#font-blur): Skia delegates glyph rasterization
    /// to CoreText, so UI text — buttons, dialogs, menus at small point sizes —
    /// is sharp and matches native apps. FemtoVG (the old default) uses its own
    /// un-hinted, non-pixel-grid-aligned path renderer and made everything except
    /// the large monospace terminal look blurry. An empty/unknown value (fresh
    /// install, or upgrading users who never picked a renderer) therefore now
    /// resolves to Skia; only an explicit "femtovg" opt-out stays on FemtoVG.
    #[cfg(target_os = "macos")]
    pub fn renderer_mode(&self) -> &str {
        match self.cache.renderer_mode.as_str() {
            "femtovg" => "femtovg", // explicit opt-out (Settings -> Rendering)
            _ => "skia",            // default: "", "skia", or any unknown value
        }
    }

    /// Missing and invalid Windows values deliberately use software so upgrades
    /// preserve the high-DPI/VM compatibility from #224.
    #[cfg(not(target_os = "macos"))]
    pub fn renderer_mode(&self) -> &str {
        match self.cache.renderer_mode.as_str() {
            "auto" => "auto",
            "gpu" => "gpu",
            _ => "software",
        }
    }

    #[cfg(target_os = "macos")]
    pub fn set_renderer_mode(&mut self, mode: String) {
        // Store the exact chosen token. "femtovg" is the deliberate opt-out;
        // everything else (incl. the default "skia") normalizes to "skia".
        self.cache.renderer_mode = match mode.as_str() {
            "femtovg" => "femtovg".into(),
            _ => "skia".into(),
        };
    }

    #[cfg(not(target_os = "macos"))]
    pub fn set_renderer_mode(&mut self, mode: String) {
        self.cache.renderer_mode = match mode.as_str() {
            "auto" => "auto".into(),
            "gpu" => "gpu".into(),
            _ => "software".into(),
        };
    }

    /// Terminal font family ("" = built-in default).
    pub fn font_family(&self) -> &str {
        &self.cache.font_family
    }

    pub fn set_font_family(&mut self, family: String) {
        self.cache.font_family = family;
    }

    /// UI (interface) font family. Empty = follow the auto-resolved system font.
    /// Distinct from `font_family` (terminal).
    pub fn ui_font_family(&self) -> &str {
        &self.cache.ui_font_family
    }

    /// Set the UI font family override. Empty string clears the override and
    /// returns the interface to the auto-resolved system font.
    pub fn set_ui_font_family(&mut self, family: String) {
        self.cache.ui_font_family = family;
    }

    /// Terminal font size in px (falls back to 13 when unset).
    pub fn font_size(&self) -> u32 {
        if self.cache.font_size == 0 {
            13
        } else {
            self.cache.font_size
        }
    }

    pub fn set_font_size(&mut self, size: u32) {
        self.cache.font_size = size.clamp(8, 32);
    }

    /// Force regular terminal text to render with a bold face (#262).
    pub fn terminal_bold(&self) -> bool {
        self.cache.terminal_bold
    }

    pub fn set_terminal_bold(&mut self, bold: bool) {
        self.cache.terminal_bold = bold;
    }

    /// Selected terminal insertion cursor shape. Legacy and invalid values use
    /// the existing block cursor so upgrades preserve the current appearance.
    pub fn terminal_cursor_style(&self) -> &str {
        match self.cache.terminal_cursor_style.as_str() {
            "bar" => "bar",
            "underline" => "underline",
            _ => "block",
        }
    }

    pub fn set_terminal_cursor_style(&mut self, style: String) {
        self.cache.terminal_cursor_style = match style.as_str() {
            "bar" => "bar".into(),
            "underline" => "underline".into(),
            _ => "block".into(),
        };
    }

    pub fn terminal_cursor_color(&self) -> &str {
        if normalize_hex_color(&self.cache.terminal_cursor_color).is_some() {
            &self.cache.terminal_cursor_color
        } else {
            ""
        }
    }

    pub fn set_terminal_cursor_color(&mut self, color: &str) -> bool {
        let Some(normalized) = normalize_hex_color(color) else {
            return false;
        };
        self.cache.terminal_cursor_color = normalized;
        true
    }

    /// Whether client-side highlighting of otherwise unstyled output is active.
    pub fn output_highlight_enabled(&self) -> bool {
        !self.cache.output_highlight_disabled
    }

    pub fn set_output_highlight_enabled(&mut self, enabled: bool) {
        self.cache.output_highlight_disabled = !enabled;
    }

    /// Selected built-in rule set. Unknown values safely fall back to the
    /// conservative log-level preset for forward/backward compatibility.
    pub fn output_highlight_preset(&self) -> &str {
        match self.cache.output_highlight_preset.as_str() {
            "devops" => "devops",
            _ => "log",
        }
    }

    pub fn set_output_highlight_preset(&mut self, preset: String) {
        self.cache.output_highlight_preset = match preset.as_str() {
            "devops" => "devops".to_string(),
            _ => "log".to_string(),
        };
    }

    pub fn output_highlight_rules(&self) -> &[OutputHighlightRule] {
        &self.cache.output_highlight_rules
    }

    pub fn add_output_highlight_rule(&mut self, mut rule: OutputHighlightRule) {
        rule.pattern = rule.pattern.trim().to_string();
        rule.color = normalize_highlight_color(&rule.color).to_string();
        self.cache.output_highlight_rules.push(rule);
    }

    pub fn remove_output_highlight_rule(&mut self, index: usize) {
        if index < self.cache.output_highlight_rules.len() {
            self.cache.output_highlight_rules.remove(index);
        }
    }

    pub fn set_output_highlight_rule_enabled(&mut self, index: usize, enabled: bool) {
        if let Some(rule) = self.cache.output_highlight_rules.get_mut(index) {
            rule.enabled = enabled;
        }
    }

    /// Global UI scale in percent (#100). Defaults to 100.
    pub fn ui_scale(&self) -> u32 {
        if self.cache.ui_scale == 0 {
            100
        } else {
            self.cache.ui_scale
        }
    }

    pub fn set_ui_scale(&mut self, percent: u32) {
        self.cache.ui_scale = percent.clamp(80, 200);
    }

    /// Immersive wallpaper id ("" = none).
    pub fn wallpaper(&self) -> &str {
        &self.cache.wallpaper
    }

    pub fn set_wallpaper(&mut self, id: impl Into<String>) {
        self.cache.wallpaper = id.into();
    }

    /// Whether the SFTP panel follows the terminal's cd (default true).
    pub fn sftp_follow_cd(&self) -> bool {
        !self.cache.sftp_no_follow_cd
    }

    pub fn set_sftp_follow_cd(&mut self, follow: bool) {
        self.cache.sftp_no_follow_cd = !follow;
    }

    /// Saved quick commands (#55).
    pub fn quick_commands(&self) -> &[QuickCommand] {
        &self.cache.quick_commands
    }

    pub fn set_quick_commands(&mut self, cmds: Vec<QuickCommand>) {
        self.cache.quick_commands = cmds;
    }

    pub fn quick_panel_open(&self) -> bool {
        self.cache.quick_panel_open
    }

    pub fn quick_commands_as_sidebar(&self) -> bool {
        self.cache.quick_commands_as_sidebar
    }

    pub fn set_quick_commands_as_sidebar(&mut self, enabled: bool) {
        self.cache.quick_commands_as_sidebar = enabled;
        if !enabled {
            self.cache.quick_panel_open = false;
        }
    }

    pub fn set_quick_panel_open(&mut self, open: bool) {
        self.cache.quick_panel_open = open;
    }

    pub fn quick_panel_collapsed(&self) -> bool {
        self.cache.quick_panel_collapsed
    }

    pub fn set_quick_panel_collapsed(&mut self, collapsed: bool) {
        self.cache.quick_panel_collapsed = collapsed;
    }

    pub fn quick_panel_width(&self) -> f32 {
        let width = self.cache.quick_panel_width;
        if width <= 0.0 {
            default_quick_panel_width()
        } else {
            width
        }
    }

    pub fn set_quick_panel_width(&mut self, width: f32) {
        self.cache.quick_panel_width = width;
    }

    pub fn quick_panel_height(&self) -> f32 {
        let height = self.cache.quick_panel_height;
        if height <= 0.0 {
            default_quick_panel_height()
        } else {
            height
        }
    }

    pub fn set_quick_panel_height(&mut self, height: f32) {
        self.cache.quick_panel_height = height;
    }

    pub fn quick_panel_dock(&self) -> String {
        match self.cache.quick_panel_dock.trim() {
            "left" | "right" | "top" | "bottom" => self.cache.quick_panel_dock.clone(),
            _ => "right".into(),
        }
    }

    pub fn set_quick_panel_dock(&mut self, dock: String) {
        self.cache.quick_panel_dock = dock;
    }

    /// Explicit quick-command groups (#55) — parallels [`groups`](Self::groups).
    pub fn quick_groups(&self) -> &[String] {
        &self.cache.quick_groups
    }

    /// Create an empty quick-command group. Ignores blank, "default", duplicates.
    pub fn add_quick_group(&mut self, name: String) {
        let n = name.trim().to_string();
        if n.is_empty() || n.eq_ignore_ascii_case("default") {
            return;
        }
        if !self.cache.quick_groups.iter().any(|g| g == &n) {
            self.cache.quick_groups.push(n);
        }
    }

    /// Delete a quick-command group; any command still in it falls back to
    /// ungrouped (the UI only offers delete on empty groups, but clear defensively).
    pub fn remove_quick_group(&mut self, name: &str) {
        self.cache.quick_groups.retain(|g| g != name);
        for c in &mut self.cache.quick_commands {
            if c.group == name {
                c.group.clear();
            }
        }
    }

    /// Rename a quick-command group, moving its commands along. No-op for
    /// blank / "default".
    pub fn rename_quick_group(&mut self, old: &str, new: String) {
        let n = new.trim().to_string();
        if n.is_empty() || n.eq_ignore_ascii_case("default") || n == old {
            return;
        }
        for g in &mut self.cache.quick_groups {
            if g == old {
                *g = n.clone();
            }
        }
        for c in &mut self.cache.quick_commands {
            if c.group == old {
                c.group = n.clone();
            }
        }
        self.cache.quick_groups.sort();
        self.cache.quick_groups.dedup();
    }

    /// Update one quick command in place by index (#55).
    pub fn update_quick_command(&mut self, index: usize, cmd: QuickCommand) {
        if let Some(slot) = self.cache.quick_commands.get_mut(index) {
            *slot = cmd;
        }
    }

    /// Recent command-box history, oldest first (#55).
    pub fn command_history(&self) -> &[String] {
        &self.cache.command_history
    }

    /// Append a command to the history: skips blanks, de-duplicates globally so
    /// each command appears once, and re-appends at the end so the most-recently
    /// used command is always last. Capped so it can't grow without bound (#113).
    pub fn push_command_history(&mut self, cmd: String) {
        if cmd.trim().is_empty() {
            return;
        }
        // Drop any earlier occurrence, then push → no duplicates and "last used"
        // moves to the end (bash `HISTCONTROL=erasedups` semantics).
        self.cache.command_history.retain(|c| c != &cmd);
        const CAP: usize = 200;
        self.cache.command_history.push(cmd);
        let len = self.cache.command_history.len();
        if len > CAP {
            self.cache.command_history.drain(0..len - CAP);
        }
    }

    /// Collapse the resource sidebar on startup (default false) (#78).
    pub fn collapse_sidebar_default(&self) -> bool {
        self.cache.collapse_sidebar_default
    }

    pub fn set_collapse_sidebar_default(&mut self, v: bool) {
        self.cache.collapse_sidebar_default = v;
    }

    /// Persisted sidebar width in logical px. Falls back to the default when the
    /// stored value is unset/zero (e.g. a config created via `Default`).
    pub fn sidebar_width(&self) -> f32 {
        let w = self.cache.sidebar_width;
        if w <= 0.0 {
            default_sidebar_width()
        } else {
            w
        }
    }

    pub fn set_sidebar_width(&mut self, v: f32) {
        self.cache.sidebar_width = v;
    }

    /// Resource / SFTP panel docking geometry, persisted across restarts (#dock).
    /// Sizes fall back to their defaults when unset/zero; docks fall back to a
    /// sensible edge when the stored string is empty.
    pub fn sidebar_height(&self) -> f32 {
        let h = self.cache.sidebar_height;
        if h <= 0.0 {
            default_sidebar_height()
        } else {
            h
        }
    }
    pub fn set_sidebar_height(&mut self, v: f32) {
        self.cache.sidebar_height = v;
    }
    pub fn sidebar_dock(&self) -> String {
        let d = self.cache.sidebar_dock.trim();
        if d.is_empty() {
            "left".into()
        } else {
            d.to_string()
        }
    }
    pub fn set_sidebar_dock(&mut self, v: String) {
        self.cache.sidebar_dock = v;
    }
    pub fn sidebar_collapsed(&self) -> Option<bool> {
        self.cache.sidebar_collapsed
    }
    pub fn set_sidebar_collapsed(&mut self, v: bool) {
        self.cache.sidebar_collapsed = Some(v);
    }
    pub fn welcome_as_sidebar(&self) -> bool {
        self.cache.welcome_as_sidebar
    }
    pub fn set_welcome_as_sidebar(&mut self, v: bool) {
        self.cache.welcome_as_sidebar = v;
    }
    pub fn welcome_sidebar_width(&self) -> f32 {
        let w = self.cache.welcome_sidebar_width;
        if w <= 0.0 {
            240.0
        } else {
            w
        }
    }
    pub fn set_welcome_sidebar_width(&mut self, v: f32) {
        self.cache.welcome_sidebar_width = v;
    }
    pub fn welcome_sidebar_dock(&self) -> String {
        let d = self.cache.welcome_sidebar_dock.trim();
        if d.is_empty() {
            "left".into()
        } else {
            d.to_string()
        }
    }
    pub fn set_welcome_sidebar_dock(&mut self, v: String) {
        self.cache.welcome_sidebar_dock = v;
    }
    pub fn welcome_collapsed(&self) -> Option<bool> {
        self.cache.welcome_collapsed
    }
    pub fn set_welcome_collapsed(&mut self, v: bool) {
        self.cache.welcome_collapsed = Some(v);
    }
    pub fn wallpaper_overlay(&self) -> f32 {
        let a = self.cache.wallpaper_overlay;
        // Floor lowered 0.40 -> 0.30 so more see-through panels are reachable.
        if a <= 0.0 {
            DEFAULT_WALLPAPER_OVERLAY
        } else {
            a.clamp(0.30, 1.0)
        }
    }
    pub fn set_wallpaper_overlay(&mut self, v: f32) {
        self.cache.wallpaper_overlay = v.clamp(0.30, 1.0);
    }
    pub fn panel_font(&self) -> u32 {
        if self.cache.panel_font == 0 {
            100
        } else {
            self.cache.panel_font
        }
    }
    pub fn set_panel_font(&mut self, percent: u32) {
        self.cache.panel_font = percent.clamp(80, 160);
    }

    // --- Custom per-zone background colours (#custom-zone-colors) -----------
    // A zone is "enabled" when it has a valid #RRGGBB colour; empty follows the
    // theme. Setters accept an empty string (to clear) or a hex colour; they
    // return false only for a malformed non-empty colour. Alpha is 0.0–1.0
    // (0 = default / fully opaque via the theme's own logic).
    pub fn zone_sidebar_color(&self) -> &str {
        if normalize_hex_color(&self.cache.zone_sidebar_color).is_some() {
            &self.cache.zone_sidebar_color
        } else {
            ""
        }
    }
    pub fn set_zone_sidebar_color(&mut self, color: &str) -> bool {
        if color.trim().is_empty() {
            self.cache.zone_sidebar_color.clear();
            return true;
        }
        let Some(normalized) = normalize_hex_color(color) else {
            return false;
        };
        self.cache.zone_sidebar_color = normalized;
        true
    }
    pub fn zone_sidebar_alpha(&self) -> f32 {
        let a = self.cache.zone_sidebar_alpha;
        if a <= 0.0 { 1.0 } else { a.clamp(0.10, 1.0) }
    }
    pub fn set_zone_sidebar_alpha(&mut self, v: f32) {
        self.cache.zone_sidebar_alpha = v.clamp(0.10, 1.0);
    }

    pub fn zone_right_top_color(&self) -> &str {
        if normalize_hex_color(&self.cache.zone_right_top_color).is_some() {
            &self.cache.zone_right_top_color
        } else {
            ""
        }
    }
    pub fn set_zone_right_top_color(&mut self, color: &str) -> bool {
        if color.trim().is_empty() {
            self.cache.zone_right_top_color.clear();
            return true;
        }
        let Some(normalized) = normalize_hex_color(color) else {
            return false;
        };
        self.cache.zone_right_top_color = normalized;
        true
    }
    pub fn zone_right_top_alpha(&self) -> f32 {
        let a = self.cache.zone_right_top_alpha;
        if a <= 0.0 { 1.0 } else { a.clamp(0.10, 1.0) }
    }
    pub fn set_zone_right_top_alpha(&mut self, v: f32) {
        self.cache.zone_right_top_alpha = v.clamp(0.10, 1.0);
    }

    pub fn zone_right_bottom_color(&self) -> &str {
        if normalize_hex_color(&self.cache.zone_right_bottom_color).is_some() {
            &self.cache.zone_right_bottom_color
        } else {
            ""
        }
    }
    pub fn set_zone_right_bottom_color(&mut self, color: &str) -> bool {
        if color.trim().is_empty() {
            self.cache.zone_right_bottom_color.clear();
            return true;
        }
        let Some(normalized) = normalize_hex_color(color) else {
            return false;
        };
        self.cache.zone_right_bottom_color = normalized;
        true
    }
    pub fn zone_right_bottom_alpha(&self) -> f32 {
        let a = self.cache.zone_right_bottom_alpha;
        if a <= 0.0 { 1.0 } else { a.clamp(0.10, 1.0) }
    }
    pub fn set_zone_right_bottom_alpha(&mut self, v: f32) {
        self.cache.zone_right_bottom_alpha = v.clamp(0.10, 1.0);
    }

    // --- Custom per-zone text colours (#custom-zone-text) -------------------
    // Only a primary #RRGGBB is stored; the secondary/muted tiers are derived in
    // theme.slint by lowering opacity. Empty follows the theme. Setters mirror
    // the background-colour setters: empty clears, malformed non-empty returns
    // false. Applied only while the shared per-zone `*_enabled` flag is on.
    pub fn zone_sidebar_text_color(&self) -> &str {
        if normalize_hex_color(&self.cache.zone_sidebar_text_color).is_some() {
            &self.cache.zone_sidebar_text_color
        } else {
            ""
        }
    }
    pub fn set_zone_sidebar_text_color(&mut self, color: &str) -> bool {
        if color.trim().is_empty() {
            self.cache.zone_sidebar_text_color.clear();
            return true;
        }
        let Some(normalized) = normalize_hex_color(color) else {
            return false;
        };
        self.cache.zone_sidebar_text_color = normalized;
        true
    }
    pub fn zone_right_top_text_color(&self) -> &str {
        if normalize_hex_color(&self.cache.zone_right_top_text_color).is_some() {
            &self.cache.zone_right_top_text_color
        } else {
            ""
        }
    }
    pub fn set_zone_right_top_text_color(&mut self, color: &str) -> bool {
        if color.trim().is_empty() {
            self.cache.zone_right_top_text_color.clear();
            return true;
        }
        let Some(normalized) = normalize_hex_color(color) else {
            return false;
        };
        self.cache.zone_right_top_text_color = normalized;
        true
    }
    pub fn zone_right_bottom_text_color(&self) -> &str {
        if normalize_hex_color(&self.cache.zone_right_bottom_text_color).is_some() {
            &self.cache.zone_right_bottom_text_color
        } else {
            ""
        }
    }
    pub fn set_zone_right_bottom_text_color(&mut self, color: &str) -> bool {
        if color.trim().is_empty() {
            self.cache.zone_right_bottom_text_color.clear();
            return true;
        }
        let Some(normalized) = normalize_hex_color(color) else {
            return false;
        };
        self.cache.zone_right_bottom_text_color = normalized;
        true
    }

    pub fn zone_sidebar_enabled(&self) -> bool {
        self.cache.zone_sidebar_enabled
    }
    pub fn set_zone_sidebar_enabled(&mut self, v: bool) {
        self.cache.zone_sidebar_enabled = v;
    }
    pub fn zone_right_top_enabled(&self) -> bool {
        self.cache.zone_right_top_enabled
    }
    pub fn set_zone_right_top_enabled(&mut self, v: bool) {
        self.cache.zone_right_top_enabled = v;
    }
    pub fn zone_right_bottom_enabled(&self) -> bool {
        self.cache.zone_right_bottom_enabled
    }
    pub fn set_zone_right_bottom_enabled(&mut self, v: bool) {
        self.cache.zone_right_bottom_enabled = v;
    }

    /// Custom accent override (#custom-accent). Returns the saved `#RRGGBB` only
    /// when it is a valid hex colour, otherwise an empty string (follow the
    /// wallpaper-derived accent).
    pub fn custom_accent_enabled(&self) -> bool {
        self.cache.custom_accent_enabled
    }
    pub fn set_custom_accent_enabled(&mut self, v: bool) {
        self.cache.custom_accent_enabled = v;
    }
    pub fn custom_accent_color(&self) -> &str {
        if normalize_hex_color(&self.cache.custom_accent_color).is_some() {
            &self.cache.custom_accent_color
        } else {
            ""
        }
    }
    pub fn set_custom_accent_color(&mut self, color: &str) -> bool {
        if color.trim().is_empty() {
            self.cache.custom_accent_color.clear();
            return true;
        }
        let Some(normalized) = normalize_hex_color(color) else {
            return false;
        };
        self.cache.custom_accent_color = normalized;
        true
    }

    pub fn sftp_panel_width(&self) -> f32 {
        let w = self.cache.sftp_panel_width;
        if w <= 0.0 {
            default_sftp_width()
        } else {
            w
        }
    }
    pub fn set_sftp_panel_width(&mut self, v: f32) {
        self.cache.sftp_panel_width = v;
    }
    pub fn sftp_panel_height(&self) -> f32 {
        let h = self.cache.sftp_panel_height;
        if h <= 0.0 {
            default_sftp_height()
        } else {
            h
        }
    }
    pub fn set_sftp_panel_height(&mut self, v: f32) {
        self.cache.sftp_panel_height = v;
    }
    pub fn sftp_dock(&self) -> String {
        let d = self.cache.sftp_dock.trim();
        if d.is_empty() {
            "bottom".into()
        } else {
            d.to_string()
        }
    }
    pub fn set_sftp_dock(&mut self, v: String) {
        self.cache.sftp_dock = v;
    }
    /// Last window size in logical px; `(0,0)` means unset (use the default).
    pub fn window_size(&self) -> (f32, f32) {
        (self.cache.window_width, self.cache.window_height)
    }
    pub fn set_window_size(&mut self, w: f32, h: f32) {
        self.cache.window_width = w;
        self.cache.window_height = h;
    }

    /// Collapse the SFTP panel on startup (default false) (#78).
    pub fn collapse_sftp_default(&self) -> bool {
        self.cache.collapse_sftp_default
    }

    pub fn set_collapse_sftp_default(&mut self, v: bool) {
        self.cache.collapse_sftp_default = v;
    }

    /// Mirror SFTP uploads to other sessions while session-sync is on (default
    /// false). Only has effect when the session-sync toggle is on.
    pub fn sync_upload(&self) -> bool {
        self.cache.sync_upload
    }

    pub fn set_sync_upload(&mut self, v: bool) {
        self.cache.sync_upload = v;
    }

    /// Whether each download prompts for a save location (default false) (#87).
    pub fn download_always_ask(&self) -> bool {
        self.cache.download_always_ask
    }

    pub fn set_download_always_ask(&mut self, ask: bool) {
        self.cache.download_always_ask = ask;
    }

    // ── Session groups / folders (#41) ────────────────────────────────────

    /// Explicit groups (empty folders included). "default" is implicit.
    pub fn groups(&self) -> &[String] {
        &self.cache.groups
    }

    pub fn collapsed_session_groups(&self) -> Option<&[String]> {
        self.cache.collapsed_session_groups.as_deref()
    }

    /// Remember a Quick Connect folder's open/closed state. On the first
    /// interaction, materialise the default-collapsed state for every existing
    /// folder so expanding one folder does not accidentally expand the rest.
    pub fn set_session_group_collapsed(&mut self, name: &str, collapsed: bool) {
        if self.cache.collapsed_session_groups.is_none() {
            let mut groups = vec!["system".to_string()];
            if self
                .cache
                .sessions
                .iter()
                .any(|session| session.group.is_empty())
            {
                groups.push("default".to_string());
            }
            groups.extend(self.cache.groups.iter().cloned());
            groups.extend(
                self.cache
                    .sessions
                    .iter()
                    .filter(|session| !session.group.is_empty())
                    .map(|session| session.group.clone()),
            );
            groups.sort();
            groups.dedup();
            self.cache.collapsed_session_groups = Some(groups);
        }

        let groups = self.cache.collapsed_session_groups.as_mut().unwrap();
        groups.retain(|group| group != name);
        if collapsed {
            groups.push(name.to_string());
            groups.sort();
            groups.dedup();
        }
    }

    /// Create an empty group. Ignores blank names, the reserved "default", and
    /// duplicates.
    pub fn add_group(&mut self, name: String) {
        let n = name.trim().to_string();
        if n.is_empty() || n.eq_ignore_ascii_case("default") {
            return;
        }
        if !self.cache.groups.iter().any(|g| g == &n) {
            self.cache.groups.push(n.clone());
            if let Some(groups) = &mut self.cache.collapsed_session_groups {
                groups.push(n);
                groups.sort();
                groups.dedup();
            }
        }
    }

    /// Delete a group. Any session still in it falls back to ungrouped — the UI
    /// only offers delete on empty groups, but we clear sessions defensively.
    pub fn remove_group(&mut self, name: &str) {
        self.cache.groups.retain(|g| g != name);
        if let Some(groups) = &mut self.cache.collapsed_session_groups {
            groups.retain(|group| group != name);
        }
        for s in &mut self.cache.sessions {
            if s.group == name {
                s.group.clear();
            }
        }
    }

    /// Rename a group, moving its sessions along. No-op for blank / "default".
    pub fn rename_group(&mut self, old: &str, new: String) {
        let n = new.trim().to_string();
        if n.is_empty() || n.eq_ignore_ascii_case("default") || n == old {
            return;
        }
        for g in &mut self.cache.groups {
            if g == old {
                *g = n.clone();
            }
        }
        for s in &mut self.cache.sessions {
            if s.group == old {
                s.group = n.clone();
            }
        }
        if let Some(groups) = &mut self.cache.collapsed_session_groups {
            for group in groups.iter_mut() {
                if group == old {
                    *group = n.clone();
                }
            }
            groups.sort();
            groups.dedup();
        }
        self.cache.groups.sort();
        self.cache.groups.dedup();
    }

    pub fn save(&self) -> Result<()> {
        let raw = if let Some(enc) = &self.enc {
            // Whole-file encryption: seal the *entire* ConfigFile (passwords stay
            // plaintext inside the sealed body — the body itself is the
            // protection) and write it as a plaintext-header envelope.
            let envelope = Self::build_envelope(&self.cache, enc)?;
            serde_json::to_string_pretty(&envelope)?
        } else {
            // Plaintext track (original behaviour): a disk copy where every
            // non-empty password is per-field encrypted with `secret.key`.
            let mut disk = self.cache.clone();
            for session in &mut disk.sessions {
                if !session.password.is_empty()
                    && !session.password.as_str().starts_with(Self::ENC_PREFIX)
                {
                    let enc = Self::encrypt(&self.key, session.password.as_str())?;
                    session.password = Secret::new(enc);
                }
                if !session.private_key_inline.is_empty()
                    && !session
                        .private_key_inline
                        .as_str()
                        .starts_with(Self::ENC_PREFIX)
                {
                    let enc = Self::encrypt(&self.key, session.private_key_inline.as_str())?;
                    session.private_key_inline = Secret::new(enc);
                }
            }
            serde_json::to_string_pretty(&disk)?
        };
        self.write_atomic(&raw)
    }

    /// Atomically publish `raw` to `self.path`: write a sibling temp file
    /// (owner-only on Unix) then rename over the target. Shared by both the
    /// plaintext and encrypted save paths.
    fn write_atomic(&self, raw: &str) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, raw).with_context(|| format!("failed to write {}", tmp.display()))?;
        // Restrict to owner-only before publishing (#34): sessions.json holds
        // (encrypted) credentials, so it shouldn't be world-readable. Set 0600
        // on the temp file so the permission is already in place at rename.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", tmp.display()))?;
        }
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("failed to finalise {}", self.path.display()))?;
        Ok(())
    }

    // ── Startup-password / whole-file encryption management ────────────────

    /// Whether a startup password is currently set (whole-file encryption on).
    pub fn is_encrypted(&self) -> bool {
        self.enc.is_some()
    }

    /// Turn on whole-file encryption with `password`. Generates a fresh random
    /// DEK, wraps it under the password-derived KEK, and rewrites `sessions.json`
    /// as an encrypted envelope. No-op-safe to call only when currently
    /// unencrypted; returns an error otherwise so callers don't silently reset
    /// the DEK (which would be a data-loss footgun if misused).
    pub fn enable_encryption(&mut self, password: &str) -> Result<()> {
        if self.enc.is_some() {
            anyhow::bail!("encryption is already enabled");
        }
        if password.is_empty() {
            anyhow::bail!("password must not be empty");
        }
        let mut salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let params = KdfParams::interactive();
        let kek = Self::derive_kek(password, &salt, &params)?;

        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);
        let wrapped_dek = Self::seal(&kek, &dek)?;

        self.enc = Some(EncState {
            dek,
            salt,
            params,
            wrapped_dek,
        });
        // Persist immediately so the on-disk file becomes an envelope now.
        self.save()
    }

    /// Change the startup password without touching the sealed data: re-derive a
    /// KEK from `new_password` (fresh salt) and re-wrap the *same* DEK.
    /// `current_password` is verified first so a wrong entry can't silently
    /// replace the wrapping. Errors if encryption is not enabled.
    pub fn change_password(&mut self, current_password: &str, new_password: &str) -> Result<()> {
        let enc = self
            .enc
            .as_ref()
            .context("encryption is not enabled")?;
        // Verify the current password by unwrapping the existing DEK.
        let cur_kek = Self::derive_kek(current_password, &enc.salt, &enc.params)?;
        if Self::open(&cur_kek, &enc.wrapped_dek).is_none() {
            anyhow::bail!("current password is incorrect");
        }
        if new_password.is_empty() {
            anyhow::bail!("new password must not be empty");
        }
        let dek = enc.dek;
        let params = KdfParams::interactive();
        let mut salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let new_kek = Self::derive_kek(new_password, &salt, &params)?;
        let wrapped_dek = Self::seal(&new_kek, &dek)?;
        self.enc = Some(EncState {
            dek,
            salt,
            params,
            wrapped_dek,
        });
        self.save()
    }

    /// Turn off whole-file encryption, verifying `current_password` first, and
    /// rewrite `sessions.json` back to the plaintext track. Errors on a wrong
    /// password or if encryption isn't enabled.
    pub fn disable_encryption(&mut self, current_password: &str) -> Result<()> {
        let enc = self
            .enc
            .as_ref()
            .context("encryption is not enabled")?;
        let kek = Self::derive_kek(current_password, &enc.salt, &enc.params)?;
        if Self::open(&kek, &enc.wrapped_dek).is_none() {
            anyhow::bail!("current password is incorrect");
        }
        self.enc = None;
        // Rewrites as plaintext (per-field encryption under secret.key).
        self.save()
    }

    // ── Portable export / import (issue #46) ──────────────────────────────

    /// Encrypt a password with the portable export key → `"enc:exp:v1:<b64>"`.
    fn encrypt_export(plaintext: &str) -> Result<String> {
        let cipher = ChaCha20Poly1305::new((&Self::EXPORT_KEY).into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("export encrypt error: {e}"))?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&ciphertext);
        Ok(format!(
            "{}{}",
            Self::EXPORT_PREFIX,
            URL_SAFE_NO_PAD.encode(&blob)
        ))
    }

    /// Decrypt a value produced by [`Self::encrypt_export`]; `None` if it isn't one.
    fn decrypt_export(s: &str) -> Option<String> {
        let b64 = s.strip_prefix(Self::EXPORT_PREFIX)?;
        let blob = URL_SAFE_NO_PAD.decode(b64).ok()?;
        if blob.len() < 12 {
            return None;
        }
        let (nonce_bytes, ciphertext) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new((&Self::EXPORT_KEY).into());
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
        let plain = cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plain).ok()
    }

    /// Export all sessions to a portable JSON file. Passwords are re-encrypted
    /// with the built-in export key; everything else stays plaintext so the
    /// file is human-readable and editable. Returns the number of sessions.
    pub fn export_json(&self) -> Result<(String, usize)> {
        let mut out = ExportFile {
            newshell_export: 1,
            sessions: self.cache.sessions.clone(),
            quick_commands: self.cache.quick_commands.clone(),
            quick_groups: self.cache.quick_groups.clone(),
        };
        for s in &mut out.sessions {
            // `cache` holds plaintext passwords; obfuscate with the export key.
            if !s.password.is_empty() {
                let enc = Self::encrypt_export(s.password.as_str())?;
                s.password = Secret::new(enc);
            }
            if !s.private_key_inline.is_empty() {
                let enc = Self::encrypt_export(s.private_key_inline.as_str())?;
                s.private_key_inline = Secret::new(enc);
            }
            // `last_used` is machine-local noise — don't carry it across.
            s.last_used = None;
        }
        Ok((serde_json::to_string_pretty(&out)?, out.sessions.len()))
    }

    /// Export all sessions to a portable JSON file. Passwords are re-encrypted
    /// with the built-in export key; everything else stays plaintext so the
    /// file is human-readable and editable. Returns the number of sessions.
    pub fn export_to(&self, path: &Path) -> Result<usize> {
        let (raw, count) = self.export_json()?;
        fs::write(path, raw).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(count)
    }

    /// Import sessions **and quick commands** from a string produced by
    /// [`Self::export_json`]. New sessions get fresh ids; duplicate sessions
    /// (same host+user+port+kind) and duplicate quick commands (same
    /// name+command+group) are skipped. The store is saved if anything was added.
    pub fn import_json(&mut self, raw: &str) -> Result<ImportReport> {
        let file: ExportFile =
            serde_json::from_str(&raw).context("not a valid newshell export file")?;

        let mut added = 0usize;
        let mut skipped = 0usize;
        for mut s in file.sessions {
            // Recover the plaintext password (cache stores plaintext). Accept an
            // export blob, our local enc:v1 blob, or a legacy plaintext value.
            if let Some(plain) = Self::decrypt_export(s.password.as_str()) {
                s.password = Secret::new(plain);
            } else if let Some(plain) = Self::try_decrypt(&self.key, s.password.as_str()) {
                s.password = Secret::new(plain);
            }
            if let Some(plain) = Self::decrypt_export(s.private_key_inline.as_str()) {
                s.private_key_inline = Secret::new(plain);
            } else if let Some(plain) = Self::try_decrypt(&self.key, s.private_key_inline.as_str())
            {
                s.private_key_inline = Secret::new(plain);
            }
            let dup = self.cache.sessions.iter().any(|x| {
                x.host == s.host && x.user == s.user && x.port == s.port && x.kind == s.kind
            });
            if dup {
                skipped += 1;
                continue;
            }
            s.id = Uuid::new_v4().to_string();
            self.cache.sessions.push(s);
            added += 1;
        }
        let (quick_added, quick_skipped) =
            self.merge_quick_commands(file.quick_commands, file.quick_groups);
        if added > 0 || quick_added > 0 {
            self.save()?;
        }
        Ok(ImportReport {
            sessions_added: added,
            sessions_skipped: skipped,
            quick_added,
            quick_skipped,
        })
    }

    /// Import sessions from a file produced by [`Self::export_to`].
    pub fn import_from(&mut self, path: &Path) -> Result<ImportReport> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        self.import_json(&raw)
    }

    /// Merge imported quick commands + groups into the cache (#55). Quick commands
    /// are de-duplicated by (name, command, group); groups are unioned. Non-empty
    /// groups referenced by an added command are registered so they show up in the
    /// group list even when the export omitted them. Returns `(added, skipped)`.
    fn merge_quick_commands(
        &mut self,
        cmds: Vec<QuickCommand>,
        groups: Vec<String>,
    ) -> (usize, usize) {
        // Register any explicit (possibly empty) groups first. `add_quick_group`
        // trims, ignores blank/"default", and de-duplicates.
        for g in groups {
            self.add_quick_group(g);
        }
        let mut added = 0usize;
        let mut skipped = 0usize;
        for c in cmds {
            let dup = self
                .cache
                .quick_commands
                .iter()
                .any(|x| x.name == c.name && x.command == c.command && x.group == c.group);
            if dup {
                skipped += 1;
                continue;
            }
            if !c.group.trim().is_empty() {
                self.add_quick_group(c.group.clone());
            }
            self.cache.quick_commands.push(c);
            added += 1;
        }
        (added, skipped)
    }

    // ── Encrypted export / import (startup-password track) ─────────────────

    /// True if `raw` is an encrypted export envelope (needs a password to
    /// import). Lets the UI decide whether to prompt before importing.
    ///
    /// Detection is **content-based**, mirroring [`Self::detect_envelope`]: it is
    /// not enough for the `newshell_export_enc` marker to be present. Every sealed
    /// field (salt, wrapped DEK, ciphertext) must base64url-decode to a plausible
    /// length and the KDF parameters must be sane. So a user who copies an export,
    /// hand-edits the JSON (e.g. flips a field, pastes a plaintext value, or bolts
    /// the marker onto a plaintext export) can no longer make it *look* encrypted:
    /// it is either a real encrypted envelope or it is treated as plaintext.
    pub fn is_encrypted_export(raw: &str) -> bool {
        let Ok(e) = serde_json::from_str::<EncryptedExport>(raw) else {
            return false;
        };
        e.newshell_export_enc != 0
            && Self::envelope_fields_valid(&e.kdf, &e.kdf_params, &e.salt, &e.enc_dek, &e.ciphertext)
    }

    /// True if the file at `path` is an encrypted export envelope.
    pub fn file_is_encrypted_export(path: &Path) -> bool {
        fs::read_to_string(path)
            .map(|raw| Self::is_encrypted_export(&raw))
            .unwrap_or(false)
    }

    /// Export all sessions as a **password-protected** portable file. Only valid
    /// while whole-file encryption is active: the sessions are sealed under the
    /// in-memory DEK, and the DEK is carried wrapped under the current startup
    /// password (via the existing `EncState`), so importing on another machine
    /// needs that same password — no re-prompt here (issue: copy-protected
    /// export). Returns the JSON string and the session count.
    pub fn export_encrypted_json(&self) -> Result<(String, usize)> {
        let enc = self
            .enc
            .as_ref()
            .context("encrypted export requires a startup password to be set")?;
        let mut sessions = self.cache.sessions.clone();
        for s in &mut sessions {
            // `last_used` is machine-local noise — don't carry it across.
            s.last_used = None;
        }
        let count = sessions.len();
        let payload = EncryptedPayload {
            sessions,
            quick_commands: self.cache.quick_commands.clone(),
            quick_groups: self.cache.quick_groups.clone(),
        };
        let body = Self::seal(&enc.dek, &serde_json::to_vec(&payload)?)?;
        let out = EncryptedExport {
            newshell_export_enc: 1,
            kdf: "argon2id".into(),
            kdf_params: enc.params.clone(),
            salt: URL_SAFE_NO_PAD.encode(&enc.salt),
            enc_dek: URL_SAFE_NO_PAD.encode(&enc.wrapped_dek),
            ciphertext: URL_SAFE_NO_PAD.encode(&body),
        };
        Ok((serde_json::to_string_pretty(&out)?, count))
    }

    /// Write [`export_encrypted_json`](Self::export_encrypted_json) to `path`.
    pub fn export_encrypted_to(&self, path: &Path) -> Result<usize> {
        let (raw, count) = self.export_encrypted_json()?;
        fs::write(path, raw).with_context(|| format!("failed to write {}", path.display()))?;
        Ok(count)
    }

    /// Import from an encrypted export produced by
    /// [`export_encrypted_json`](Self::export_encrypted_json), unlocking it with
    /// `password`. Returns `Ok(None)` when the password is wrong (so the UI can
    /// re-prompt), `Ok(Some(report))` on success, and `Err` only for a
    /// malformed/corrupt file. Dedup rules match [`import_json`](Self::import_json).
    pub fn import_encrypted_json(
        &mut self,
        raw: &str,
        password: &str,
    ) -> Result<Option<ImportReport>> {
        let env: EncryptedExport =
            serde_json::from_str(raw).context("not a valid encrypted newshell export")?;
        let salt = URL_SAFE_NO_PAD
            .decode(env.salt.as_bytes())
            .context("malformed export salt")?;
        let wrapped_dek = URL_SAFE_NO_PAD
            .decode(env.enc_dek.as_bytes())
            .context("malformed export key")?;
        let body = URL_SAFE_NO_PAD
            .decode(env.ciphertext.as_bytes())
            .context("malformed export body")?;

        let kek = Self::derive_kek(password, &salt, &env.kdf_params)?;
        let Some(dek_bytes) = Self::open(&kek, &wrapped_dek) else {
            return Ok(None); // wrong password
        };
        if dek_bytes.len() != 32 {
            anyhow::bail!("corrupt export: unexpected key length");
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);
        let plain = Self::open(&dek, &body)
            .context("corrupt export: body failed authentication")?;
        dek.zeroize();

        // The payload shape evolved. Newer exports seal an `EncryptedPayload` with
        // sessions, quick_commands, and quick_groups; older exports sealed a bare
        // `Vec<Session>`. Try the new shape first; fall back to the bare Vec on a
        // structure mismatch so old encrypted exports keep opening (#55).
        let report = match serde_json::from_slice::<EncryptedPayload>(&plain) {
            Ok(payload) => {
                let (s_added, s_skipped) = self.merge_sessions(payload.sessions);
                let (q_added, q_skipped) =
                    self.merge_quick_commands(payload.quick_commands, payload.quick_groups);
                ImportReport {
                    sessions_added: s_added,
                    sessions_skipped: s_skipped,
                    quick_added: q_added,
                    quick_skipped: q_skipped,
                }
            }
            Err(_) => {
                // Not the new payload shape → try the old bare Vec<Session>.
                let sessions: Vec<Session> =
                    serde_json::from_slice(&plain).context("corrupt export: bad session data")?;
                let (added, skipped) = self.merge_sessions(sessions);
                ImportReport {
                    sessions_added: added,
                    sessions_skipped: skipped,
                    quick_added: 0,
                    quick_skipped: 0,
                }
            }
        };
        if report.sessions_added > 0 || report.quick_added > 0 {
            self.save()?;
        }
        Ok(Some(report))
    }

    /// Import from an encrypted export file. See [`import_encrypted_json`].
    ///
    /// The UI import path reads the file itself and calls `import_encrypted_json`
    /// directly (so it can show a busy state around the argon2id pass), so this
    /// file-level convenience wrapper is only exercised by tests — kept for
    /// symmetry with [`import_from`](Self::import_from). Gated to `test` builds so
    /// it doesn't trip dead-code warnings in the shipped binary (a `pub` method in
    /// a binary crate is still flagged when nothing outside tests calls it).
    #[cfg(test)]
    pub fn import_encrypted_from(
        &mut self,
        path: &Path,
        password: &str,
    ) -> Result<Option<ImportReport>> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        self.import_encrypted_json(&raw, password)
    }

    /// Add `sessions` to the cache, skipping duplicates (same host+user+port+
    /// kind) and assigning fresh ids. Returns `(added, skipped)`. Shared by the
    /// plaintext and encrypted import paths.
    fn merge_sessions(&mut self, sessions: Vec<Session>) -> (usize, usize) {
        let mut added = 0usize;
        let mut skipped = 0usize;
        for mut s in sessions {
            let dup = self.cache.sessions.iter().any(|x| {
                x.host == s.host && x.user == s.user && x.port == s.port && x.kind == s.kind
            });
            if dup {
                skipped += 1;
                continue;
            }
            s.id = Uuid::new_v4().to_string();
            self.cache.sessions.push(s);
            added += 1;
        }
        (added, skipped)
    }
}

impl LockedStore {
    /// Renderer preference read from the plaintext envelope header, so platform
    /// and backend init can run before the unlock window is created. Mirrors
    /// [`ConfigStore::renderer_mode`]'s platform defaulting.
    #[cfg(target_os = "macos")]
    pub fn renderer_mode(&self) -> &str {
        match self.envelope.renderer_mode.as_str() {
            "femtovg" => "femtovg",
            _ => "skia",
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn renderer_mode(&self) -> &str {
        match self.envelope.renderer_mode.as_str() {
            "auto" => "auto",
            "gpu" => "gpu",
            _ => "software",
        }
    }

    /// Theme preference ("system" | "dark" | "light") mirrored in the plaintext
    /// header so the unlock window can pick light/dark before decryption. Not
    /// sensitive.
    pub fn theme_pref(&self) -> &str {
        &self.envelope.theme_pref
    }

    /// Immersive wallpaper id ("" = none) mirrored in the plaintext header so the
    /// unlock window can show the same backdrop as the app. Not sensitive.
    pub fn wallpaper(&self) -> &str {
        &self.envelope.wallpaper
    }

    /// Global UI scale in percent (0 = default 100%), mirrored in the header.
    // The unlock screen is intentionally exempt from UI-scale (it renders at a
    // fixed 1.0), so this header accessor currently has no caller. Kept for
    // symmetry with the other plaintext-header getters and in case a future
    // pre-decryption view wants it.
    #[allow(dead_code)]
    pub fn ui_scale(&self) -> u32 {
        if self.envelope.ui_scale == 0 {
            100
        } else {
            self.envelope.ui_scale
        }
    }

    /// UI font family override ("" = auto), mirrored in the header.
    pub fn ui_font_family(&self) -> &str {
        &self.envelope.ui_font_family
    }

    /// UI language ("zh" default / "en"), mirrored in the plaintext header so the
    /// unlock window can render in the user's chosen language pre-decryption.
    pub fn language(&self) -> &str {
        if self.envelope.language.is_empty() {
            "zh"
        } else {
            &self.envelope.language
        }
    }

    /// Attempt to unlock the encrypted config with `password`.
    ///
    /// * `Ok(Some(store))` — correct password; the returned store is fully
    ///   usable and stays in encrypted mode (subsequent saves re-seal).
    /// * `Ok(None)` — wrong password; the caller can re-prompt against this same
    ///   `LockedStore`.
    /// * `Err(_)` — the envelope is corrupt/malformed (not a wrong-password
    ///   case).
    pub fn unlock(&self, password: &str) -> Result<Option<ConfigStore>> {
        let salt = URL_SAFE_NO_PAD
            .decode(self.envelope.salt.as_bytes())
            .context("malformed envelope salt")?;
        let wrapped_dek = URL_SAFE_NO_PAD
            .decode(self.envelope.enc_dek.as_bytes())
            .context("malformed wrapped key")?;
        let body = URL_SAFE_NO_PAD
            .decode(self.envelope.ciphertext.as_bytes())
            .context("malformed ciphertext")?;

        let kek = ConfigStore::derive_kek(password, &salt, &self.envelope.kdf_params)?;
        let Some(dek_bytes) = ConfigStore::open(&kek, &wrapped_dek) else {
            return Ok(None); // wrong password — DEK unwrap failed authentication
        };
        if dek_bytes.len() != 32 {
            anyhow::bail!("corrupt config: unexpected key length");
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_bytes);

        let plain = ConfigStore::open(&dek, &body)
            .context("corrupt config: body failed authentication")?;
        let mut cfg: ConfigFile =
            serde_json::from_slice(&plain).context("corrupt config: bad JSON body")?;
        let _ = ConfigStore::post_process(&mut cfg, &self.key);

        let enc = EncState {
            dek,
            salt,
            params: self.envelope.kdf_params.clone(),
            wrapped_dek,
        };
        let store = ConfigStore {
            path: self.path.clone(),
            cache: cfg,
            key: self.key,
            enc: Some(enc),
        };
        Ok(Some(store))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// True if `path` is a config file that parses and has at least one session.
    fn sessions_file_has_connections(path: &Path) -> bool {
        let Ok(raw) = fs::read_to_string(path) else {
            return false;
        };
        serde_json::from_str::<ConfigFile>(&raw)
            .map(|cfg| !cfg.sessions.is_empty())
            .unwrap_or(false)
    }

    fn temp_store() -> ConfigStore {
        let path = std::env::temp_dir().join(format!("ms-test-{}.json", Uuid::new_v4()));
        ConfigStore {
            path,
            cache: ConfigFile::default(),
            key: [7u8; 32],
            enc: None,
        }
    }

    #[test]
    fn ui_font_family_is_separate_from_terminal_and_roundtrips() {
        let mut store = temp_store();
        // Fresh install: no interface-font override (empty = auto system font),
        // and it is independent of the terminal font.
        assert_eq!(store.ui_font_family(), "");
        assert_eq!(store.font_family(), "");

        // Setting the UI font must NOT touch the terminal font, and vice-versa.
        store.set_ui_font_family("Helvetica Neue".into());
        store.set_font_family("Menlo".into());
        assert_eq!(store.ui_font_family(), "Helvetica Neue");
        assert_eq!(store.font_family(), "Menlo");

        // Returning to the system default is an empty string.
        store.set_ui_font_family(String::new());
        assert_eq!(store.ui_font_family(), "");

        // Upgrading users whose config predates this key still deserialize.
        store.cache = serde_json::from_str("{}").expect("legacy config must deserialize");
        assert_eq!(store.ui_font_family(), "");
    }

    #[test]
    fn terminal_cursor_style_defaults_and_validates() {
        let mut store = temp_store();
        assert_eq!(store.terminal_cursor_style(), "block");

        store.set_terminal_cursor_style("bar".into());
        assert_eq!(store.terminal_cursor_style(), "bar");
        store.set_terminal_cursor_style("underline".into());
        assert_eq!(store.terminal_cursor_style(), "underline");
        store.set_terminal_cursor_style("unexpected".into());
        assert_eq!(store.terminal_cursor_style(), "block");

        store.cache = serde_json::from_str("{}").expect("legacy config must deserialize");
        assert_eq!(store.terminal_cursor_style(), "block");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn renderer_mode_preserves_compatibility_default_and_validates() {
        let mut store = temp_store();
        assert_eq!(store.renderer_mode(), "software");

        store.set_renderer_mode("auto".into());
        assert_eq!(store.renderer_mode(), "auto");
        store.set_renderer_mode("gpu".into());
        assert_eq!(store.renderer_mode(), "gpu");
        store.set_renderer_mode("unexpected".into());
        assert_eq!(store.renderer_mode(), "software");

        store.cache = serde_json::from_str("{}").expect("legacy config must deserialize");
        assert_eq!(store.renderer_mode(), "software");
    }

    #[test]
    fn quick_connect_groups_default_collapsed_and_remember_expansion() {
        let mut store = temp_store();
        store.cache.groups = vec!["production".into(), "staging".into()];
        store.cache.sessions.push(Session {
            group: "production".into(),
            ..sample_session("server")
        });

        assert!(store.collapsed_session_groups().is_none());
        store.set_session_group_collapsed("production", false);

        let collapsed = store.collapsed_session_groups().unwrap();
        assert!(!collapsed.iter().any(|group| group == "production"));
        assert!(collapsed.iter().any(|group| group == "staging"));
        assert!(collapsed.iter().any(|group| group == "system"));

        store.set_session_group_collapsed("production", true);
        assert!(store
            .collapsed_session_groups()
            .unwrap()
            .iter()
            .any(|group| group == "production"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn renderer_mode_uses_macos_backends_and_validates() {
        let mut store = temp_store();
        // Fresh install (empty renderer_mode) now defaults to Skia for crisp,
        // CoreText-rendered UI text (#font-blur).
        assert_eq!(store.renderer_mode(), "skia");

        // Explicit opt-out to FemtoVG is honoured.
        store.set_renderer_mode("femtovg".into());
        assert_eq!(store.renderer_mode(), "femtovg");
        // Switching back to Skia works.
        store.set_renderer_mode("skia".into());
        assert_eq!(store.renderer_mode(), "skia");
        // Any unknown value normalizes to the Skia default, not FemtoVG.
        store.set_renderer_mode("unexpected".into());
        assert_eq!(store.renderer_mode(), "skia");

        // Upgrading users whose config predates this key (no field at all) also
        // get Skia rather than staying on the old blurry FemtoVG default.
        store.cache = serde_json::from_str("{}").expect("legacy config must deserialize");
        assert_eq!(store.renderer_mode(), "skia");
    }

    #[test]
    fn terminal_cursor_color_normalizes_and_rejects_invalid_values() {
        let mut store = temp_store();
        assert_eq!(store.terminal_cursor_color(), "");

        assert!(store.set_terminal_cursor_color("#1a2B3c"));
        assert_eq!(store.terminal_cursor_color(), "#1A2B3C");
        assert!(store.set_terminal_cursor_color("abcdef"));
        assert_eq!(store.terminal_cursor_color(), "#ABCDEF");

        assert!(!store.set_terminal_cursor_color("#12345"));
        assert_eq!(store.terminal_cursor_color(), "#ABCDEF");
        assert!(!store.set_terminal_cursor_color("#GG0000"));
        assert_eq!(store.terminal_cursor_color(), "#ABCDEF");
    }

    fn sample_session(name: &str) -> Session {
        Session {
            name: name.into(),
            host: "192.168.100.2".into(),
            port: 22,
            user: "root".into(),
            ..Session::new_empty()
        }
    }

    #[test]
    fn save_writes_only_to_its_own_directory() {
        // Portable-only invariant: save() must touch nothing but the config
        // folder it was given — no sibling/backup directory is ever created.
        let base = std::env::temp_dir().join(format!("ms-portable-{}", Uuid::new_v4()));
        let config_dir = base.join("config");
        std::fs::create_dir_all(&config_dir).unwrap();

        let store = ConfigStore {
            path: config_dir.join("sessions.json"),
            cache: ConfigFile {
                sessions: vec![sample_session("only")],
                ..ConfigFile::default()
            },
            key: [7u8; 32],
            enc: None,
        };
        store.save().unwrap();

        // The session file exists exactly where we asked for it.
        assert!(sessions_file_has_connections(
            &config_dir.join("sessions.json")
        ));

        // `base` contains the `config` dir and nothing else — no stray backup
        // dir, no per-user mirror.
        let entries: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("config")]);

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn wallpaper_defaults_to_dark_but_keeps_explicit_choice() {
        // Fresh install (no file).
        let fresh = fresh_config();
        assert_eq!(fresh.wallpaper, "builtin:dark");
        assert!((fresh.wallpaper_overlay - 0.85).abs() < f32::EPSILON);
        // User upgrading from before the feature: JSON without the key.
        let cfg: ConfigFile = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.wallpaper, "builtin:tech");
        // An explicit "无"/none (stored as "") is preserved, not re-defaulted.
        let cfg: ConfigFile = serde_json::from_str(r#"{"wallpaper":""}"#).unwrap();
        assert_eq!(cfg.wallpaper, "");
        // A custom choice is preserved.
        let cfg: ConfigFile = serde_json::from_str(r#"{"wallpaper":"builtin:light"}"#).unwrap();
        assert_eq!(cfg.wallpaper, "builtin:light");

        let mut cfg = ConfigFile {
            wallpaper: "builtin:miku".to_string(),
            defaults_rev: DEFAULTS_REV,
            ..ConfigFile::default()
        };
        assert!(!migrate_defaults(&mut cfg));
        assert_eq!(cfg.wallpaper, "builtin:miku");
    }

    #[test]
    fn wallpaper_transparency_default_migrates_without_overwriting_custom_value() {
        let mut old_default = ConfigFile {
            wallpaper_overlay: PREVIOUS_DEFAULT_WALLPAPER_OVERLAY,
            defaults_rev: 2,
            ..ConfigFile::default()
        };
        assert!(migrate_defaults(&mut old_default));
        assert!((old_default.wallpaper_overlay - 0.85).abs() < f32::EPSILON);

        let mut custom = ConfigFile {
            wallpaper_overlay: 0.70,
            defaults_rev: 2,
            ..ConfigFile::default()
        };
        assert!(migrate_defaults(&mut custom));
        assert!((custom.wallpaper_overlay - 0.70).abs() < f32::EPSILON);
    }

    #[test]
    fn output_highlight_defaults_and_preset_validation() {
        let mut store = temp_store();
        assert!(store.output_highlight_enabled());
        assert_eq!(store.output_highlight_preset(), "log");

        store.set_output_highlight_enabled(false);
        store.set_output_highlight_preset("devops".to_string());
        assert!(!store.output_highlight_enabled());
        assert_eq!(store.output_highlight_preset(), "devops");

        store.set_output_highlight_preset("future-preset".to_string());
        assert_eq!(store.output_highlight_preset(), "log");

        store.add_output_highlight_rule(OutputHighlightRule {
            pattern: "  connection refused  ".to_string(),
            regex: false,
            case_sensitive: false,
            whole_line: true,
            color: "unknown".to_string(),
            enabled: true,
        });
        assert_eq!(store.output_highlight_rules().len(), 1);
        assert_eq!(
            store.output_highlight_rules()[0].pattern,
            "connection refused"
        );
        assert_eq!(store.output_highlight_rules()[0].color, "red");
        store.set_output_highlight_rule_enabled(0, false);
        assert!(!store.output_highlight_rules()[0].enabled);
        store.remove_output_highlight_rule(0);
        assert!(store.output_highlight_rules().is_empty());

        // An older settings file without either field retains the feature that
        // shipped in the previous version: enabled with the log preset.
        let legacy: ConfigFile = serde_json::from_str("{}").unwrap();
        store.cache = legacy;
        assert!(store.output_highlight_enabled());
        assert_eq!(store.output_highlight_preset(), "log");
    }

    #[test]
    fn saved_password_encrypts_and_decrypts_without_changes() {
        let mut store = temp_store();
        let password = "p@ss word!^&*中文";
        store.cache.sessions.push(Session {
            name: "windows-password".into(),
            host: "192.168.100.2".into(),
            port: 22,
            user: "root".into(),
            password: Secret::new(password),
            ..Session::new_empty()
        });

        store.save().unwrap();
        let raw = std::fs::read_to_string(&store.path).unwrap();
        assert!(!raw.contains(password));
        let disk: ConfigFile = serde_json::from_str(&raw).unwrap();
        let encrypted = disk.sessions[0].password.as_str();
        assert!(encrypted.starts_with(ConfigStore::ENC_PREFIX));
        assert_eq!(
            ConfigStore::try_decrypt(&store.key, encrypted).as_deref(),
            Some(password)
        );

        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn export_import_roundtrip_preserves_password() {
        let mut a = temp_store();
        a.cache.sessions.push(Session {
            name: "pve".into(),
            host: "192.168.100.2".into(),
            port: 22,
            user: "root".into(),
            password: Secret::new("s3cr3t"),
            ..Session::new_empty()
        });
        // Quick commands ride along in the same export file (#55).
        a.cache.quick_commands.push(QuickCommand {
            name: "tail log".into(),
            command: "tail -f /var/log/syslog".into(),
            group: "ops".into(),
            send_enter: true,
        });
        a.cache.quick_groups.push("ops".into());

        let export_path = std::env::temp_dir().join(format!("ms-exp-{}.json", Uuid::new_v4()));
        assert_eq!(a.export_to(&export_path).unwrap(), 1);

        // The file keeps host/user plaintext but the password is obfuscated, and
        // it carries the quick command too.
        let raw = std::fs::read_to_string(&export_path).unwrap();
        assert!(raw.contains("192.168.100.2"));
        assert!(raw.contains(ConfigStore::EXPORT_PREFIX));
        assert!(!raw.contains("s3cr3t"));
        assert!(raw.contains("tail -f /var/log/syslog"));

        // Importing into a fresh store recovers the plaintext password and the
        // quick command / group.
        let mut b = temp_store();
        let rep = b.import_from(&export_path).unwrap();
        assert_eq!(rep.sessions_added, 1);
        assert_eq!(rep.sessions_skipped, 0);
        assert_eq!(rep.quick_added, 1);
        assert_eq!(b.cache.sessions.len(), 1);
        assert_eq!(b.cache.sessions[0].password.as_str(), "s3cr3t");
        assert_eq!(b.cache.sessions[0].host, "192.168.100.2");
        assert_eq!(b.cache.quick_commands.len(), 1);
        assert_eq!(b.cache.quick_commands[0].command, "tail -f /var/log/syslog");
        assert!(b.cache.quick_groups.iter().any(|g| g == "ops"));

        // Re-importing the same file skips both the duplicate session and command.
        let rep2 = b.import_from(&export_path).unwrap();
        assert_eq!(rep2.sessions_added, 0);
        assert_eq!(rep2.sessions_skipped, 1);
        assert_eq!(rep2.quick_added, 0);
        assert_eq!(rep2.quick_skipped, 1);

        let _ = std::fs::remove_file(&export_path);
        let _ = std::fs::remove_file(&a.path);
        let _ = std::fs::remove_file(&b.path);
    }

    // ── Whole-file encryption / startup password ──────────────────────────

    /// A ConfigStore bound to a real (temp) path so save()/load()/unlock() can
    /// round-trip through the filesystem like production. Returns the store and
    /// its config dir (caller cleans up).
    fn temp_store_at(dir: &Path) -> ConfigStore {
        ConfigStore {
            path: dir.join("sessions.json"),
            cache: ConfigFile::default(),
            key: [9u8; 32],
            enc: None,
        }
    }

    fn unique_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ms-enc-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn enable_encryption_seals_file_and_unlock_roundtrips() {
        let dir = unique_dir("roundtrip");
        let mut store = temp_store_at(&dir);
        store.cache.sessions.push(Session {
            name: "pve".into(),
            host: "10.0.0.9".into(),
            port: 22,
            user: "root".into(),
            password: Secret::new("hunter2中文"),
            ..Session::new_empty()
        });
        store.save().unwrap();

        // Turn encryption on. The on-disk file must now be an envelope with NO
        // plaintext session data (neither host nor password leaks).
        store.enable_encryption("launch-pw").unwrap();
        assert!(store.is_encrypted());
        let raw = std::fs::read_to_string(&store.path).unwrap();
        assert!(raw.contains("newshell_enc"));
        assert!(raw.contains("ciphertext"));
        assert!(!raw.contains("10.0.0.9"), "host leaked into envelope");
        assert!(!raw.contains("hunter2"), "password leaked into envelope");
        // A plaintext ConfigFile parse must fail (it's an envelope now).
        assert!(serde_json::from_str::<ConfigFile>(&raw).is_err());

        // Re-loading detects encryption and returns Locked.
        drop(store);
        let loaded = load_from(&dir);
        let locked = match loaded {
            LoadedConfig::Locked(l) => l,
            _ => panic!("expected Locked"),
        };

        // Wrong password → Ok(None), can retry.
        assert!(locked.unlock("nope").unwrap().is_none());
        // Correct password → usable store with data intact and still encrypted.
        let unlocked = locked.unlock("launch-pw").unwrap().expect("right password");
        assert!(unlocked.is_encrypted());
        assert_eq!(unlocked.sessions().len(), 1);
        assert_eq!(unlocked.sessions()[0].host, "10.0.0.9");
        assert_eq!(unlocked.sessions()[0].password.as_str(), "hunter2中文");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reload a store from a config dir via the real detection path.
    fn load_from(dir: &Path) -> LoadedConfig {
        // Mirror ConfigStore::load but against an explicit path (tests can't
        // rely on data_dir()).
        let path = dir.join("sessions.json");
        let key = [9u8; 32];
        let raw = std::fs::read_to_string(&path).unwrap();
        if let Some(envelope) = ConfigStore::detect_envelope(&raw) {
            LoadedConfig::Locked(LockedStore {
                path,
                key,
                envelope,
            })
        } else {
            let mut cfg: ConfigFile = serde_json::from_str(&raw).unwrap();
            ConfigStore::post_process(&mut cfg, &key);
            LoadedConfig::Ready(ConfigStore {
                path,
                cache: cfg,
                key,
                enc: None,
            })
        }
    }

    #[test]
    fn change_password_preserves_data_and_invalidates_old() {
        let dir = unique_dir("changepw");
        let mut store = temp_store_at(&dir);
        store.cache.sessions.push(Session {
            host: "1.2.3.4".into(),
            password: Secret::new("secret"),
            ..Session::new_empty()
        });
        store.enable_encryption("old-pw").unwrap();
        // Wrong current password is rejected; data untouched.
        assert!(store.change_password("WRONG", "new-pw").is_err());
        // Correct rotation succeeds.
        store.change_password("old-pw", "new-pw").unwrap();
        drop(store);

        let locked = match load_from(&dir) {
            LoadedConfig::Locked(l) => l,
            _ => panic!("expected Locked"),
        };
        // Old password no longer works; new one does and data survived.
        assert!(locked.unlock("old-pw").unwrap().is_none());
        let s = locked.unlock("new-pw").unwrap().unwrap();
        assert_eq!(s.sessions()[0].host, "1.2.3.4");
        assert_eq!(s.sessions()[0].password.as_str(), "secret");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disable_encryption_returns_to_plaintext_track() {
        let dir = unique_dir("disable");
        let mut store = temp_store_at(&dir);
        store.cache.sessions.push(Session {
            host: "5.6.7.8".into(),
            password: Secret::new("pw"),
            ..Session::new_empty()
        });
        store.enable_encryption("gate").unwrap();
        // Wrong password can't disable.
        assert!(store.disable_encryption("bad").is_err());
        store.disable_encryption("gate").unwrap();
        assert!(!store.is_encrypted());
        drop(store);

        // File is plaintext again: loads Ready, and the per-field password is
        // re-encrypted under secret.key (not readable in the clear).
        match load_from(&dir) {
            LoadedConfig::Ready(s) => {
                assert_eq!(s.sessions()[0].host, "5.6.7.8");
                assert_eq!(s.sessions()[0].password.as_str(), "pw");
            }
            _ => panic!("expected Ready after disable"),
        }
        let raw = std::fs::read_to_string(dir.join("sessions.json")).unwrap();
        assert!(!raw.contains("newshell_enc"));
        assert!(!raw.contains("\"pw\""), "plaintext password leaked");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn downgrade_and_tamper_are_rejected() {
        let dir = unique_dir("tamper");
        let mut store = temp_store_at(&dir);
        store.cache.sessions.push(Session {
            host: "9.9.9.9".into(),
            password: Secret::new("pw"),
            ..Session::new_empty()
        });
        store.enable_encryption("k").unwrap();
        drop(store);

        // Detection is structural: an attacker injecting `encrypted:false` into
        // the header does NOT make it parse as plaintext — it still has a
        // ciphertext, so it stays Locked.
        let raw = std::fs::read_to_string(dir.join("sessions.json")).unwrap();
        let tampered = raw.replacen("{", "{\"encrypted\":false,", 1);
        std::fs::write(dir.join("sessions.json"), &tampered).unwrap();
        assert!(matches!(load_from(&dir), LoadedConfig::Locked(_)));

        // Flipping a byte in the ciphertext body → AEAD auth fails on unlock
        // (corrupt, not wrong-password). Rebuild a clean envelope, then corrupt.
        let mut env = ConfigStore::detect_envelope(&raw).unwrap();
        let mut body = URL_SAFE_NO_PAD.decode(env.ciphertext.as_bytes()).unwrap();
        let last = body.len() - 1;
        body[last] ^= 0x01;
        env.ciphertext = URL_SAFE_NO_PAD.encode(&body);
        let locked = LockedStore {
            path: dir.join("sessions.json"),
            key: [9u8; 32],
            envelope: env,
        };
        assert!(locked.unlock("k").is_err(), "tampered body must not unlock");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypted_export_import_needs_password() {
        let dir = unique_dir("expenc");
        let mut store = temp_store_at(&dir);
        store.cache.sessions.push(Session {
            host: "172.16.0.1".into(),
            user: "admin".into(),
            password: Secret::new("topsecret"),
            ..Session::new_empty()
        });
        store.enable_encryption("export-gate").unwrap();

        let export_path = dir.join("out.nsx");
        assert_eq!(store.export_encrypted_to(&export_path).unwrap(), 1);
        let raw = std::fs::read_to_string(&export_path).unwrap();
        assert!(ConfigStore::is_encrypted_export(&raw));
        assert!(!raw.contains("172.16.0.1"));
        assert!(!raw.contains("topsecret"));

        // Import into a different encrypted store; wrong password → Ok(None).
        let dir2 = unique_dir("expenc2");
        let mut dest = temp_store_at(&dir2);
        dest.enable_encryption("dest-gate").unwrap();
        assert!(dest
            .import_encrypted_from(&export_path, "wrong")
            .unwrap()
            .is_none());
        // Correct source password imports the session.
        assert_eq!(
            dest.import_encrypted_from(&export_path, "export-gate")
                .unwrap(),
            Some(ImportReport {
                sessions_added: 1,
                sessions_skipped: 0,
                quick_added: 0,
                quick_skipped: 0,
            })
        );
        assert_eq!(dest.sessions()[0].host, "172.16.0.1");
        assert_eq!(dest.sessions()[0].password.as_str(), "topsecret");
        // Re-import skips the duplicate.
        assert_eq!(
            dest.import_encrypted_from(&export_path, "export-gate")
                .unwrap(),
            Some(ImportReport {
                sessions_added: 0,
                sessions_skipped: 1,
                quick_added: 0,
                quick_skipped: 0,
            })
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn plaintext_file_never_detected_as_envelope() {
        // A normal plaintext config (even one mentioning the word) must not be
        // misclassified — detection requires the marker AND a ciphertext.
        let plain = r#"{"sessions":[],"language":"zh"}"#;
        assert!(ConfigStore::detect_envelope(plain).is_none());
        assert!(!ConfigStore::is_encrypted_export(plain));
    }

    #[test]
    fn forged_marker_is_not_detected_as_encrypted() {
        // The user's threat model: someone copies an export, hand-edits the JSON,
        // and tries to pass it off as encrypted (or the reverse — bolts the
        // marker onto plaintext). Detection is content-based, so merely having
        // the marker with junk in the sealed fields must NOT be treated as
        // encrypted. It should fall through to the plaintext import path instead.

        // sessions.json envelope shape: marker present, but salt/enc_dek/
        // ciphertext are not valid sealed material.
        let fake_cfg = r#"{
            "newshell_enc": 1,
            "kdf": "argon2id",
            "kdf_params": {"m": 19456, "t": 2, "p": 1},
            "salt": "not-base64!!",
            "enc_dek": "AAAA",
            "ciphertext": "AAAA"
        }"#;
        assert!(
            ConfigStore::detect_envelope(fake_cfg).is_none(),
            "a forged config envelope with junk sealed fields must not be detected as encrypted"
        );

        // export shape: marker present, ciphertext far too short to be a sealed
        // blob (< nonce+tag), enc_dek the wrong length.
        let fake_export = r#"{
            "newshell_export_enc": 1,
            "kdf": "argon2id",
            "kdf_params": {"m": 19456, "t": 2, "p": 1},
            "salt": "AAAAAAAAAAA",
            "enc_dek": "AAAA",
            "ciphertext": "AA"
        }"#;
        assert!(
            !ConfigStore::is_encrypted_export(fake_export),
            "a forged export envelope with junk sealed fields must not be detected as encrypted"
        );

        // A plaintext export with the *encrypted* marker maliciously added but no
        // real sealed fields also stays plaintext.
        let plaintext_export_with_marker = r#"{
            "newshell_export": 1,
            "newshell_export_enc": 1,
            "sessions": []
        }"#;
        assert!(
            !ConfigStore::is_encrypted_export(plaintext_export_with_marker),
            "adding the marker to a plaintext export must not make it look encrypted"
        );
    }

    #[test]
    fn real_encrypted_files_still_detected_after_hardening() {
        // Regression guard: the stricter content check must not reject genuine
        // encrypted files produced by the app itself.
        let dir = unique_dir("harden");
        let mut store = temp_store_at(&dir);
        store.cache.sessions.push(Session {
            host: "10.0.0.9".into(),
            user: "root".into(),
            password: Secret::new("pw"),
            ..Session::new_empty()
        });
        store.enable_encryption("gate").unwrap();

        // sessions.json on disk is now a real envelope.
        let raw_cfg = std::fs::read_to_string(dir.join("sessions.json")).unwrap();
        assert!(
            ConfigStore::detect_envelope(&raw_cfg).is_some(),
            "a genuine encrypted sessions.json must still be detected"
        );

        // and a real encrypted export must still be detected.
        let export_path = dir.join("out.nsx");
        store.export_encrypted_to(&export_path).unwrap();
        let raw_exp = std::fs::read_to_string(&export_path).unwrap();
        assert!(
            ConfigStore::is_encrypted_export(&raw_exp),
            "a genuine encrypted export must still be detected"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
