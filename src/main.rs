// Entry point. Wires the Slint UI to the config store, system sampler and
// SSH session manager.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
// Opt-in startup diagnostics, off by default. See src/diag.rs.
mod diag;
mod dialog;
mod i18n;
mod layout;
mod resource;
mod session;
mod sftp;
mod ssh;
mod terminal;
mod ui;
mod update;
mod wallpaper;

fn main() -> anyhow::Result<()> {
    if std::env::args().any(|arg| arg == "--version" || arg == "-V") {
        println!("newshell {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // macOS default renderer is **Skia** (see ConfigStore::renderer_mode).
    //
    // Why Skia is the default: FemtoVG rasterizes glyphs with its own un-hinted
    // path renderer that does NOT go through CoreText and does not align glyphs to
    // the pixel grid, so small UI text (buttons, dialogs, menus) came out blurry
    // on Retina — everything except the large monospace terminal looked soft
    // (#font-blur). Skia delegates glyph rendering to CoreText, matching native
    // macOS apps, so UI text is crisp. Skia is compiled in on macOS (Cargo.toml)
    // and uses Metal, so switching renderers needs no rebuild.
    //
    // History / why this was risky: 0.4.10 force-set SLINT_BACKEND=winit-skia to
    // work around femtovg's CoreText font lookup failing on macOS 26 / Tahoe (all
    // text vanished, #108). That shipped unverified and *broke* a different set of
    // Macs (Apple Silicon M5 / 26.5): Skia couldn't resolve the hard-coded
    // "PingFang SC" UI font and text vanished there instead (#129). BOTH failures
    // were font-resolution failures, not renderer bugs. The fix that makes Skia
    // safe as the default is pairing it with a *concrete, nameable* Simplified-
    // Chinese UI font ("Heiti SC", then "PingFang SC"; resolve_ui_font_family in
    // app.rs) — real CoreText families that resolve identically on every Mac.
    // Crucially we do NOT default to the private ".AppleSystemUIFont" sentinel:
    // fontdb reports it as resolvable but CoreText often fails to draw it, which
    // is what blanked the UI on some machines while "working" on others.
    //
    // Escape hatches remain: users can pick FemtoVG under Settings -> Interface ->
    // Rendering (persisted as renderer_mode = "femtovg"), and SLINT_BACKEND=
    // winit-femtovg / winit-skia overrides the saved setting for one launch.

    // Install the panic hook before anything else can crash. Costs nothing while
    // the diagnostics switch is off (the default) — but once it is on, this is
    // what turns a silent `panic = "abort"` into a named source location.
    // Whether a log file is actually opened is decided in app::run(), once the
    // config (which holds the switch) has been read (#diag-switch).
    diag::install_panic_hook();

    init_tracing();

    // ── IME policy ───────────────────────────────────────────────────────────
    // NOTE: We deliberately DO **NOT** call `ImmDisableIME` here.
    //
    // An earlier version disabled the IME for the whole Slint event-loop thread
    // to work around a vim `:q!` glitch (Chinese IMEs intercept letter keys and,
    // on a Shift press, discard the in-flight pinyin).  But disabling the IME
    // also makes 中文输入 completely impossible — there is no composition window
    // at all, which is exactly the "无法输入任何中文" bug.
    //
    // Chinese input now flows through the hidden `ime-input` TextInput in
    // terminal_view.slint: composition happens there, and committed text is
    // forwarded to the PTY via the `edited` callback.  The vim/Shift side-effects
    // are handled instead by the C0-marker + 3-layer Backspace filters in
    // `app::on_send_key`, so we no longer need (and must not use) ImmDisableIME.

    // Record how app::run() ended. Without this an early error (unwritable config
    // dir, failed event loop) exits through stderr, which a
    // `windows_subsystem = "windows"` binary has no way to show (#diag-switch).
    diag::mark("main: entering app::run()");
    let result = app::run();
    match &result {
        Ok(()) => diag::mark("main: app::run() returned Ok — clean exit"),
        Err(err) => diag::mark(&format!("main: app::run() returned Err — {err:#}")),
    }
    result
}

/// Set up tracing: stderr only (honours RUST_LOG, default info). No on-disk log
/// file is written — diagnostics go to stderr so they can be captured via
/// `RUST_LOG` / console redirection if needed (#86).
///
/// A second layer mirrors events into `newshell-diag.log`, but ONLY while the
/// diagnostics switch is on (Settings → Interface → Diagnostics). With the switch
/// off — the default — its writer discards every byte without allocating, so the
/// "never writes a log file" behaviour is preserved (#diag-switch).
fn init_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{fmt, EnvFilter};

    // Third-party noise routed through `log` → tracing: ICU4X data-error warnings
    // (icu_provider dependency) and fontdb's "malformed font" warning for fonts it
    // can't parse but harmlessly skips (e.g. Windows' mstmc.ttf). Silence on every
    // layer; keep fontdb at `error` so genuine failures still surface.
    fn quiet_noise(mut f: EnvFilter) -> EnvFilter {
        for d in [
            "icu_provider=off",
            "icu_segmenter=off",
            "icu_normalizer=off",
            "fontdb=error",
        ] {
            if let Ok(dir) = d.parse() {
                f = f.add_directive(dir);
            }
        }
        f
    }

    let env_filter =
        quiet_noise(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")));
    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(env_filter);

    // Mirror every event into newshell-diag.log, with extra verbosity for the
    // window/GL stack — the layer most often implicated in startup failures.
    // These crates log through `log`, which tracing-subscriber's log bridge
    // forwards here, so e.g. glutin's GL-config failures become visible.
    // EnvFilter is not Clone, hence the second instance. The layer stays
    // registered permanently; `diag::MakeTracingWriter` throws the bytes away
    // while the switch is off (#diag-switch).
    fn verbose_window_stack(mut f: EnvFilter) -> EnvFilter {
        for d in [
            "glutin=debug",
            "winit=debug",
            "femtovg=debug",
            "i_slint_core=debug",
            "i_slint_backend_winit=debug",
            "i_slint_renderer_femtovg=debug",
            "i_slint_renderer_software=debug",
        ] {
            if let Ok(dir) = d.parse() {
                f = f.add_directive(dir);
            }
        }
        f
    }
    let diag_filter = verbose_window_stack(quiet_noise(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    ));
    let diag_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(diag::MakeTracingWriter)
        .with_filter(diag_filter);

    tracing_subscriber::registry()
        .with(stderr_layer)
        .with(diag_layer)
        .init();
}
