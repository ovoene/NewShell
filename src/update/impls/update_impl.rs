//! Application update check for the About dialog.
//!
//! Scope is deliberately tiny: when the user opens **Settings → About**, we ask
//! the public GitHub Releases API what the newest published version is and
//! compare it to the compiled-in `CARGO_PKG_VERSION`. We never download or
//! replace anything — if a newer version exists the dialog shows a button that
//! opens the Releases page in the user's browser (see `RELEASES_PAGE_URL`).
//!
//! Everything here is synchronous and must be called from a background thread:
//! [`check_latest`] does a blocking HTTPS request. `app.rs` runs it on a detached
//! `std::thread` and pushes the [`UpdateCheck`] result back onto the Slint event
//! loop with `slint::invoke_from_event_loop`.

use std::time::Duration;

/// Public Releases page opened by the "前往下载 / Go to download" button.
pub const RELEASES_PAGE_URL: &str = "https://github.com/ovoene/NewShell/releases";

/// GitHub REST endpoint for the newest **published, non-prerelease** release.
const LATEST_API_URL: &str = "https://api.github.com/repos/ovoene/NewShell/releases/latest";

/// Outcome of an update check, mapped 1:1 onto the three dialog states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheck {
    /// The compiled version is the newest (or newer than) the latest release.
    UpToDate,
    /// A newer release exists. `latest` is the plain version, e.g. `"8.8.11"`.
    Newer { latest: String },
    /// Network unreachable / request failed / response unparseable. The dialog
    /// shows "当前网络无法检查更新" and no button — we deliberately do NOT
    /// distinguish error kinds to the user.
    Failed,
}

/// The version this binary was built as (from `Cargo.toml` via Cargo).
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Blocking update check. **Call from a background thread only** — it performs a
/// synchronous HTTPS request with a short timeout so a slow/blocked GitHub
/// (common behind the GFW) can never hang the UI; any failure collapses to
/// [`UpdateCheck::Failed`] and is surfaced as a benign "cannot check" notice.
pub fn check_latest() -> UpdateCheck {
    match fetch_latest_tag() {
        Some(tag) => match compare(&tag, current_version()) {
            Some(true) => UpdateCheck::Newer {
                latest: normalize(&tag).to_string(),
            },
            Some(false) => UpdateCheck::UpToDate,
            // Couldn't parse the remote tag as a version → treat as "cannot
            // check" rather than nagging with a bogus update.
            None => UpdateCheck::Failed,
        },
        None => UpdateCheck::Failed,
    }
}

/// Query the GitHub API and pull `tag_name` out of the JSON, or `None` on any
/// network/HTTP/parse error.
fn fetch_latest_tag() -> Option<String> {
    // Short, explicit timeouts: a hung TCP connect or read must not keep the
    // background thread (and the user's mental model of "checking…") alive
    // forever. ~6s connect + ~6s read is plenty for a tiny JSON body.
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(6))
        .timeout_read(Duration::from_secs(6))
        .build();

    let resp = agent
        .get(LATEST_API_URL)
        // GitHub REJECTS requests without a User-Agent (HTTP 403), so this is
        // mandatory, not cosmetic.
        .set("User-Agent", "NewShell-UpdateCheck")
        .set("Accept", "application/vnd.github+json")
        .call()
        .ok()?;

    // Parse with our own serde_json rather than ureq's `json` feature, so ureq
    // stays at the default rustls+gzip feature set already pinned in Cargo.lock.
    let body = resp.into_string().ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let tag = json.get("tag_name")?.as_str()?.trim().to_string();
    if tag.is_empty() {
        None
    } else {
        Some(tag)
    }
}

/// Strip a leading `v`/`V` and any pre-release/build suffix, leaving the numeric
/// `MAJOR.MINOR.PATCH` core. `"v8.8.11"` → `"8.8.11"`, `"v9.0.0-rc1"` → `"9.0.0"`.
fn normalize(tag: &str) -> &str {
    let t = tag.trim();
    let t = t.strip_prefix('v').or_else(|| t.strip_prefix('V')).unwrap_or(t);
    // Drop a `-rc1` / `+build` suffix; we only compare the numeric core.
    let end = t.find(['-', '+']).unwrap_or(t.len());
    &t[..end]
}

/// Parse a normalized `MAJOR.MINOR.PATCH` string into a comparable tuple. Missing
/// components default to 0 (`"8.8"` → `(8, 8, 0)`); a non-numeric component fails
/// the whole parse so we never misread a garbage tag as a version.
fn parse(version: &str) -> Option<(u64, u64, u64)> {
    let core = normalize(version);
    let mut it = core.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next().map(|s| s.parse()).transpose().ok()?.unwrap_or(0);
    let patch = it.next().map(|s| s.parse()).transpose().ok()?.unwrap_or(0);
    Some((major, minor, patch))
}

/// `Some(true)` if `latest` is strictly newer than `current`, `Some(false)` if
/// same-or-older, `None` if either side can't be parsed. Compares numerically so
/// `8.8.10 > 8.8.9` (a plain string compare would get this backwards).
fn compare(latest: &str, current: &str) -> Option<bool> {
    Some(parse(latest)? > parse(current)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_tags() {
        assert_eq!(normalize("v8.8.11"), "8.8.11");
        assert_eq!(normalize("V8.8.11"), "8.8.11");
        assert_eq!(normalize("8.8.11"), "8.8.11");
        assert_eq!(normalize("v9.0.0-rc1"), "9.0.0");
        assert_eq!(normalize(" v9.0.0+build.5 "), "9.0.0");
    }

    #[test]
    fn numeric_not_lexical() {
        // The whole point: 8.8.10 must be seen as newer than 8.8.9.
        assert_eq!(compare("v8.8.10", "8.8.9"), Some(true));
        assert_eq!(compare("8.8.9", "8.8.10"), Some(false));
    }

    #[test]
    fn same_and_older() {
        assert_eq!(compare("v8.8.10", "8.8.10"), Some(false));
        assert_eq!(compare("v8.7.99", "8.8.10"), Some(false));
        assert_eq!(compare("v9.0.0", "8.8.10"), Some(true));
        assert_eq!(compare("v8.9.0", "8.8.10"), Some(true));
    }

    #[test]
    fn missing_components_default_zero() {
        assert_eq!(parse("8.8"), Some((8, 8, 0)));
        assert_eq!(parse("8"), Some((8, 0, 0)));
    }

    #[test]
    fn garbage_fails() {
        assert_eq!(parse("latest"), None);
        assert_eq!(compare("nightly", "8.8.10"), None);
    }
}
