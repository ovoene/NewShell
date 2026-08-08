//! Minimal ZMODEM **receiver** — the `rz` side of an `sz` transfer (#76).
//!
//! When the user runs `sz <file>` in the terminal, the remote starts a ZMODEM
//! send. We implement just enough of the protocol to receive: reply to ZRQINIT
//! with ZRINIT, accept ZFILE, drive the transfer with ZRPOS/ZACK, collect the
//! ZDATA subpackets into a local file, and finish on ZEOF/ZFIN. Files land in
//! the user's Downloads directory (FinalShell style).
//!
//! We advertise CANFC32, so the sender uses CRC-32 binary frames; the CRC-16
//! paths are implemented for completeness but rarely exercised.
//!
//! This is intentionally a *receive-only* implementation; `rz` (upload) is not
//! handled here. Every header is logged at debug level to aid diagnosis, since
//! the binary protocol can't easily be tested without a live server.

use crate::i18n::t;
use crate::ssh::SessionEvent;
use anyhow::{bail, Context, Result};
use russh::client::Msg;
use russh::{Channel, ChannelMsg};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;

// --- Frame types -----------------------------------------------------------
const ZRQINIT: u8 = 0;
const ZRINIT: u8 = 1;
const ZACK: u8 = 3;
const ZFILE: u8 = 4;
const ZNAK: u8 = 6;
const ZABORT: u8 = 7;
const ZFIN: u8 = 8;
const ZRPOS: u8 = 9;
const ZDATA: u8 = 10;
const ZEOF: u8 = 11;
const ZCAN: u8 = 16;

// --- Control bytes ---------------------------------------------------------
const ZDLE: u8 = 0x18; // ZMODEM escape (also CAN)
const ZPAD: u8 = b'*';
const ZBIN: u8 = b'A'; // binary header, CRC-16
const ZHEX: u8 = b'B'; // hex header, CRC-16
const ZBIN32: u8 = b'C'; // binary header, CRC-32

// Data-subpacket terminators (the byte right after a ZDLE inside data).
const ZCRCE: u8 = b'h'; // end of frame, header follows, no ZACK
const ZCRCG: u8 = b'i'; // frame continues, no ZACK
const ZCRCQ: u8 = b'j'; // frame continues, ZACK expected
const ZCRCW: u8 = b'k'; // end of frame, ZACK expected
const ZRUB0: u8 = b'l'; // escaped 0x7f
const ZRUB1: u8 = b'm'; // escaped 0xff

// ZRINIT capability flags we advertise: full-duplex, overlap I/O, CRC-32.
const CANFDX: u8 = 0x01;
const CANOVIO: u8 = 0x02;
const CANFC32: u8 = 0x20;

/// Receive one or more files via ZMODEM. `first` is the channel chunk that
/// triggered detection (it contains the leading ZRQINIT).
///
/// Returns any bytes read past the end of the ZMODEM session (typically the
/// shell prompt the sender's exit produces) so the caller can feed them back to
/// the terminal — otherwise the prompt would be swallowed. On a protocol failure
/// it returns an error and the caller cancels.
pub async fn receive(
    channel: &mut Channel<Msg>,
    first: &[u8],
    events: &UnboundedSender<SessionEvent>,
) -> Result<Vec<u8>> {
    let dest = download_dir();
    tokio::fs::create_dir_all(&dest)
        .await
        .with_context(|| format!("create download dir {}", dest.display()))?;

    tracing::debug!(
        "zmodem: receive start, first[{}]={:02x?}",
        first.len(),
        &first[..first.len().min(80)]
    );

    let mut rx = Rx::new(channel, first);
    let mut received = 0u32;
    let mut cur: Option<CurFile> = None;
    // A header already read ahead (e.g. the next ZFILE peeked after a ZEOF).
    let mut pending: Option<(u8, [u8; 4])> = None;

    loop {
        let (ftype, hdr) = match pending.take() {
            Some(h) => h,
            None => rx.read_header().await?,
        };
        tracing::debug!("zmodem rx header type={ftype} data={hdr:02x?}");
        match ftype {
            ZRQINIT => {
                rx.send_hex(ZRINIT, [0, 0, 0, CANFDX | CANOVIO | CANFC32])
                    .await?
            }
            ZFILE => {
                // Data subpacket: "name\0size mtime mode ...".
                let (sub, _end) = rx.read_subpacket(true).await?;
                let nul = sub.iter().position(|&b| b == 0).unwrap_or(sub.len());
                let name = sanitize(&String::from_utf8_lossy(&sub[..nul]));
                let size = sub
                    .get(nul + 1..)
                    .map(|rest| String::from_utf8_lossy(rest))
                    .and_then(|s| s.split_whitespace().next().map(str::to_owned))
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let path = dest.join(&name);
                let file = tokio::fs::File::create(&path)
                    .await
                    .with_context(|| format!("create {}", path.display()))?;
                let id = format!("zmodem-{}", uuid::Uuid::new_v4());
                emit(events, &id, &name, 0, size, 0, "");
                cur = Some(CurFile {
                    file,
                    name,
                    id,
                    size,
                    written: 0,
                });
                rx.send_hex(ZRPOS, 0u32.to_le_bytes()).await?;
            }
            ZDATA => loop {
                let (chunk, end) = rx.read_subpacket(true).await?;
                if let Some(c) = cur.as_mut() {
                    c.file.write_all(&chunk).await.context("write file")?;
                    c.written += chunk.len() as u64;
                    emit(
                        events,
                        &c.id,
                        &c.name,
                        c.written,
                        c.size.max(c.written),
                        0,
                        "",
                    );
                }
                match end {
                    ZCRCG => continue,
                    ZCRCQ => {
                        let pos = cur.as_ref().map(|c| c.written).unwrap_or(0) as u32;
                        rx.send_hex(ZACK, pos.to_le_bytes()).await?;
                    }
                    ZCRCE => break,
                    ZCRCW => {
                        let pos = cur.as_ref().map(|c| c.written).unwrap_or(0) as u32;
                        rx.send_hex(ZACK, pos.to_le_bytes()).await?;
                        break;
                    }
                    _ => break,
                }
            },
            ZEOF => {
                if let Some(mut c) = cur.take() {
                    c.file.flush().await.context("flush file")?;
                    emit(
                        events,
                        &c.id,
                        &c.name,
                        c.written,
                        c.size.max(c.written),
                        1,
                        "",
                    );
                    received += 1;
                }
                // ZEOF ends one *file*, not the whole session (#109). Tell the
                // sender we're ready for more (ZRINIT) and peek the next frame:
                // a multi-file `sz` sends the next ZFILE; otherwise it sends ZFIN
                // (or just waits for our ZFIN and sends nothing). The peek is
                // capped by a short timeout so a finished single-file transfer
                // never blocks on the long per-byte read timeout — anything that
                // isn't a ZFILE drops to the close handshake below.
                rx.send_hex(ZRINIT, [0, 0, 0, CANFDX | CANOVIO | CANFC32])
                    .await?;
                match tokio::time::timeout(Duration::from_secs(2), rx.read_header()).await {
                    Ok(Ok(h)) if h.0 == ZFILE => pending = Some(h),
                    _ => break, // ZFIN / unexpected / parse error / timeout → done
                }
            }
            ZFIN => break, // sender signals the whole session is done
            ZCAN | ZABORT => bail!("{}", t("传输被远端取消", "transfer aborted by sender")),
            ZNAK => { /* sender NAK; just keep going */ }
            _ => tracing::debug!("zmodem: ignoring unhandled frame type {ftype}"),
        }
    }

    // Close handshake. The sender (lrzsz `sz`) just sent ZEOF and is finishing
    // its session: it expects a ZRINIT, then sends ZFIN and waits for OUR ZFIN
    // before emitting "OO" (over-and-out) and exiting. We reply so it exits
    // promptly, and consume its ZFIN + OO here so they don't leak to the terminal
    // or get re-detected as a new transfer. Whatever follows (the shell prompt)
    // stays in the buffer and is returned to the caller (#76).
    if received > 0 {
        // Send ZRINIT + ZFIN *immediately and unconditionally*. This sender
        // finishes its session waiting for OUR ZFIN and does not send its own
        // first; if we wait to read its ZFIN it never comes and the sender hangs
        // ~100 s on its global timeout. Sending ZFIN proactively makes it exit at
        // once. Then swallow its lingering close frames (its ZFIN / "OO"),
        // stopping at the first byte that isn't part of a ZMODEM hex header or
        // "OO" — that byte begins the shell prompt, returned as leftover (#76).
        let _ = rx
            .send_hex(ZRINIT, [0, 0, 0, CANFDX | CANOVIO | CANFC32])
            .await;
        let _ = rx.send_hex(ZFIN, [0, 0, 0, 0]).await;
        let _ = tokio::time::timeout(Duration::from_millis(800), async {
            for _ in 0..64 {
                match rx.byte().await {
                    Ok(b) if is_close_byte(b) => continue,
                    Ok(b) => {
                        rx.buf.push_front(b); // start of the shell prompt
                        break;
                    }
                    Err(_) => break,
                }
            }
        })
        .await;
    }

    let _ = events.send(SessionEvent::Output(
        format!(
            "\r\n[NewShell 新の世界] {} {} → {}\r\n",
            received,
            t("个文件已通过 sz 下载到", "file(s) downloaded via sz to"),
            dest.display()
        )
        .into(),
    ));
    // Hand back any trailing bytes (the shell prompt) so the caller can display
    // them instead of the receiver swallowing them.
    Ok(rx.buf.drain(..).collect())
}

/// The ZMODEM abort sequence: eight CAN (0x18) then eight BS (0x08). Mirrors
/// `ZMODEM_CANCEL` in ssh_impl.rs so the remote `rz` gives up on error (#76).
const ZMODEM_CANCEL_SEQ: [u8; 16] = [
    0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
];

/// Send one or more local files via ZMODEM in response to a remote `rz`.
///
/// `first` is the channel chunk that triggered detection — it contains the
/// leading `ZRINIT` the remote sent to announce it is ready to *receive*. We
/// read that ZRINIT, then stream each file as `ZFILE` + `ZDATA` subpackets +
/// `ZEOF`, finishing with `ZFIN`. This is the sender (upload) half that
/// `receive()` deliberately omitted, and is what makes a remote `rz` — e.g. a
/// black-Synology helper script's "upload file" menu — pop a local picker in
/// FinalShell-style clients.
///
/// On any protocol error we send the cancel sequence so the remote `rz` does not
/// hang, then return the error for the caller to surface.
pub async fn send(
    channel: &mut Channel<Msg>,
    first: &[u8],
    files: Vec<PathBuf>,
    events: &UnboundedSender<SessionEvent>,
) -> Result<()> {
    if files.is_empty() {
        let _ = channel.data(&ZMODEM_CANCEL_SEQ[..]).await;
        return Ok(());
    }

    let mut rx = Rx::new(channel, first);
    // The remote `rz` already told us it's ready to receive via ZRINIT.
    let (ftype, hdr) = rx.read_header().await?;
    if ftype != ZRINIT {
        rx.cancel().await;
        bail!(
            "{} (frame type {})",
            t("远端未请求上传(ZRINIT)", "remote did not request upload (ZRINIT)"),
            ftype
        );
    }
    // Honour the receiver's advertised CRC capability. A `rz` that sets CANFC32
    // (0x20, the 4th ZRINIT info byte) wants CRC-32 binary frames — exactly what
    // `receive()` advertises to a remote `sz` and what a black-Synology helper
    // `rz` expects. If we answer a CRC-32-capable `rz` with CRC-16 frames it NAKs
    // every subpacket, the transfer never starts, and the progress stalls at 0
    // (#76). Fall back to CRC-16 hex frames only when CRC-32 is not offered.
    let use_crc32 = hdr[3] & CANFC32 != 0;
    // Stream the remote `rz`'s echo/progress to the terminal so the upload
    // doesn't look frozen (#ZMODEM-echo), and arm the echo-back stripper so a
    // remote tty left in echo mode (black-Synology helper scripts) can't flood
    // the terminal with our own binary or drown the real ACKs (#synology-echo).
    rx.echo = Some(events.clone());
    rx.strip = Some(EchoStrip::new());

    for path in &files {
        if let Err(e) = send_one(&mut rx, path, events, use_crc32).await {
            rx.cancel().await;
            return Err(e);
        }
    }

    // Session close: send ZFIN as a hex header regardless of the CRC mode
    // negotiated for data frames. The spec and all lrzsz/busybox `rz`
    // implementations expect the session-close ZFIN in the hex format; sending
    // a binary ZFIN causes some receivers to hang waiting for the hex version.
    rx.send_hex(ZFIN, [0, 0, 0, 0]).await?;
    // Flush any buffered remote echo, then forward whatever the server sends
    // next (rz's "done" banner + the shell prompt) to the terminal so it stays
    // in sync after the transfer. Previously these bytes were pushed back into
    // `rx.buf` and lost when `rx` dropped, leaving the prompt missing (#ZMODEM-echo).
    rx.echo_flush();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let mut rest = Vec::new();
        for _ in 0..256 {
            match rx.byte().await {
                Ok(b) if is_close_byte(b) => continue,
                Ok(b) => rest.push(b),
                Err(_) => break,
            }
        }
        if !rest.is_empty() {
            let _ = events.send(SessionEvent::Output(String::from_utf8_lossy(&rest).into_owned()));
        }
    })
    .await;

    let _ = events.send(SessionEvent::Output(
        format!(
            "\r\n[NewShell 新の世界] {} {}\r\n",
            files.len(),
            t("个文件已通过 sz 上传到远端", "file(s) uploaded to the remote via sz")
        )
        .into(),
    ));
    Ok(())
}

/// Send a single file: ZFILE header + info subpacket, then ZDATA subpackets,
/// then ZEOF. Each subpacket awaits a ZACK from the receiver before continuing.
async fn send_one(
    rx: &mut Rx<'_>,
    path: &PathBuf,
    events: &UnboundedSender<SessionEvent>,
    use_crc32: bool,
) -> Result<()> {
    let raw_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let name = sanitize(&raw_name);

    let meta = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("stat {}", path.display()))?;
    if meta.is_dir() {
        bail!(
            "{} {}",
            name,
            t("是目录,ZMODEM 不支持文件夹上传", "is a directory; ZMODEM folder upload unsupported")
        );
    }
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mode_oct = format!("{:o}", 0o100644u32); // regular file, rw-r--r--
    let id = format!("zmodem-{}", uuid::Uuid::new_v4());
    emit(events, &id, &name, 0, size, 0, "");

    // Run the actual transfer. On any error, mark the UI record as failed
    // (state=2) before returning so the progress panel shows "failed" rather
    // than staying frozen at "0 B / total" indefinitely.
    let result = send_one_inner(rx, path, events, use_crc32, &id, &name, size, mtime, &mode_oct).await;
    if let Err(ref e) = result {
        emit(events, &id, &name, 0, size, 2, &e.to_string());
    }
    result
}

/// Inner transfer logic extracted so `send_one` can catch errors and emit
/// the failure UI event centrally without duplicating error paths.
async fn send_one_inner(
    rx: &mut Rx<'_>,
    path: &PathBuf,
    events: &UnboundedSender<SessionEvent>,
    use_crc32: bool,
    id: &str,
    name: &str,
    size: u64,
    mtime: u32,
    mode_oct: &str,
) -> Result<()> {
    // ZFILE, then the file-info subpacket: "name\0 size mtime mode 0 0".
    // Frame type (binary CRC-32 vs hex CRC-16) follows the receiver's capability.
    if use_crc32 {
        rx.send_bin(true, ZFILE, [0, 0, 0, 0]).await?;
    } else {
        rx.send_hex(ZFILE, [0, 0, 0, 0]).await?;
    }
    let info = format!("{}\0{} {} {} 0 0", name, size, mtime, mode_oct);
    send_data_subpacket(rx, info.as_bytes(), ZCRCW, use_crc32).await?;
    // The receiver answers the ZFILE with a ZRPOS naming the offset to start
    // from (normally 0); some send a bare ZACK. Seed our position from it.
    let mut offset: u32 = match guarded_ack(rx, 0, true).await? {
        Ack::Resend(pos) => pos,
        Ack::Ok => 0,
    };

    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    if offset != 0 {
        file.seek(std::io::SeekFrom::Start(offset as u64)).await?;
    }

    // Stream the body as ZDATA frames. The ZDATA header and every ZCRCG
    // subpacket are coalesced into ONE SSH write (buffered in `pending`), then
    // the group is closed with a ZCRCW and we read the receiver's reply — a
    // bounded window that hides latency without stop-and-wait per packet.
    // Fewer SSH packets also means fewer encrypt/decrypt rounds, which matters
    // on a weak black-Synology CPU. On a garbled/lost block `rz` replies ZRPOS
    // with the offset it still wants; we seek back and resend from there.
    const SUB: usize = 8192;
    const WINDOW_SUBS: usize = 16; // ~128 KiB between ACK checkpoints
    const PROGRESS_TIMEOUT: Duration = Duration::from_secs(20);
    let mut buf = vec![0u8; SUB];
    let mut confirmed: u32 = offset; // last offset the receiver acknowledged
    let mut stalls: u32 = 0; // consecutive resend requests (loop guard)
    let mut at_eof = false;
    let mut pending: Vec<u8> = Vec::with_capacity(SUB * (WINDOW_SUBS + 2));

    loop {
        if !at_eof {
            // Open a data frame at the current offset (coalesced into `pending`).
            build_bin_hdr(&mut pending, use_crc32, ZDATA, offset.to_le_bytes());
            let mut subs = 0usize;
            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    at_eof = true;
                    break;
                }
                subs += 1;
                let last = offset as u64 + n as u64 >= size;
                let checkpoint = subs >= WINDOW_SUBS;
                // Final subpacket closes the frame with ZCRCE (ZEOF follows, no
                // ACK); a window boundary uses ZCRCW (ACK expected); otherwise
                // ZCRCG keeps the frame streaming.
                let term = if last {
                    ZCRCE
                } else if checkpoint {
                    ZCRCW
                } else {
                    ZCRCG
                };
                build_data_subpacket(&mut pending, &buf[..n], term, use_crc32);
                offset += n as u32;
                emit(events, id, name, offset as u64, size, 0, "");
                if last {
                    at_eof = true;
                    break;
                }
                if checkpoint {
                    break;
                }
            }
            // One SSH write for the whole frame (header + subpackets).
            flush_pending(rx, &mut pending, PROGRESS_TIMEOUT).await?;
            if !at_eof {
                // Window checkpoint: honour the receiver's reply before continuing.
                match guarded_ack(rx, confirmed, false).await? {
                    Ack::Ok => {
                        confirmed = offset;
                        stalls = 0;
                    }
                    Ack::Resend(pos) => {
                        stalls += 1;
                        if stalls > 64 {
                            bail!("{}", t(
                                "ZMODEM 反复重传失败(链路不稳定)",
                                "ZMODEM kept retransmitting (unstable link)",
                            ));
                        }
                        file.seek(std::io::SeekFrom::Start(pos as u64)).await?;
                        offset = pos;
                        emit(events, id, name, offset as u64, size, 0, "");
                    }
                }
                continue;
            }
            // Reached EOF: fall through to send ZEOF. Any trailing ZCRCG blocks
            // are synchronised by the ZEOF handshake below.
        }

        // ZEOF at the final offset. Normally the receiver replies ZRINIT/ZACK; a
        // ZRPOS means it wants a late resend, so seek back and keep streaming.
        build_bin_hdr(&mut pending, use_crc32, ZEOF, offset.to_le_bytes());
        flush_pending(rx, &mut pending, PROGRESS_TIMEOUT).await?;
        match guarded_ack(rx, confirmed, false).await? {
            Ack::Ok => break,
            Ack::Resend(pos) => {
                stalls += 1;
                if stalls > 64 {
                    bail!("{}", t(
                        "ZMODEM 反复重传失败(链路不稳定)",
                        "ZMODEM kept retransmitting (unstable link)",
                    ));
                }
                file.seek(std::io::SeekFrom::Start(pos as u64)).await?;
                offset = pos;
                at_eof = false;
                emit(events, id, name, offset as u64, size, 0, "");
            }
        }
    }
    emit(events, id, name, size, size, 1, "");
    Ok(())
}

/// Send a ZMODEM data subpacket: ZDLE-escaped `data` + `terminator`, followed by
/// the CRC (ZDLE-escaped). Uses CRC-32 when `crc32` (matching `receive()`'s
/// `read_subpacket(true)` verification) and CRC-16 otherwise — the two must stay
/// in lockstep with what the receiver verifies, or every subpacket is NAK'd (#76).
async fn send_data_subpacket(
    rx: &mut Rx<'_>,
    data: &[u8],
    terminator: u8,
    crc32: bool,
) -> Result<()> {
    let mut crcbuf = data.to_vec();
    crcbuf.push(terminator);
    let crc = if crc32 {
        crc32_of(&crcbuf)
    } else {
        crc16(&crcbuf) as u32
    };

    let mut out: Vec<u8> = Vec::with_capacity(data.len() + 12);
    for &b in data {
        if needs_escape(b) {
            out.push(ZDLE);
            out.push(b ^ 0x40);
        } else {
            out.push(b);
        }
    }
    out.push(ZDLE);
    out.push(terminator);
    // CRC bytes to emit: 4 (CRC-32, little-endian) or 2 (CRC-16, big-endian).
    let crc_raw: Vec<u8> = if crc32 {
        crc.to_le_bytes().to_vec()
    } else {
        let c = crc as u16;
        vec![(c >> 8) as u8, (c & 0xff) as u8]
    };
    for &b in &crc_raw {
        if needs_escape(b) {
            out.push(ZDLE);
            out.push(b ^ 0x40);
        } else {
            out.push(b);
        }
    }
    rx.record_sent(&out);
    rx.ch
        .data(out.as_slice())
        .await
        .context("zmodem send data subpacket")?;
    Ok(())
}

/// The receiver's reply to a ZCRCW checkpoint or a ZEOF.
enum Ack {
    /// ZACK / ZRINIT — the window (or the whole file) was accepted; go forward.
    Ok,
    /// ZRPOS / ZNAK — the receiver wants the stream rewound to this offset and
    /// resent from there. This is the case the old code dropped on the floor.
    Resend(u32),
}

/// Read the receiver's reply after a ZCRCW window checkpoint or a ZEOF.
///
/// `ZRPOS` carries the byte offset the receiver still wants; a bare `ZNAK` does
/// not, so we rewind to `fallback` (the last confirmed offset). Unknown frames
/// are skipped; an explicit abort bails. A stalled link is bounded by the 30 s
/// read timeout in `Rx::byte`.
async fn read_ack(rx: &mut Rx<'_>, fallback: u32) -> Result<Ack> {
    loop {
        let (ftype, hdr) = rx.read_header().await?;
        tracing::debug!("zmodem(send) reply type={ftype} data={hdr:02x?}");
        match ftype {
            ZACK | ZRINIT => return Ok(Ack::Ok),
            ZRPOS => return Ok(Ack::Resend(u32::from_le_bytes(hdr))),
            ZNAK => return Ok(Ack::Resend(fallback)),
            ZCAN | ZABORT => {
                bail!("{}", t("传输被远端取消", "transfer aborted by receiver"))
            }
            _ => continue,
        }
    }
}

/// Read the receiver's reply (ZACK/ZRINIT/ZRPOS/ZNAK/abort), bounded by a
/// "no progress for 20 s" watchdog instead of the raw 30 s channel-silent
/// timeout. A remote `rz` keeps echoing progress while it is alive-but-stuck,
/// so the channel is never *silent* and the old 30 s timeout never fired — the
/// transfer hung at 0 forever. This wrapper fails fast so the caller can cancel
/// and surface a clear error (#ZMODEM-stall).
async fn guarded_ack(rx: &mut Rx<'_>, fallback: u32, first_reply: bool) -> Result<Ack> {
    match tokio::time::timeout(Duration::from_secs(20), read_ack(rx, fallback)).await {
        Ok(ack) => ack,
        // Stalled waiting for the very first reply: the receiver never
        // answered our ZFILE at all. On black-Synology boxes this usually
        // means a helper-script `rz` that left the tty in echo mode or only
        // implements a fragment of the protocol — say so, so the user has a
        // concrete next step instead of a bare timeout.
        Err(_) if first_reply => bail!(
            "{}",
            t(
                "ZMODEM 上传卡死(远端无响应),已取消。远端 rz 可能未关闭终端回显或协议实现不完整(群晖替代脚本常见),建议安装 lrzsz (ipkg install lrzsz) 或改用文件面板 SFTP 上传",
                "ZMODEM upload stalled (no response from the receiver); cancelled. The remote rz may have tty echo enabled or an incomplete protocol implementation (common with Synology helper scripts) — install lrzsz (ipkg install lrzsz) or use the SFTP file panel instead"
            )
        ),
        Err(_) => bail!(
            "{}",
            t(
                "ZMODEM 上传卡死(长时间无进度),已取消",
                "ZMODEM upload stalled (no progress for a while); cancelled"
            )
        ),
    }
}

/// Append a binary ZMODEM header (ZBIN/ZBIN32) to `out` — the coalesced-write
/// twin of `send_bin` that does not flush to the channel on its own.
fn build_bin_hdr(out: &mut Vec<u8>, crc32: bool, ftype: u8, data: [u8; 4]) {
    let payload = [ftype, data[0], data[1], data[2], data[3]];
    out.push(ZPAD);
    out.push(ZPAD);
    out.push(ZDLE);
    out.push(if crc32 { ZBIN32 } else { ZBIN });
    for &b in &payload {
        if needs_escape(b) {
            out.push(ZDLE);
            out.push(b ^ 0x40);
        } else {
            out.push(b);
        }
    }
    let crc_raw: Vec<u8> = if crc32 {
        crc32_of(&payload).to_le_bytes().to_vec()
    } else {
        let c = crc16(&payload);
        vec![(c >> 8) as u8, (c & 0xff) as u8]
    };
    for &b in &crc_raw {
        if needs_escape(b) {
            out.push(ZDLE);
            out.push(b ^ 0x40);
        } else {
            out.push(b);
        }
    }
}

/// Append a ZDLE-escaped data subpacket to `out` — the coalesced-write twin of
/// `send_data_subpacket`.
fn build_data_subpacket(out: &mut Vec<u8>, data: &[u8], terminator: u8, crc32: bool) {
    let mut crcbuf = data.to_vec();
    crcbuf.push(terminator);
    let crc = if crc32 {
        crc32_of(&crcbuf)
    } else {
        crc16(&crcbuf) as u32
    };
    for &b in data {
        if needs_escape(b) {
            out.push(ZDLE);
            out.push(b ^ 0x40);
        } else {
            out.push(b);
        }
    }
    out.push(ZDLE);
    out.push(terminator);
    let crc_raw: Vec<u8> = if crc32 {
        crc.to_le_bytes().to_vec()
    } else {
        let c = crc as u16;
        vec![(c >> 8) as u8, (c & 0xff) as u8]
    };
    for &b in &crc_raw {
        if needs_escape(b) {
            out.push(ZDLE);
            out.push(b ^ 0x40);
        } else {
            out.push(b);
        }
    }
}

/// Flush a coalesced frame to the channel. The frame is written in small slices
/// with a short, non-blocking drain of the inbound channel *between* slices.
///
/// This is the fix for the ZMODEM-over-SSH deadlock. While we stream data to the
/// remote `rz`, `rz` simultaneously writes its progress echo back through the
/// same SSH channel. If we only send and never read, `rz`'s echo fills the SSH
/// receive window, `rz` blocks on its own echo write, stops reading our data,
/// our send window stays full, and `ch.data()` hangs until the timeout — the
/// exact "ZMODEM 上传发送超时,已取消" the user hit. Draining between slices keeps
/// both directions flowing so neither side stalls (#ZMODEM-deadlock).
async fn flush_pending(rx: &mut Rx<'_>, pending: &mut Vec<u8>, timeout: Duration) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let data = std::mem::take(pending);
    // A single oversized `ch.data()` is what blocked for 20 s before: the remote
    // receive window ran out and never recovered because nothing was reading the
    // echo. Sending in modest slices that fit comfortably inside any sane SSH
    // window, then draining echo between them, avoids that.
    const CHUNK: usize = 32 * 1024;
    let overall_deadline = tokio::time::Instant::now() + timeout;
    let mut sent = 0usize;
    rx.record_sent(&data);
    while sent < data.len() {
        let end = (sent + CHUNK).min(data.len());
        // Per-slice budget shrinks as the overall timeout approaches.
        let per = overall_deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or_default()
            .max(Duration::from_millis(50));
        match tokio::time::timeout(per, rx.ch.data(&data[sent..end])).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e).context("zmodem send frame"),
            Err(_) => bail!(
                "{}",
                t(
                    "ZMODEM 上传发送超时,已取消",
                    "ZMODEM upload send timed out; cancelled"
                )
            ),
        }
        sent = end;
        // Drain echo between slices (but not after the final slice — the
        // remaining reply frame is read by `guarded_ack`). If the channel went
        // away mid-transfer, fail fast instead of hanging on the next write.
        if sent < data.len() {
            rx.drain_echo(Duration::from_millis(15)).await;
            if rx.closed {
                bail!(
                    "{}",
                    t("ZMODEM 上传时连接已断开", "connection closed during ZMODEM upload")
                );
            }
        }
    }
    Ok(())
}

/// Bytes that must be ZDLE-escaped in a ZMODEM data subpacket. The link (SSH) is
/// 8-bit clean, but escaping ZDLE plus control chars matches what `rz`
/// implementations expect and what `Rx::zbyte` un-escapes.
fn needs_escape(b: u8) -> bool {
    b == ZDLE || b < 0x20 || b == 0x7f
}


struct CurFile {
    file: tokio::fs::File,
    name: String,
    id: String,
    size: u64,
    written: u64,
}

/// Detects and strips a remote tty's echo-back of our own outbound stream.
///
/// A healthy `rz` puts the PTY into raw no-echo mode, but the helper scripts
/// common on black-Synology boxes (and some busybox setups) leave echo on:
/// every byte we send bounces back through the same channel. Left alone, that
/// echoed binary floods the terminal through the progress-echo path and drowns
/// the receiver's real ACKs in the frame scanner — the upload stalls at 0 and
/// the screen fills with garbage (#synology-echo). We keep a bounded rolling
/// window of recently-sent bytes; inbound bytes that continue an exact match
/// of that stream are echo and are dropped. Anything that doesn't match is a
/// real receiver byte and passes through untouched.
struct EchoStrip {
    /// Rolling window of recently-sent bytes, oldest at the front.
    sent: VecDeque<u8>,
    /// Tentatively matched bytes not yet confirmed as echo — released as real
    /// data if the run breaks before the threshold (a coincidental prefix).
    pending: Vec<u8>,
    /// Once true, matching bytes are dropped immediately (confirmed echo).
    echoing: bool,
}

impl EchoStrip {
    /// Consecutive matching bytes before we call it echo: long enough that a
    /// receiver's real output can never collide with our sent stream.
    const THRESHOLD: usize = 32;
    /// Bound on the rolling sent window. Echo lag is bounded by SSH flow
    /// control; 1 MiB is generous even for a slow, weak-CPU receiver.
    const WINDOW: usize = 1024 * 1024;

    fn new() -> Self {
        EchoStrip {
            sent: VecDeque::new(),
            pending: Vec::new(),
            echoing: false,
        }
    }

    /// Record bytes we are about to send so their echo can be recognised.
    fn record(&mut self, bytes: &[u8]) {
        self.sent.extend(bytes.iter().copied());
        while self.sent.len() > Self::WINDOW {
            self.sent.pop_front();
        }
    }

    /// Classify one inbound byte: confirmed echo is swallowed; anything else
    /// is pushed to `out` (possibly after releasing a tentative run that
    /// turned out to be real receiver data).
    fn feed(&mut self, b: u8, out: &mut Vec<u8>) {
        if self.echoing {
            if self.sent.front() == Some(&b) {
                self.sent.pop_front();
                return; // echo of our own stream — drop it
            }
            // The echo burst is over; this is a real receiver byte.
            self.echoing = false;
            out.push(b);
            return;
        }
        if self.sent.front() == Some(&b) {
            self.sent.pop_front();
            self.pending.push(b);
            if self.pending.len() >= Self::THRESHOLD {
                self.echoing = true;
                self.pending.clear();
            }
            return; // hold until the run confirms (echo) or breaks (real data)
        }
        if !self.pending.is_empty() {
            // Coincidental prefix match: those were real receiver bytes.
            out.append(&mut self.pending);
        }
        out.push(b);
    }
}

/// Reduce remote progress echo to terminal-safe text: printable ASCII,
/// `\t`/`\r`/`\n`, ESC (ANSI sequences), and complete valid UTF-8 multibyte
/// characters. Everything else — C0/C1 control bytes, stray UTF-8
/// continuation bytes, truncated sequences — is dropped, so a noisy or
/// echoing sender can't flood the terminal with binary garbage
/// (#synology-echo).
fn sanitize_echo(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        let b = buf[i];
        match b {
            b'\t' | b'\r' | b'\n' | 0x1b | 0x20..=0x7e => {
                out.push(b);
                i += 1;
            }
            0xc2..=0xf4 => {
                let n = match b {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    _ => 4,
                };
                if i + n <= buf.len() && std::str::from_utf8(&buf[i..i + n]).is_ok() {
                    out.extend_from_slice(&buf[i..i + n]);
                    i += n;
                } else {
                    i += 1; // invalid / truncated sequence — drop the lead byte
                }
            }
            _ => i += 1, // other control bytes and stray continuations
        }
    }
    out
}

/// Reader/writer over the SSH channel with a byte buffer and ZMODEM helpers.
struct Rx<'a> {
    ch: &'a mut Channel<Msg>,
    buf: VecDeque<u8>,
    closed: bool,
    /// When set (upload / `rz` path only), non-protocol bytes the remote `rz`
    /// echoes back during the transfer are forwarded here so the terminal keeps
    /// showing live progress instead of looking frozen (#ZMODEM-echo).
    echo: Option<UnboundedSender<SessionEvent>>,
    /// Buffered echo text, flushed on newline / size / frame boundary.
    echo_buf: Vec<u8>,
    /// Upload-only: strips a remote tty's echo-back of our own outbound
    /// stream before it can reach the frame scanner or the terminal
    /// (#synology-echo). `None` on the receive path, which never needs it.
    strip: Option<EchoStrip>,
}

impl<'a> Rx<'a> {
    fn new(ch: &'a mut Channel<Msg>, first: &[u8]) -> Self {
        Rx {
            ch,
            buf: first.iter().copied().collect(),
            closed: false,
            echo: None,
            echo_buf: Vec::new(),
            strip: None,
        }
    }

    /// Record outbound bytes with the echo stripper (upload path only).
    fn record_sent(&mut self, bytes: &[u8]) {
        if let Some(strip) = &mut self.strip {
            strip.record(bytes);
        }
    }

    /// Send the cancel sequence so a broken remote `rz` gives up, recording
    /// it so its echo-back is stripped too.
    async fn cancel(&mut self) {
        self.record_sent(&ZMODEM_CANCEL_SEQ);
        let _ = self.ch.data(&ZMODEM_CANCEL_SEQ[..]).await;
    }

    /// Run an inbound channel chunk through the echo stripper (upload path)
    /// and return only the bytes that are real receiver output.
    fn strip_echo(&mut self, data: &[u8]) -> Vec<u8> {
        match &mut self.strip {
            Some(strip) => {
                let mut kept = Vec::with_capacity(data.len());
                for &b in data {
                    strip.feed(b, &mut kept);
                }
                kept
            }
            None => data.to_vec(),
        }
    }

    /// Buffer a byte of remote echo; flush on newline or when the buffer is
    /// large so the terminal updates smoothly without one-event-per-byte spam.
    fn echo_push(&mut self, b: u8) {
        if self.echo.is_none() {
            return;
        }
        self.echo_buf.push(b);
        if b == b'\n' || self.echo_buf.len() >= 1024 {
            self.echo_flush();
        }
    }

    /// Flush any buffered remote echo to the terminal, reduced to
    /// terminal-safe text first so a noisy/echoing remote can't flood the
    /// screen with binary garbage (#synology-echo).
    fn echo_flush(&mut self) {
        if let Some(ev) = &self.echo {
            if !self.echo_buf.is_empty() {
                let clean = sanitize_echo(&self.echo_buf);
                self.echo_buf.clear();
                if !clean.is_empty() {
                    let s = String::from_utf8_lossy(&clean).into_owned();
                    let _ = ev.send(SessionEvent::Output(s));
                }
            }
        }
    }

    /// Drain inbound channel data for up to `budget`, forwarding remote `rz` echo
    /// to the terminal. Keeps the SSH receive window from filling so the remote
    /// never blocks on its own echo (which would deadlock our upload). Reply
    /// frames are not expected here — `rz` only ACKs after a frame's ZCRCW
    /// terminator, by which point `flush_pending` has returned and `guarded_ack`
    /// reads the reply — so everything seen mid-frame is progress echo
    /// (#ZMODEM-deadlock).
    async fn drain_echo(&mut self, budget: Duration) {
        if budget.is_zero() {
            return;
        }
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or_default();
            if remaining.is_zero() {
                break;
            }
            let msg = match tokio::time::timeout(remaining, self.ch.wait()).await {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    let kept = self.strip_echo(&data);
                    for &b in &kept {
                        self.echo_push(b);
                    }
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    self.closed = true;
                    break;
                }
                _ => {}
            }
        }
    }

    /// Next raw byte; pulls more channel data when the buffer drains.
    async fn byte(&mut self) -> Result<u8> {
        loop {
            if let Some(b) = self.buf.pop_front() {
                return Ok(b);
            }
            if self.closed {
                bail!("channel closed during ZMODEM");
            }
            // Guard against a stalled transfer hanging the session forever.
            let msg = tokio::time::timeout(Duration::from_secs(30), self.ch.wait())
                .await
                .map_err(|_| anyhow::anyhow!("ZMODEM read timed out"))?;
            match msg {
                Some(ChannelMsg::Data { data }) => {
                    let kept = self.strip_echo(&data);
                    self.buf.extend(kept);
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    let kept = self.strip_echo(&data);
                    self.buf.extend(kept);
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => self.closed = true,
                _ => {}
            }
        }
    }

    /// One logical byte with ZDLE un-escaping applied.
    async fn zbyte(&mut self) -> Result<u8> {
        let b = self.byte().await?;
        if b != ZDLE {
            return Ok(b);
        }
        let e = self.byte().await?;
        Ok(match e {
            ZRUB0 => 0x7f,
            ZRUB1 => 0xff,
            _ => e ^ 0x40,
        })
    }

    /// Read the next frame header, scanning past any padding/garbage. Returns
    /// the frame type and its four data bytes.
    async fn read_header(&mut self) -> Result<(u8, [u8; 4])> {
        // A candidate header that fails CRC/hex validation is skipped and
        // scanning resumes — lrzsz-style resync — so line noise or a remote
        // tty's echo-back can't abort the whole transfer (#synology-echo).
        // Only I/O-level failures (channel closed, read timeout) propagate.
        // The run of consecutive bad headers is bounded so a stream that is
        // pure garbage still errors out instead of looping forever.
        let mut bad = 0u32;
        loop {
            // Find ZDLE followed by a recognised format byte. Bytes that are not
            // a frame start are remote `rz` echo — forward them to the terminal
            // so the upload doesn't look frozen (#ZMODEM-echo).
            let b = self.byte().await?;
            if b != ZDLE {
                self.echo_push(b);
                continue;
            }
            self.echo_flush();
            let parsed = match self.byte().await? {
                ZHEX => self.try_read_hex_header().await?,
                ZBIN => self.try_read_bin_header(false).await?,
                ZBIN32 => self.try_read_bin_header(true).await?,
                _ => continue, // not a header start (could be a CAN run); keep scanning
            };
            match parsed {
                Some(h) => return Ok(h),
                None => {
                    bad += 1;
                    if bad > 256 {
                        bail!(
                            "{}",
                            t(
                                "ZMODEM 帧头连续校验失败(链路噪声过大)",
                                "too many bad ZMODEM headers (noisy link)"
                            )
                        );
                    }
                    continue;
                }
            }
        }
    }

    async fn try_read_hex_header(&mut self) -> Result<Option<(u8, [u8; 4])>> {
        let mut bytes = [0u8; 5];
        for b in bytes.iter_mut() {
            match self.try_hex_byte().await? {
                Some(v) => *b = v,
                None => return Ok(None),
            }
        }
        let (Some(crc_hi), Some(crc_lo)) =
            (self.try_hex_byte().await?, self.try_hex_byte().await?)
        else {
            return Ok(None);
        };
        let crc = u16::from_be_bytes([crc_hi, crc_lo]);
        if crc16(&bytes) != crc {
            tracing::debug!("zmodem: hex header CRC mismatch, resyncing");
            return Ok(None);
        }
        // Swallow the trailing CR/LF (+ optional XON) — but ONLY bytes already
        // buffered. Blocking here would stall up to the full read timeout when
        // a sender appends no trailer, and a sender that starts the next frame
        // immediately would lose its first byte. Whatever we miss is skipped
        // later by the header scanner.
        for _ in 0..3 {
            match self.buf.front().copied() {
                Some(b'\r') | Some(b'\n') | Some(0x11) => {
                    self.buf.pop_front();
                }
                _ => break,
            }
        }
        Ok(Some((bytes[0], [bytes[1], bytes[2], bytes[3], bytes[4]])))
    }

    async fn try_read_bin_header(&mut self, crc32: bool) -> Result<Option<(u8, [u8; 4])>> {
        let mut bytes = [0u8; 5];
        for b in bytes.iter_mut() {
            *b = self.zbyte().await?;
        }
        if crc32 {
            let mut c = [0u8; 4];
            for b in c.iter_mut() {
                *b = self.zbyte().await?;
            }
            if crc32_of(&bytes) != u32::from_le_bytes(c) {
                tracing::debug!("zmodem: bin32 header CRC mismatch, resyncing");
                return Ok(None);
            }
        } else {
            let hi = self.zbyte().await?;
            let lo = self.zbyte().await?;
            if crc16(&bytes) != u16::from_be_bytes([hi, lo]) {
                tracing::debug!("zmodem: bin16 header CRC mismatch, resyncing");
                return Ok(None);
            }
        }
        Ok(Some((bytes[0], [bytes[1], bytes[2], bytes[3], bytes[4]])))
    }

    /// Read a data subpacket, returning the (un-escaped) data and the terminator
    /// byte (ZCRCE/ZCRCG/ZCRCQ/ZCRCW). The CRC covers data + terminator.
    async fn read_subpacket(&mut self, crc32: bool) -> Result<(Vec<u8>, u8)> {
        let mut data = Vec::new();
        loop {
            let b = self.byte().await?;
            if b != ZDLE {
                data.push(b);
                continue;
            }
            let e = self.byte().await?;
            match e {
                ZCRCE | ZCRCG | ZCRCQ | ZCRCW => {
                    let mut crcbuf = data.clone();
                    crcbuf.push(e);
                    if crc32 {
                        let mut c = [0u8; 4];
                        for x in c.iter_mut() {
                            *x = self.zbyte().await?;
                        }
                        if crc32_of(&crcbuf) != u32::from_le_bytes(c) {
                            bail!("subpacket CRC-32 mismatch");
                        }
                    } else {
                        let hi = self.zbyte().await?;
                        let lo = self.zbyte().await?;
                        if crc16(&crcbuf) != u16::from_be_bytes([hi, lo]) {
                            bail!("subpacket CRC-16 mismatch");
                        }
                    }
                    return Ok((data, e));
                }
                ZRUB0 => data.push(0x7f),
                ZRUB1 => data.push(0xff),
                _ => data.push(e ^ 0x40),
            }
        }
    }

    /// Read two hex ASCII digits into a byte; `None` on a non-hex digit so
    /// the caller can resync instead of aborting the transfer.
    async fn try_hex_byte(&mut self) -> Result<Option<u8>> {
        let hi = self.byte().await?;
        let lo = self.byte().await?;
        Ok(match (hex_val(hi), hex_val(lo)) {
            (Some(h), Some(l)) => Some((h << 4) | l),
            _ => None,
        })
    }

    /// Send a hex-encoded header (always accepted regardless of CRC mode).
    async fn send_hex(&mut self, ftype: u8, data: [u8; 4]) -> Result<()> {
        let payload = [ftype, data[0], data[1], data[2], data[3]];
        let crc = crc16(&payload);
        let mut out = vec![ZPAD, ZPAD, ZDLE, ZHEX];
        for &b in &payload {
            out.extend_from_slice(&hex_digits(b));
        }
        out.extend_from_slice(&hex_digits((crc >> 8) as u8));
        out.extend_from_slice(&hex_digits((crc & 0xff) as u8));
        out.extend_from_slice(b"\r\n");
        // XON after every hex header except ZACK/ZFIN (per the protocol).
        if ftype != ZACK && ftype != ZFIN {
            out.push(0x11);
        }
        tracing::debug!("zmodem tx type={ftype} bytes={:02x?}", &out);
        self.record_sent(&out);
        self.ch.data(&out[..]).await.context("zmodem send header")?;
        Ok(())
    }

    /// Send a binary ZMODEM header (ZBIN for CRC-16, ZBIN32 for CRC-32). Binary
    /// headers carry the 5 payload bytes raw (ZDLE-escaped) followed by the
    /// (escaped) CRC — no hex encoding, no trailing CRLF/XON. Used when the
    /// receiver advertised CANFC32 so the whole session speaks CRC-32, mirroring
    /// a real `sz` and the black-Synology helper `rz` (#76).
    async fn send_bin(&mut self, crc32: bool, ftype: u8, data: [u8; 4]) -> Result<()> {
        let payload = [ftype, data[0], data[1], data[2], data[3]];
        let mut out = vec![ZPAD, ZPAD, ZDLE, if crc32 { ZBIN32 } else { ZBIN }];
        for &b in &payload {
            if needs_escape(b) {
                out.push(ZDLE);
                out.push(b ^ 0x40);
            } else {
                out.push(b);
            }
        }
        let crc_raw: Vec<u8> = if crc32 {
            crc32_of(&payload).to_le_bytes().to_vec()
        } else {
            let c = crc16(&payload);
            vec![(c >> 8) as u8, (c & 0xff) as u8]
        };
        for &b in &crc_raw {
            if needs_escape(b) {
                out.push(ZDLE);
                out.push(b ^ 0x40);
            } else {
                out.push(b);
            }
        }
        tracing::debug!("zmodem tx bin type={ftype} crc32={crc32} bytes={:02x?}", &out);
        self.record_sent(&out);
        self.ch.data(&out[..]).await.context("zmodem send bin header")?;
        Ok(())
    }
}

/// True for bytes that make up a ZMODEM hex close frame (ZFIN) or the "OO"
/// over-and-out, used to drain the sender's lingering close frames without
/// eating the shell prompt that follows (which starts with ESC/letters) (#76).
fn is_close_byte(b: u8) -> bool {
    matches!(b,
        b'*' | ZDLE | b'A' | b'B' | b'C' | b'O'
        | b'\r' | b'\n' | 0x8a | 0x11
        | b'0'..=b'9' | b'a'..=b'f')
}

/// Where received files go: the user's Downloads dir, else a temp fallback.
fn download_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::temp_dir().join("newshell"))
}

/// Reduce a sender-supplied name to a safe basename inside the download dir.
fn sanitize(name: &str) -> String {
    let base = name
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(name);
    let cleaned: String = base
        .chars()
        .filter(|c| !matches!(c, '\0' | '/' | '\\'))
        .collect();
    // Trim trailing dots/spaces (illegal on Windows) and leading spaces, but
    // KEEP leading dots so dotfiles like ".viminfo" keep their name (#76).
    let cleaned = cleaned
        .trim_end_matches(|c| c == '.' || c == ' ')
        .trim_start_matches(' ');
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        "download".to_string()
    } else {
        cleaned.to_string()
    }
}

fn emit(
    events: &UnboundedSender<SessionEvent>,
    id: &str,
    name: &str,
    transferred: u64,
    total: u64,
    state: u8,
    msg: &str,
) {
    let _ = events.send(SessionEvent::SftpTransfer {
        id: id.to_string(),
        name: name.to_string(),
        is_upload: true,
        transferred,
        total,
        state,
        msg: msg.to_string(),
    });
}

fn hex_digits(b: u8) -> [u8; 2] {
    const H: &[u8; 16] = b"0123456789abcdef";
    [H[(b >> 4) as usize], H[(b & 0x0f) as usize]]
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// CRC-16/XMODEM (poly 0x1021, init 0, no final xor) — ZMODEM header/subpacket.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// CRC-32/ISO-HDLC (zlib): init 0xFFFFFFFF, reflected, final xor 0xFFFFFFFF.
fn crc32_of(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_known_vector() {
        // CRC-16/XMODEM of "123456789" is 0x31C3.
        assert_eq!(crc16(b"123456789"), 0x31C3);
    }

    #[test]
    fn crc32_known_vector() {
        // CRC-32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32_of(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn sanitize_strips_paths() {
        assert_eq!(sanitize("/etc/passwd"), "passwd");
        assert_eq!(sanitize("..\\..\\x"), "x");
        assert_eq!(sanitize(""), "download");
        // Dotfiles keep their leading dot.
        assert_eq!(sanitize(".viminfo"), ".viminfo");
        assert_eq!(sanitize("/home/jeff/.bashrc"), ".bashrc");
        // Trailing dots/spaces are trimmed; pure-dot names rejected.
        assert_eq!(sanitize("name..."), "name");
        assert_eq!(sanitize(".."), "download");
    }

    #[test]
    fn sanitize_echo_keeps_text_drops_binary() {
        // Plain progress text passes through untouched.
        assert_eq!(sanitize_echo(b"rz waiting to receive.\r\n"), b"rz waiting to receive.\r\n");
        // C0/C1 control bytes are dropped; printable text survives.
        assert_eq!(sanitize_echo(&[0x00, 0x07, b'o', b'k', 0x1f, 0x9b]), b"ok");
        // ESC is kept so ANSI colour/cursor sequences still work.
        assert_eq!(sanitize_echo(b"\x1b[31mred\x1b[0m"), b"\x1b[31mred\x1b[0m");
        // Valid UTF-8 (localised rz messages) is kept…
        assert_eq!(sanitize_echo("正在接收…".as_bytes()), "正在接收…".as_bytes());
        // …but invalid bytes and truncated sequences are dropped.
        assert_eq!(sanitize_echo(&[0xff, 0xfe, b'a']), b"a");
        assert_eq!(sanitize_echo(&[0xe4, 0xb8]), b"");
        assert_eq!(sanitize_echo(&[b'a', 0x80, b'b']), b"ab");
    }

    #[test]
    fn echo_strip_passes_real_data_when_remote_is_silent() {
        let mut s = EchoStrip::new();
        s.record(b"our outbound frame bytes");
        let mut out = Vec::new();
        for &b in b"**\x18B03receiver-ack" {
            s.feed(b, &mut out);
        }
        assert_eq!(out, b"**\x18B03receiver-ack");
        assert!(!s.echoing);
    }

    #[test]
    fn echo_strip_drops_exact_echo_and_passes_real_ack() {
        let mut s = EchoStrip::new();
        let sent: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        s.record(&sent);
        let mut out = Vec::new();
        // The remote tty echoes the first 200 bytes back, then the receiver's
        // real ACK arrives interleaved.
        for &b in &sent[..200] {
            s.feed(b, &mut out);
        }
        for &b in b"\x18C\x03ack!" {
            s.feed(b, &mut out);
        }
        assert_eq!(out, b"\x18C\x03ack!");
    }

    #[test]
    fn echo_strip_releases_tentative_run_on_mismatch() {
        // A short coincidental prefix match must not eat real receiver bytes.
        let mut s = EchoStrip::new();
        s.record(b"abcdefgh");
        let mut out = Vec::new();
        for &b in b"abcXY" {
            s.feed(b, &mut out);
        }
        assert_eq!(out, b"abcXY");
        assert!(!s.echoing);
    }

    #[test]
    fn echo_strip_window_is_bounded() {
        let mut s = EchoStrip::new();
        s.record(&vec![0x55; EchoStrip::WINDOW + 8]);
        assert!(s.sent.len() <= EchoStrip::WINDOW);
    }
}
