//! Native PuTTY PPK v2/v3 private-key loader (#281).
//!
//! PPK files are authenticated before their private blob is translated into
//! the in-memory OpenSSH key representation understood by `ssh-key`/russh.
//! No converted private key is ever written to disk.

use aes::Aes256;
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params, Version};
use base64::Engine;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use russh::keys::PrivateKey;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

const PPK_PREFIX: &[u8] = b"PuTTY-User-Key-File-";
const MAX_PPK_SIZE: usize = 16 * 1024 * 1024;
const MAX_ARGON_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_ARGON_PASSES: u32 = 1000;
const MAX_ARGON_PARALLELISM: u32 = 64;

#[derive(Debug)]
struct Ppk {
    version: u8,
    algorithm: String,
    encryption: String,
    comment: String,
    public: Vec<u8>,
    private: Zeroizing<Vec<u8>>,
    mac: Vec<u8>,
    derivation: Option<ArgonSettings>,
}

#[derive(Debug)]
struct ArgonSettings {
    algorithm: ArgonAlgorithm,
    memory_kib: u32,
    passes: u32,
    parallelism: u32,
    salt: Vec<u8>,
}

pub(crate) fn is_ppk(input: &[u8]) -> bool {
    input
        .iter()
        .copied()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .take(PPK_PREFIX.len())
        .eq(PPK_PREFIX.iter().copied())
}

pub(crate) fn decode_ppk(input: &[u8], passphrase: &str) -> Result<PrivateKey> {
    let mut ppk = parse_ppk(input)?;
    decrypt_private_blob(&mut ppk, passphrase)?;
    verify_mac(&ppk, passphrase)?;
    ppk_to_openssh(&ppk)
}

fn parse_ppk(input: &[u8]) -> Result<Ppk> {
    if input.len() > MAX_PPK_SIZE {
        bail!("PPK file is too large");
    }
    let text = std::str::from_utf8(input).context("PPK file is not valid UTF-8 text")?;
    let mut lines = text.lines().map(|line| line.trim_end_matches('\r'));

    let first = lines.next().context("empty PPK file")?;
    let first = first
        .strip_prefix("PuTTY-User-Key-File-")
        .context("not a PuTTY private key (expected PuTTY-User-Key-File-2 or -3)")?;
    let (version, algorithm) = first
        .split_once(':')
        .context("invalid PPK version header")?;
    let version = version
        .trim()
        .parse::<u8>()
        .context("invalid PPK version")?;
    if !matches!(version, 2 | 3) {
        bail!("unsupported PPK version {version}; only versions 2 and 3 are supported");
    }
    let algorithm = algorithm.trim().to_string();
    let encryption = header_value(lines.next(), "Encryption")?.to_string();
    if !matches!(encryption.as_str(), "none" | "aes256-cbc") {
        bail!("unsupported PPK encryption: {encryption}");
    }
    let comment = header_value(lines.next(), "Comment")?.to_string();
    let public_lines = parse_count_header(lines.next(), "Public-Lines")?;
    let public = decode_base64_lines(&mut lines, public_lines, "public")?;

    let derivation = if version == 3 && encryption != "none" {
        let algorithm = match header_value(lines.next(), "Key-Derivation")? {
            "Argon2d" => ArgonAlgorithm::Argon2d,
            "Argon2i" => ArgonAlgorithm::Argon2i,
            "Argon2id" => ArgonAlgorithm::Argon2id,
            other => bail!("unsupported PPK key derivation: {other}"),
        };
        let memory_kib = parse_u32_header(lines.next(), "Argon2-Memory")?;
        let passes = parse_u32_header(lines.next(), "Argon2-Passes")?;
        let parallelism = parse_u32_header(lines.next(), "Argon2-Parallelism")?;
        if memory_kib == 0 || memory_kib > MAX_ARGON_MEMORY_KIB {
            bail!("unsafe PPK Argon2 memory setting: {memory_kib} KiB");
        }
        if passes == 0 || passes > MAX_ARGON_PASSES {
            bail!("unsafe PPK Argon2 pass count: {passes}");
        }
        if parallelism == 0 || parallelism > MAX_ARGON_PARALLELISM {
            bail!("unsafe PPK Argon2 parallelism: {parallelism}");
        }
        let salt = decode_hex(header_value(lines.next(), "Argon2-Salt")?)
            .context("invalid PPK Argon2 salt")?;
        Some(ArgonSettings {
            algorithm,
            memory_kib,
            passes,
            parallelism,
            salt,
        })
    } else {
        None
    };

    let private_lines = parse_count_header(lines.next(), "Private-Lines")?;
    let private = Zeroizing::new(decode_base64_lines(&mut lines, private_lines, "private")?);
    let mac = decode_hex(header_value(lines.next(), "Private-MAC")?)
        .context("invalid PPK private MAC")?;

    Ok(Ppk {
        version,
        algorithm,
        encryption,
        comment,
        public,
        private,
        mac,
        derivation,
    })
}

fn header_value<'a>(line: Option<&'a str>, name: &str) -> Result<&'a str> {
    let line = line.with_context(|| format!("missing PPK {name} header"))?;
    let (actual, value) = line
        .split_once(':')
        .with_context(|| format!("invalid PPK {name} header"))?;
    if actual != name {
        bail!("expected PPK {name} header, found {actual}");
    }
    Ok(value.trim_start())
}

fn parse_count_header(line: Option<&str>, name: &str) -> Result<usize> {
    header_value(line, name)?
        .parse::<usize>()
        .with_context(|| format!("invalid PPK {name} count"))
}

fn parse_u32_header(line: Option<&str>, name: &str) -> Result<u32> {
    header_value(line, name)?
        .parse::<u32>()
        .with_context(|| format!("invalid PPK {name} value"))
}

fn decode_base64_lines<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    count: usize,
    section: &str,
) -> Result<Vec<u8>> {
    if count > MAX_PPK_SIZE / 4 {
        bail!("PPK {section} section contains too many lines");
    }
    let mut encoded = String::new();
    for _ in 0..count {
        encoded.push_str(
            lines
                .next()
                .with_context(|| format!("truncated PPK {section} section"))?
                .trim(),
        );
    }
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .with_context(|| format!("invalid base64 in PPK {section} section"))
}

fn decrypt_private_blob(ppk: &mut Ppk, passphrase: &str) -> Result<()> {
    if ppk.encryption == "none" {
        return Ok(());
    }
    if passphrase.is_empty() {
        bail!("this PuTTY private key is encrypted; enter its passphrase");
    }
    if ppk.private.is_empty() || ppk.private.len() % 16 != 0 {
        bail!("invalid encrypted PPK private-data length");
    }

    let (mut key, mut iv, _) = derive_keys(ppk, passphrase)?;
    Aes256CbcDec::new((&key).into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut ppk.private)
        .map_err(|_| anyhow!("failed to decrypt PPK private data"))?;
    key.zeroize();
    iv.zeroize();
    Ok(())
}

fn derive_keys(ppk: &Ppk, passphrase: &str) -> Result<([u8; 32], [u8; 16], Vec<u8>)> {
    if ppk.version == 2 {
        let mut material = Zeroizing::new(Vec::with_capacity(40));
        for sequence in 0_u32..2 {
            let mut hash = Sha1::new();
            hash.update(sequence.to_be_bytes());
            hash.update(passphrase.as_bytes());
            material.extend_from_slice(&hash.finalize());
        }
        let mut key = [0_u8; 32];
        key.copy_from_slice(&material[..32]);
        let mut mac_hash = Sha1::new();
        mac_hash.update(b"putty-private-key-file-mac-key");
        mac_hash.update(passphrase.as_bytes());
        return Ok((key, [0_u8; 16], mac_hash.finalize().to_vec()));
    }

    if ppk.encryption == "none" {
        return Ok(([0_u8; 32], [0_u8; 16], Vec::new()));
    }
    let settings = ppk
        .derivation
        .as_ref()
        .context("encrypted PPKv3 is missing Argon2 settings")?;
    let params = Params::new(
        settings.memory_kib,
        settings.passes,
        settings.parallelism,
        Some(80),
    )
    .map_err(|error| anyhow!("invalid PPK Argon2 parameters: {error}"))?;
    let argon = Argon2::new(settings.algorithm, Version::V0x13, params);
    let mut material = Zeroizing::new([0_u8; 80]);
    argon
        .hash_password_into(passphrase.as_bytes(), &settings.salt, &mut *material)
        .map_err(|error| anyhow!("failed to derive PPK encryption key: {error}"))?;
    let mut key = [0_u8; 32];
    let mut iv = [0_u8; 16];
    key.copy_from_slice(&material[..32]);
    iv.copy_from_slice(&material[32..48]);
    Ok((key, iv, material[48..].to_vec()))
}

fn verify_mac(ppk: &Ppk, passphrase: &str) -> Result<()> {
    let mut authenticated = Zeroizing::new(Vec::new());
    push_string(&mut authenticated, ppk.algorithm.as_bytes())?;
    push_string(&mut authenticated, ppk.encryption.as_bytes())?;
    push_string(&mut authenticated, ppk.comment.as_bytes())?;
    push_string(&mut authenticated, &ppk.public)?;
    push_string(&mut authenticated, &ppk.private)?;

    let (_, _, mac_key) = derive_keys(ppk, passphrase)?;
    let valid = if ppk.version == 2 {
        let mut mac = Hmac::<Sha1>::new_from_slice(&mac_key).expect("HMAC accepts any key size");
        mac.update(&authenticated);
        mac.verify_slice(&ppk.mac).is_ok()
    } else {
        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).expect("HMAC accepts any key size");
        mac.update(&authenticated);
        mac.verify_slice(&ppk.mac).is_ok()
    };
    if !valid {
        bail!("PuTTY private key passphrase is incorrect or the key file is damaged");
    }
    Ok(())
}

fn ppk_to_openssh(ppk: &Ppk) -> Result<PrivateKey> {
    let public = PublicParts::parse(&ppk.public, &ppk.algorithm)?;
    let private = PrivateParts::parse(&ppk.private, &ppk.algorithm)?;

    let mut key_fields = Zeroizing::new(Vec::new());
    push_string(&mut key_fields, ppk.algorithm.as_bytes())?;
    match (public, private) {
        (PublicParts::Rsa { e, n }, PrivateParts::Rsa { d, p, q, iqmp }) => {
            key_fields.extend_from_slice(n);
            key_fields.extend_from_slice(e);
            key_fields.extend_from_slice(d);
            key_fields.extend_from_slice(iqmp);
            key_fields.extend_from_slice(p);
            key_fields.extend_from_slice(q);
        }
        (PublicParts::Ecdsa { curve, point }, PrivateParts::Ecdsa { exponent }) => {
            key_fields.extend_from_slice(curve);
            key_fields.extend_from_slice(point);
            key_fields.extend_from_slice(exponent);
        }
        (PublicParts::Ed25519 { public }, PrivateParts::Ed25519 { exponent }) => {
            key_fields.extend_from_slice(public);
            let public_value = string_value(public)?;
            let mut seed = normalize_integer(string_value(exponent)?, 32)?;
            let mut combined = Zeroizing::new(Vec::with_capacity(64));
            combined.extend_from_slice(&seed);
            combined.extend_from_slice(public_value);
            push_string(&mut key_fields, &combined)?;
            seed.zeroize();
        }
        _ => bail!("PPK public and private key algorithms do not match"),
    }

    let check = 0x4d53_5050_u32;
    let mut private_block = Zeroizing::new(Vec::new());
    private_block.extend_from_slice(&check.to_be_bytes());
    private_block.extend_from_slice(&check.to_be_bytes());
    private_block.extend_from_slice(&key_fields);
    push_string(&mut private_block, ppk.comment.as_bytes())?;
    let block_size = 8;
    let padding = (block_size - private_block.len() % block_size) % block_size;
    for byte in 1..=padding {
        private_block.push(byte as u8);
    }

    let mut openssh = Zeroizing::new(Vec::new());
    openssh.extend_from_slice(b"openssh-key-v1\0");
    push_string(&mut openssh, b"none")?;
    push_string(&mut openssh, b"none")?;
    push_string(&mut openssh, b"")?;
    openssh.extend_from_slice(&1_u32.to_be_bytes());
    push_string(&mut openssh, &ppk.public)?;
    push_string(&mut openssh, &private_block)?;

    PrivateKey::from_bytes(&openssh).context("converted PPK contains invalid key material")
}

enum PublicParts<'a> {
    Rsa { e: &'a [u8], n: &'a [u8] },
    Ecdsa { curve: &'a [u8], point: &'a [u8] },
    Ed25519 { public: &'a [u8] },
}

impl<'a> PublicParts<'a> {
    fn parse(blob: &'a [u8], expected: &str) -> Result<Self> {
        let mut reader = WireReader::new(blob);
        let algorithm = reader.field()?;
        if string_value(algorithm)? != expected.as_bytes() {
            bail!("PPK public key algorithm does not match its header");
        }
        let result = match expected {
            "ssh-rsa" => Self::Rsa {
                e: reader.field()?,
                n: reader.field()?,
            },
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => Self::Ecdsa {
                curve: reader.field()?,
                point: reader.field()?,
            },
            "ssh-ed25519" => Self::Ed25519 {
                public: reader.field()?,
            },
            "ssh-dss" => bail!("DSA PPK keys are not supported by this SSH backend"),
            "ssh-ed448" => bail!("Ed448 PPK keys are not supported by this SSH backend"),
            other => bail!("unsupported PPK key algorithm: {other}"),
        };
        reader.finish()?;
        Ok(result)
    }
}

enum PrivateParts<'a> {
    Rsa {
        d: &'a [u8],
        p: &'a [u8],
        q: &'a [u8],
        iqmp: &'a [u8],
    },
    Ecdsa {
        exponent: &'a [u8],
    },
    Ed25519 {
        exponent: &'a [u8],
    },
}

impl<'a> PrivateParts<'a> {
    fn parse(blob: &'a [u8], algorithm: &str) -> Result<Self> {
        let mut reader = WireReader::new(blob);
        match algorithm {
            "ssh-rsa" => Ok(Self::Rsa {
                d: reader.field()?,
                p: reader.field()?,
                q: reader.field()?,
                iqmp: reader.field()?,
            }),
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
                Ok(Self::Ecdsa {
                    exponent: reader.field()?,
                })
            }
            "ssh-ed25519" => Ok(Self::Ed25519 {
                exponent: reader.field()?,
            }),
            other => bail!("unsupported PPK key algorithm: {other}"),
        }
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Return a complete SSH string/mpint including its four-byte length.
    fn field(&mut self) -> Result<&'a [u8]> {
        let start = self.offset;
        let length_bytes: [u8; 4] = self
            .bytes
            .get(start..start + 4)
            .context("truncated PPK key field")?
            .try_into()
            .expect("four-byte slice");
        let length = u32::from_be_bytes(length_bytes) as usize;
        self.offset = start
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .context("PPK key field length overflow")?;
        self.bytes
            .get(start..self.offset)
            .context("truncated PPK key field data")
    }

    fn finish(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            bail!("unexpected trailing data in PPK public key")
        }
    }
}

fn string_value(field: &[u8]) -> Result<&[u8]> {
    let length = u32::from_be_bytes(
        field
            .get(..4)
            .context("truncated SSH key field")?
            .try_into()
            .expect("four-byte slice"),
    ) as usize;
    let value = field.get(4..).context("truncated SSH key field")?;
    if value.len() != length {
        bail!("invalid SSH key field length");
    }
    Ok(value)
}

fn normalize_integer(value: &[u8], size: usize) -> Result<Vec<u8>> {
    let value = value.strip_prefix(&[0]).unwrap_or(value);
    if value.len() > size {
        bail!("PPK private exponent is too large");
    }
    let mut out = vec![0_u8; size];
    out[size - value.len()..].copy_from_slice(value);
    Ok(out)
}

fn push_string(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let len = u32::try_from(value.len()).context("SSH key field is too large")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("hex value has odd length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex input is UTF-8");
            u8::from_str_radix(text, 16).context("invalid hex digit")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PPK_V2_RSA: &str = include_str!("../../../tests/fixtures/ppk-v2-rsa.ppk");
    const PPK_V2_RSA_ENCRYPTED: &str =
        include_str!("../../../tests/fixtures/ppk-v2-rsa-encrypted.ppk");
    const PPK_V3_ED25519: &str = include_str!("../../../tests/fixtures/ppk-v3-ed25519.ppk");
    const PPK_V3_ECDSA_ENCRYPTED: &str =
        include_str!("../../../tests/fixtures/ppk-v3-ecdsa-encrypted.ppk");

    #[test]
    fn detects_ppk_content() {
        assert!(is_ppk(PPK_V2_RSA.as_bytes()));
        assert!(!is_ppk(b"-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn loads_unencrypted_ppkv2_rsa() {
        let key = decode_ppk(PPK_V2_RSA.as_bytes(), "").unwrap();
        assert!(key.algorithm().is_rsa());
    }

    #[test]
    fn loads_encrypted_ppkv2_rsa() {
        let key = decode_ppk(PPK_V2_RSA_ENCRYPTED.as_bytes(), "v2-passphrase").unwrap();
        assert!(key.algorithm().is_rsa());
    }

    #[test]
    fn loads_unencrypted_ppkv3_ed25519() {
        let key = decode_ppk(PPK_V3_ED25519.as_bytes(), "").unwrap();
        assert_eq!(key.algorithm().as_str(), "ssh-ed25519");
    }

    #[test]
    fn loads_encrypted_ppkv3_ecdsa() {
        let key = decode_ppk(PPK_V3_ECDSA_ENCRYPTED.as_bytes(), "test-passphrase").unwrap();
        assert_eq!(key.algorithm().as_str(), "ecdsa-sha2-nistp256");
    }

    #[test]
    fn rejects_incorrect_ppkv3_passphrase() {
        let error = decode_ppk(PPK_V3_ECDSA_ENCRYPTED.as_bytes(), "wrong")
            .unwrap_err()
            .to_string();
        assert!(error.contains("incorrect") || error.contains("damaged"));
    }

    #[test]
    fn rejects_modified_ppk_before_key_conversion() {
        let changed = PPK_V2_RSA.replace("imported-openssh-key", "modified-comment");
        let error = decode_ppk(changed.as_bytes(), "").unwrap_err().to_string();
        assert!(error.contains("damaged"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let changed = PPK_V2_RSA.replacen("File-2", "File-4", 1);
        assert!(decode_ppk(changed.as_bytes(), "")
            .unwrap_err()
            .to_string()
            .contains("version 4"));
    }
}
