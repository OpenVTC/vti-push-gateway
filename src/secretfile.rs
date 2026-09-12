//! Permission-aware handling of the gateway's on-disk secrets.
//!
//! The gateway reads four operator-owned secret files — its DIDComm identity
//! (`GATEWAY_IDENTITY_FILE`), the VAPID private key, the APNs `.p8` auth key and
//! the FCM service-account JSON — and writes one (`vapid-keygen`). It also owns
//! the store snapshot, which holds raw push tokens and Web Push subscription
//! secrets and is therefore a secret file in its own right.
//!
//! Two rules, applied in one place:
//!
//! - **Writes are owner-only from the first byte.** [`write_owner_only_new`]
//!   creates the file with `O_EXCL` and mode 0600, so there is no window in
//!   which the key is world-readable and no chance of following a pre-planted
//!   symlink. `create-then-chmod` had both problems.
//! - **Reads report loose permissions.** [`read_secret_file`] warns when a
//!   secret is group- or world-accessible, and refuses to read it when
//!   [`ENV_STRICT_KEY_PERMS`] is set — so an operator can make a mis-installed
//!   key fail the deployment rather than a log line nobody reads.
//!
//! Permissions are a unix concept; on other platforms the checks are no-ops and
//! the writes are ordinary creates.

use std::path::Path;

/// Env flag: when set to `1`/`true`/`yes`, a secret file whose mode grants any
/// group or other access is an error instead of a warning.
pub const ENV_STRICT_KEY_PERMS: &str = "GATEWAY_STRICT_KEY_PERMS";

/// Mode bits a secret file must not have set: any group or other access.
#[cfg(unix)]
const FORBIDDEN_BITS: u32 = 0o077;

/// Owner-only file mode.
#[cfg(unix)]
pub const OWNER_ONLY: u32 = 0o600;

/// Whether [`ENV_STRICT_KEY_PERMS`] asks for loose permissions to be fatal.
pub fn strict_key_perms() -> bool {
    std::env::var(ENV_STRICT_KEY_PERMS)
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// The permission bits of `path`, or `None` when they can't be read (or this
/// isn't unix).
#[cfg(unix)]
fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.mode() & 0o777)
}

#[cfg(not(unix))]
fn mode_of(_path: &Path) -> Option<u32> {
    None
}

/// Whether `mode` grants any access beyond the owner.
#[cfg(unix)]
fn is_loose(mode: u32) -> bool {
    mode & FORBIDDEN_BITS != 0
}

/// Create `path` containing `bytes`, owner-readable only, failing if the path
/// already exists.
///
/// `create_new` + `mode(0o600)` in one `open`: the file is never visible to
/// another user, and an attacker cannot win a race by pre-creating the path or
/// planting a symlink there (`O_EXCL` refuses both). Contrast writing then
/// `chmod`, which leaves the secret at the umask default in between.
pub fn write_owner_only_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(OWNER_ONLY);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))?;
    Ok(())
}

/// Read a secret file, checking its permissions first.
///
/// A mode granting group or other access is a warning, or an error when
/// [`ENV_STRICT_KEY_PERMS`] is set. `what` names the secret in the message so an
/// operator knows which file to fix.
pub fn read_secret_file(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    read_secret_file_with(path, what, strict_key_perms())
}

/// [`read_secret_file`] with the strict flag supplied, so tests don't mutate the
/// process environment.
fn read_secret_file_with(path: &Path, what: &str, strict: bool) -> Result<Vec<u8>, String> {
    check_permissions(path, what, strict)?;
    std::fs::read(path).map_err(|e| format!("read {what} {}: {e}", path.display()))
}

/// Warn (or, under `strict`, fail) when `path` is group- or world-accessible.
#[cfg(unix)]
fn check_permissions(path: &Path, what: &str, strict: bool) -> Result<(), String> {
    let Some(mode) = mode_of(path) else {
        return Ok(()); // unreadable metadata: the read itself will report it
    };
    if !is_loose(mode) {
        return Ok(());
    }
    if strict {
        return Err(format!(
            "{what} {} has mode {mode:04o}; {ENV_STRICT_KEY_PERMS} requires owner-only \
             permissions (chmod 600)",
            path.display()
        ));
    }
    tracing::warn!(
        path = %path.display(), mode = %format!("{mode:04o}"), secret = what,
        "secret file is readable beyond its owner; chmod 600 it \
         (set {ENV_STRICT_KEY_PERMS}=1 to make this fatal)"
    );
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _what: &str, _strict: bool) -> Result<(), String> {
    Ok(())
}

/// Tighten `path` to owner-only if it is group- or world-accessible, warning
/// about what was found.
///
/// Used for the store snapshot, which an older build wrote at the umask default:
/// unlike a key file, the gateway owns this one and can simply fix it, and
/// refusing to boot over it would lose the registry for no security gain.
#[cfg(unix)]
pub fn tighten_to_owner_only(path: &Path) {
    let Some(mode) = mode_of(path) else {
        return;
    };
    if !is_loose(mode) {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_ONLY)) {
        Ok(()) => tracing::warn!(
            path = %path.display(), was = %format!("{mode:04o}"),
            "store snapshot was readable beyond its owner (it holds raw push tokens); \
             tightened to 0600"
        ),
        Err(e) => tracing::error!(
            error = %e, path = %path.display(), mode = %format!("{mode:04o}"),
            "store snapshot is readable beyond its owner and could not be tightened"
        ),
    }
}

#[cfg(not(unix))]
pub fn tighten_to_owner_only(_path: &Path) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_with_mode(path: &Path, mode: u32) {
        std::fs::write(path, b"secret").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A freshly written secret is owner-only, and the content round-trips.
    #[test]
    fn write_owner_only_new_creates_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vapid.pem");
        write_owner_only_new(&path, b"-----BEGIN PRIVATE KEY-----").unwrap();
        assert_eq!(mode_of(&path), Some(OWNER_ONLY));
        assert_eq!(
            read_secret_file_with(&path, "VAPID key", true).unwrap(),
            b"-----BEGIN PRIVATE KEY-----"
        );
    }

    /// Writing onto an existing path fails without touching it — a second
    /// `vapid-keygen` must not clobber a live key.
    #[test]
    fn write_owner_only_new_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vapid.pem");
        write_owner_only_new(&path, b"first").unwrap();
        assert!(write_owner_only_new(&path, b"second").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }

    /// A 0644 key is read with a warning by default, and refused under the
    /// strict flag.
    #[test]
    fn loose_mode_is_fatal_only_in_strict_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AuthKey.p8");
        write_with_mode(&path, 0o644);

        assert!(
            read_secret_file_with(&path, "APNs auth key", false).is_ok(),
            "a warning, not a failure, by default"
        );
        let err = read_secret_file_with(&path, "APNs auth key", true)
            .expect_err("strict mode must refuse a group/world-readable key");
        assert!(err.contains("0644"), "{err}");
        assert!(err.contains(ENV_STRICT_KEY_PERMS), "{err}");
    }

    /// Every mode that grants any group or other access is caught, not just
    /// the read bits — a group-writable key is worse, not better.
    #[test]
    fn strict_mode_catches_every_non_owner_bit() {
        let dir = tempfile::tempdir().unwrap();
        for (i, mode) in [0o640, 0o604, 0o620, 0o602, 0o660, 0o666, 0o777]
            .into_iter()
            .enumerate()
        {
            let path = dir.path().join(format!("key-{i}"));
            write_with_mode(&path, mode);
            assert!(
                read_secret_file_with(&path, "key", true).is_err(),
                "mode {mode:04o} must be refused"
            );
        }
        for (i, mode) in [0o600, 0o400, 0o700].into_iter().enumerate() {
            let path = dir.path().join(format!("ok-{i}"));
            write_with_mode(&path, mode);
            assert!(
                read_secret_file_with(&path, "key", true).is_ok(),
                "mode {mode:04o} is owner-only and must be accepted"
            );
        }
    }

    /// An existing world-readable snapshot is tightened in place.
    #[test]
    fn tighten_fixes_a_loose_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway-store.json");
        write_with_mode(&path, 0o644);
        tighten_to_owner_only(&path);
        assert_eq!(mode_of(&path), Some(OWNER_ONLY));
        // Idempotent: an already-tight file is left alone.
        tighten_to_owner_only(&path);
        assert_eq!(mode_of(&path), Some(OWNER_ONLY));
    }

    /// The strict flag parses the usual spellings, and nothing else.
    #[test]
    fn strict_flag_spellings() {
        // `strict_key_perms` reads the process env; exercise the parse via the
        // same match on representative values.
        for v in ["1", "true", "TRUE", "yes", "on"] {
            assert!(matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ));
        }
        for v in ["0", "false", "", "no", "maybe"] {
            assert!(!matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ));
        }
    }
}
