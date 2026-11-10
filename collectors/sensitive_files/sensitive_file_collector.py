"""
Sensitive File Collector
========================
Forensic artifact collector that searches for credential, key, secret, and
backup-code files stored on the filesystem. This collector is designed
exclusively for authorised digital forensic investigation — it locates files
that an adversary may have dropped, exfiltrated, or that the subject of an
investigation stored locally.

Collected evidence categories
-------------------------------
- Plaintext credential/secret files  (passwords.txt, secrets.txt, …)
- Cryptographic key material          (private.key, id_rsa, *.pem, *.p12, …)
- Wallet / blockchain seed files      (seed.txt, mnemonic.txt, wallet.dat, …)
- Two-factor / backup codes           (backup_codes.txt, 2fa_codes.txt, …)
- Configuration files with secrets    (.env, config.ini, settings with API keys)
- SSH / GPG / certificate material    (*.key, *.crt, *.pem, known_hosts, …)

File size limit
---------------
Files larger than MAX_FILE_SIZE_BYTES are recorded in the manifest (filename,
path, size, hashes) but their content is not copied into the case directory to
prevent filling available storage on USB / portable media.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from core.collector_base import CollectorBase, CollectionResult, FileEvidence
from core.engine import register_collector
from config.settings import CollectionStatus, ArtifactCategory, get_iso_timestamp

logger = logging.getLogger("polaris.sensitive_files")

# ---------------------------------------------------------------------------
# Tunable constants
# ---------------------------------------------------------------------------

# Maximum size of a single file that will be *copied* into the evidence store.
# Files larger than this limit are logged but not copied (content too large).
MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB

# Maximum total bytes that the entire collector will copy in a single run.
MAX_TOTAL_COPY_BYTES: int = 100 * 1024 * 1024  # 100 MB aggregate cap

# ---------------------------------------------------------------------------
# Filename pattern matching  (case-insensitive)
# ---------------------------------------------------------------------------

# Exact filename stems that are always interesting
SENSITIVE_FILENAME_STEMS: frozenset[str] = frozenset({
    # Generic credentials
    "passwords", "password", "passwd", "creds", "credentials",
    "logins", "login_info", "accounts", "account_info",
    "usernames", "users", "user_passwords", "my_passwords",
    "secret", "secrets", "secret_key", "secret_keys",
    "private", "private_key", "private_keys", "privkey", "priv_key",
    "api_key", "api_keys", "apikey", "apikeys", "api_secret", "api_secrets",
    "tokens", "token", "auth_token", "bearer_token", "access_token",
    "keys", "key", "keyfile", "key_file",
    # Two-factor / backup codes
    "backup_codes", "backup_code", "backupcodes", "backupcode",
    "2fa_backup", "2fa_codes", "2fa", "mfa_codes", "mfa_backup",
    "recovery_codes", "recovery_code", "recoverycodes", "otp_backup",
    "authenticator_backup",
    # Blockchain / crypto wallets
    "mnemonic", "seed_phrase", "seed", "wallet_seed", "bip39",
    "ethereum_key", "bitcoin_key", "crypto_keys", "crypto_seed",
    "wallet_backup", "wallet_keys", "ledger_seed", "trezor_seed",
    "metamask_seed", "blockchain_keys",
    # SSH / GPG
    "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
    "id_rsa_old", "id_ecdsa_old",
    "gpg_key", "pgp_key", "pgp_private",
    # Cloud / infra
    "aws_credentials", "gcp_credentials", "azure_credentials",
    "terraform_vars", "vault_token",
    # Miscellaneous
    "notes_passwords", "keepass_export", "bitwarden_export",
    "1password_export", "lastpass_export",
})

# Extensions to strictly exclude from collection to prevent false positives
# and bloated acquisitions (binaries, caches, images, prefetch, etc.)
EXCLUDED_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".pf", ".obj", ".o", ".pyc", ".pyo", ".class",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".riv", ".webp",
    ".ttf", ".woff", ".woff2", ".eot", ".mp3", ".mp4", ".wav", ".avi",
    ".zip", ".tar", ".gz", ".7z", ".iso", ".vmdk", ".pdb", ".lib",
    ".map", ".node", ".bin",
})

# Filename glob patterns (applied to the full filename including extension)
SENSITIVE_GLOB_PATTERNS: tuple[str, ...] = (
    "*.pem", "*.key", "*.p12", "*.pfx", "*.ppk", "*.jks",
    "*.crt", "*.cer", "*.der",
    "wallet.dat", "*.wallet",
    "*.env", ".env", ".env.*",
    "id_rsa*", "id_ecdsa*", "id_ed25519*", "id_dsa*",
    "*.ovpn", "*.vpn",
    "*.kdbx", "*.kdb",   # KeePass databases
)

# Regex applied to the full lowercase filename (stem + extension)
# Uses word/delimiter boundaries to prevent substrings like AB6EC2FA or buffalo matching.
SENSITIVE_FILENAME_RE = re.compile(
    r"(?:^|[_\-\.\s])("
    r"passwords?|passwd|creds?|credentials?|secrets?|private[_\-\.]?keys?|api[_\-\.]?keys?|"
    r"tokens?|auth[_\-\.]?tokens?|bearer[_\-\.]?tokens?|access[_\-\.]?tokens?|"
    r"backup[_\-\.]?codes?|recovery[_\-\.]?codes?|2fa|mfa|"
    r"mnemonics?|seed[_\-\.]?phrases?|crypto[_\-\.]?seeds?|wallet[_\-\.]?seeds?|bip39|"
    r"crypto[_\-\.]?keys?|bitcoin|ethereum|blockchain|"
    r"wallet|ledger|trezor|metamask|id_rsa|id_ecdsa|id_ed25519|"
    r"keystore|keychain"
    r")(?=[_\-\.\s\d]|$)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Directories to scan – ordered by forensic priority
# ---------------------------------------------------------------------------

def _get_scan_roots() -> list[Path]:
    """Return ordered list of filesystem roots to scan for sensitive files."""
    roots: list[Path] = []

    user_profile = os.environ.get("USERPROFILE", "")
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    home = Path.home()

    priority_dirs = []

    if user_profile:
        up = Path(user_profile)
        priority_dirs += [
            up / "Desktop",
            up / "Documents",
            up / "Downloads",
            up / "OneDrive",
            up / ".ssh",
            up / ".gnupg",
            up / "AppData" / "Roaming" / "gnupg",
        ]

    if appdata:
        priority_dirs += [
            Path(appdata),
        ]

    # Home directory (may overlap with user_profile on Windows but useful on
    # other OS)
    priority_dirs.append(home)

    # Drive roots (enumerate fixed drives for a wider sweep in full profile)
    try:
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter_idx in range(26):
            if bitmask & (1 << letter_idx):
                letter = chr(65 + letter_idx)
                drive = Path(f"{letter}:\\")
                # Only scan the user's home portion of system drives to keep
                # scope manageable; non-system drives are scanned fully.
                if letter in ("C",):
                    if user_profile:
                        priority_dirs.append(Path(user_profile))
                else:
                    priority_dirs.append(drive)
    except Exception:
        pass

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[Path] = []
    for p in priority_dirs:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            deduped.append(p)

    return deduped


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

def _is_sensitive_file(path: Path) -> bool:
    """Return True if *path* looks like a sensitive credential / key file."""
    # Immediately skip excluded extensions (executables, prefetch, media, etc.)
    if path.suffix.lower() in EXCLUDED_EXTENSIONS:
        return False

    stem_lower = path.stem.lower()

    # Exact stem match (e.g. passwords.txt, backupcodes.txt, id_rsa)
    if stem_lower in SENSITIVE_FILENAME_STEMS:
        return True

    # Glob-pattern match (e.g. *.env, *.pem, *.key, id_rsa*)
    for pattern in SENSITIVE_GLOB_PATTERNS:
        if path.match(pattern):
            return True

    # Regex match against full filename with delimiter boundaries
    name_lower = path.name.lower()
    if SENSITIVE_FILENAME_RE.search(name_lower):
        return True

    return False


def _sha256_file(path: Path, chunk: int = 65536) -> str:
    """Compute SHA-256 of *path*; return empty string on error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                block = f.read(chunk)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


def _file_modified_iso(path: Path) -> str:
    try:
        ts = path.stat().st_mtime
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

@register_collector("sensitive_files")
class SensitiveFileCollector(CollectorBase):
    """
    Forensic collector for credential, key, secret, and backup-code files.

    Performs a targeted sweep of the filesystem to locate files that contain
    or are likely to contain sensitive authentication material.  Each matched
    file is:

      1. Recorded in the structured manifest (path, size, SHA-256, timestamps).
      2. Copied into the evidence directory if it is below MAX_FILE_SIZE_BYTES.
      3. Flagged as "oversized" and catalogued (but not copied) if it exceeds
         the size cap.

    The parsed output includes a JSON inventory of all matches with their
    forensic attributes, suitable for AI analysis and report inclusion.
    """

    module_id: str = "sensitive_files"
    module_name: str = "Sensitive File Finder"
    category: ArtifactCategory = ArtifactCategory.USER_ACTIVITY
    source_locations: list[str] = ["User profile directories", "SSH / GPG dirs", "Drive roots"]
    required_privileges: str = "user"

    def _collect(self, result: CollectionResult) -> CollectionResult:
        evidence_subdir = self.evidence_dir / "sensitive_files"
        evidence_subdir.mkdir(parents=True, exist_ok=True)

        parsed_subdir = self.parsed_dir / "sensitive_files"
        parsed_subdir.mkdir(parents=True, exist_ok=True)

        scan_roots = _get_scan_roots()
        inventory: list[dict] = []
        total_copied_bytes = 0
        seen_paths: set[str] = set()

        for root in scan_roots:
            if not root.exists():
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                    # Prune directories we should never descend into
                    dirnames[:] = [
                        d for d in dirnames
                        if d.lower() not in {
                            "$recycle.bin", "windows", "winnt",
                            "system volume information", "programdata",
                            "program files", "program files (x86)",
                            "__pycache__", "node_modules", ".git",
                            "site-packages", "cases", ".venv", "venv",
                            ".cache", ".npm", ".cargo", ".rustup",
                        }
                    ]

                    for filename in filenames:
                        file_path = Path(dirpath) / filename
                        path_key = str(file_path).lower()

                        if path_key in seen_paths:
                            continue
                        seen_paths.add(path_key)

                        if not _is_sensitive_file(file_path):
                            continue

                        try:
                            stat = file_path.stat()
                        except (OSError, PermissionError):
                            continue

                        file_size = stat.st_size
                        sha256 = _sha256_file(file_path)
                        modified = _file_modified_iso(file_path)

                        entry: dict = {
                            "filename": file_path.name,
                            "original_path": str(file_path),
                            "file_size_bytes": file_size,
                            "sha256": sha256,
                            "last_modified": modified,
                            "copied": False,
                            "skipped_reason": "",
                        }

                        if file_size > MAX_FILE_SIZE_BYTES:
                            entry["skipped_reason"] = (
                                f"File exceeds size limit "
                                f"({file_size:,} bytes > {MAX_FILE_SIZE_BYTES:,} bytes)"
                            )
                            result.warnings.append(
                                f"Oversized sensitive file skipped (catalogued only): "
                                f"{file_path} ({file_size / 1024 / 1024:.2f} MB)"
                            )
                            inventory.append(entry)
                            continue

                        if total_copied_bytes + file_size > MAX_TOTAL_COPY_BYTES:
                            entry["skipped_reason"] = "Aggregate copy cap reached"
                            result.warnings.append(
                                f"Aggregate copy cap reached; file catalogued only: {file_path}"
                            )
                            inventory.append(entry)
                            continue

                        # Copy the file into evidence
                        evidence = self.copy_file(file_path, evidence_subdir,
                                                  evidence_id=f"sensitive_{sha256[:8]}")
                        if evidence:
                            total_copied_bytes += file_size
                            entry["copied"] = True
                            entry["acquired_path"] = evidence.acquired_path
                            result.acquired_files.append(evidence)
                        else:
                            entry["skipped_reason"] = "Copy failed (access denied or OS error)"

                        inventory.append(entry)

            except (OSError, PermissionError) as e:
                result.warnings.append(f"Walk error at {root}: {e}")

        # Persist the structured JSON inventory
        inventory_evidence = self.save_json(
            inventory, "sensitive_files_inventory.json", parsed_subdir,
            evidence_id="sensitive_files_inventory"
        )
        if inventory_evidence:
            result.parsed_output_files.append(inventory_evidence.acquired_path)

        # Persist a human-readable summary
        summary_lines = [
            "POLARIS Sensitive File Collector - Forensic Inventory",
            "=" * 60,
            f"Scan completed: {get_iso_timestamp()}",
            f"Total matches found : {len(inventory)}",
            f"Files copied        : {sum(1 for e in inventory if e.get('copied'))}",
            f"Files oversized     : {sum(1 for e in inventory if 'size limit' in e.get('skipped_reason', ''))}",
            f"Files access-denied : {sum(1 for e in inventory if 'denied' in e.get('skipped_reason', ''))}",
            f"Total bytes copied  : {total_copied_bytes:,}",
            "",
            "File Size Limit     : {:,} bytes ({:.1f} MB per file)".format(
                MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_BYTES / 1024 / 1024
            ),
            "Aggregate Copy Cap  : {:,} bytes ({:.0f} MB total)".format(
                MAX_TOTAL_COPY_BYTES, MAX_TOTAL_COPY_BYTES / 1024 / 1024
            ),
            "",
            "MATCHED FILES",
            "-" * 60,
        ]

        for entry in inventory:
            status = "COPIED" if entry.get("copied") else f"SKIPPED ({entry.get('skipped_reason', '')})"
            summary_lines.append(
                f"[{status}] {entry['filename']}"
                f"  |  {entry['file_size_bytes']:,} bytes"
                f"  |  {entry['original_path']}"
            )
            if entry.get("sha256"):
                summary_lines.append(f"         SHA-256: {entry['sha256']}")
            if entry.get("last_modified"):
                summary_lines.append(f"         Modified: {entry['last_modified']}")
            summary_lines.append("")

        summary_evidence = self.save_text(
            "\n".join(summary_lines),
            "sensitive_files_summary.txt",
            evidence_subdir,
            evidence_id="sensitive_files_summary",
        )
        if summary_evidence:
            result.acquired_files.append(summary_evidence)

        if inventory:
            result.status = CollectionStatus.SUCCESS
        else:
            result.status = CollectionStatus.SUCCESS
            result.warnings.append("No sensitive files matching the search criteria were found.")

        return result
