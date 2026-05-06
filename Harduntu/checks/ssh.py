from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List
import os
import pwd
import grp
import stat
import shutil

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover
    Console = None
    Table = None

SSH_CONFIG_PATH = Path("/etc/ssh/sshd_config")
SSH_CONFIG_D_DIR = Path("/etc/ssh/sshd_config.d")


@dataclass
class SshdConfigEntry:
    directive: str
    value: str
    source_file: str
    line_number: int

    def __post_init__(self):
        self.directive = self.directive.strip()
        self.value = self.value.strip()

    @property
    def line(self) -> str:
        return f"{self.directive} {self.value}".strip()


def _read_text(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return stream.read()
    except FileNotFoundError:
        return ""
    except PermissionError as exc:
        raise RuntimeError(f"Unable to read {path}: {exc}") from exc


def _strip_comment(line: str) -> str:
    stripped = line.rstrip("\n")
    if stripped.lstrip().startswith("#"):
        return ""
    if "#" not in stripped:
        return stripped
    return stripped.split("#", 1)[0].rstrip()


def parse_sshd_config_text(content: str, source_file: str) -> List[SshdConfigEntry]:
    entries: List[SshdConfigEntry] = []

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        stripped = _strip_comment(raw_line).strip()
        if not stripped:
            continue

        parts = stripped.split(None, 1)
        directive = parts[0]
        value = parts[1] if len(parts) > 1 else ""
        entries.append(
            SshdConfigEntry(
                directive=directive,
                value=value,
                source_file=source_file,
                line_number=line_number,
            )
        )

    return entries


def find_sshd_config_d_files() -> List[Path]:
    if SSH_CONFIG_D_DIR.is_dir():
        return sorted(
            [path for path in SSH_CONFIG_D_DIR.iterdir() if path.is_file()],
            key=lambda path: path.name,
        )
    return []


def load_sshd_config() -> Dict[str, Any]:
    entries: List[SshdConfigEntry] = []

    if SSH_CONFIG_PATH.exists():
        entries.extend(
            parse_sshd_config_text(_read_text(SSH_CONFIG_PATH), str(SSH_CONFIG_PATH))
        )

    included_paths = find_sshd_config_d_files()
    for included_path in included_paths:
        entries.extend(
            parse_sshd_config_text(_read_text(included_path), str(included_path))
        )

    effective: Dict[str, SshdConfigEntry] = {}
    for entry in entries:
        effective[entry.directive] = entry

    return {
        "entries": entries,
        "effective": effective,
        "included_files": [str(path) for path in included_paths],
        "base_file": str(SSH_CONFIG_PATH),
    }


def build_sshd_config_table(entries: Iterable[SshdConfigEntry]) -> List[Dict[str, str]]:
    return [
        {
            "Directive": entry.directive,
            "Value": entry.value,
            "Source": entry.source_file,
            "Line": str(entry.line_number),
        }
        for entry in entries
    ]


def serialize_sshd_config(entries: Iterable[SshdConfigEntry]) -> str:
    lines = [entry.line for entry in entries]
    return "\n".join(lines) + ("\n" if lines else "")


def update_sshd_config_entry(
    entries: List[SshdConfigEntry],
    directive: str,
    value: str,
    source_file: str | None = None,
) -> List[SshdConfigEntry]:
    directive = directive.strip()
    value = value.strip()

    for entry in reversed(entries):
        if entry.directive == directive:
            entry.value = value
            return entries

    source = source_file or str(SSH_CONFIG_PATH)
    entries.append(
        SshdConfigEntry(
            directive=directive,
            value=value,
            source_file=source,
            line_number=len(entries) + 1,
        )
    )
    return entries


def _print_table(entries: Iterable[SshdConfigEntry]) -> None:
    if Console is None or Table is None:
        for entry in entries:
            print(
                f"{entry.directive:<30} {entry.value:<40} {entry.source_file}:{entry.line_number}"
            )
        return

    console = Console()
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Directive", style="bold")
    table.add_column("Value")
    table.add_column("Source", overflow="fold")
    table.add_column("Line", justify="right")

    for entry in entries:
        table.add_row(entry.directive, entry.value, entry.source_file, str(entry.line_number))

    console.print(table)


def open_sshconfig() -> Dict[str, Any]:
    config = load_sshd_config()
    included_files = config["included_files"]

    if SSH_CONFIG_D_DIR.exists():
        if included_files:
            print("Additional sshd_config.d files found:")
            for path in included_files:
                print(f"  - {path}")
        else:
            print("sshd_config.d directory exists but contains no config files is currently present in it.")
    else:
        print("No sshd_config.d directory found.")

    if not config["entries"]:
        print("No active sshd configuration entries found.")
        return config

    print("\nParsed SSHD config entries (comments stripped):")
    _print_table(config["entries"])
    print("\nActive directives (last value wins):")
    _print_table(config["effective"].values())

    return config


def check_sshdconfig_permissions() -> bool:
    for path in [SSH_CONFIG_PATH] + find_sshd_config_d_files():
        print(f"Checking permissions according to SSH 5.1.1 permission on configuration file {path}...")
        current_file_mode = stat.S_IMODE(os.stat(path).st_mode)
        curent_file_owner = pwd.getpwuid(os.stat(path).st_uid).pw_name
        current_file_group = grp.getgrgid(os.stat(path).st_gid).gr_name

        # Check for permissions - should be 0600 (owner read/write only)
        if format(current_file_mode, "04o") != "0600":
            print(f"Incorrect permissions for {path}: expected 0600, found {format(current_file_mode, '04o')}")
        else:
            print(f"Permissions for {path} are properly set: 0600")
        # Check for ownership - should be root
        if curent_file_owner != "root":
            print(f"Incorrect owner for {path}: expected root, found {curent_file_owner}")
        else:
            print(f"Owner for {path} is properly set: root")
        # Check for group ownership - should be root or sshd
        if current_file_group != "root":
            print(f"Incorrect group for {path}: expected root, found {current_file_group}")
        else:
            print(f"Group for {path} is properly set: root")
    print(f"{pwd.getpwuid(os.stat(SSH_CONFIG_PATH).st_uid).pw_name}:{grp.getgrgid(os.stat(SSH_CONFIG_PATH).st_gid).gr_name}")
    return True


def sshdconfig_permissions_remediation() -> bool:
    for path in [SSH_CONFIG_PATH] + find_sshd_config_d_files():
        print(f"Remediating permissions for {path}...")
        # Initiate a backup for the file before making changes
        backup_path = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, backup_path)

        # Add to include more fail safes as it's root running
        try:
            os.chmod(path, 0o600)
            os.chown(path, 0, 0)  # Set owner to root (uid 0) and group to root (gid 0)
            print(f"Permissions for {path} set to 0600 and ownership set to root:root")
        except Exception as exc:
            print(f"Failed to remediate permissions for {path}: {exc}")
    return True
