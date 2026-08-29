# Linux Server Hardener

A modular Bash toolkit that audits and applies host hardening on Ubuntu, Debian, Fedora, CentOS, RHEL, Rocky Linux, and AlmaLinux.

It is built for real servers — including remote SSH sessions — and prefers **safety, idempotency, backups, validation, rollback, and lockout prevention** over aggressive one-size-fits-all policies.

## Features

- Interactive module menu and predefined profiles
- Audit, dry-run, apply, rollback, and report modes
- Cross-family package and service abstraction (`apt` / `dnf` / `yum`, systemd)
- SSH drop-in hardening with `sshd -t` before reload
- Optional PAM TOTP MFA for SSH only
- Firewall support for UFW, firewalld, and nftables with SSH-session protection
- auditd, Fail2ban, AIDE, and optional Wazuh agent integration
- Timestamped backups and targeted rollback
- Scored compliance report mapped to CIS / NIST guidance (see [docs/CONTROLS.md](docs/CONTROLS.md))
- Active defenses on apply (not audit-only): kernel module blacklist, sticky `/tmp`, hardened `/dev/shm`, network sysctl, faillock, empty-password lock, disable of telnet/rsh/NIS

## Requirements

- Bash 4+
- Root for apply / rollback (audit and dry-run work without root where the OS allows)
- A supported distribution, or a close derivative (`ID_LIKE` is honored)

## Quick start

```bash
git clone <this-repo> server-hardener
cd server-hardener
chmod +x harden.sh install.sh uninstall.sh
sudo ./harden.sh
```

Install onto the host (copies the toolkit to `/opt/server-hardener` and links `harden`):

```bash
sudo ./install.sh
sudo harden
```

## CLI

```text
sudo ./harden.sh
sudo ./harden.sh --audit
sudo ./harden.sh --dry-run
sudo ./harden.sh --apply
sudo ./harden.sh --rollback
sudo ./harden.sh --report
sudo ./harden.sh --profile web-server
sudo ./harden.sh --profile hardened --non-interactive
sudo ./harden.sh --modules updates,ssh,firewall --dry-run
```

| Mode | Effect |
| --- | --- |
| *(default)* | Interactive menu, then apply after confirmation |
| `--audit` | Zero changes. Root not required when files are readable |
| `--dry-run` | Print the exact plan; write nothing |
| `--apply` | Apply selected modules |
| `--rollback` | Restore a previous backup session |
| `--report` | Print the latest generated report |
| `--profile NAME` | `basic`, `server`, `web-server`, `database-server`, `hardened` |
| `--non-interactive` | No prompts; uses profile/module defaults |
| `--yes` | Skip the final apply prompt (still refuses MFA / user-deletion dangers) |

## Workflow

```text
Detect OS and environment
        ↓
Administrator confirms OS
        ↓
Select modules or profile
        ↓
Pre-security audit
        ↓
Show configuration plan
        ↓
Confirmation
        ↓
Timestamped backups
        ↓
Apply + validate each module
        ↓
Post-hardening audit + report
```

OS detection always reads `/etc/os-release` and asks for confirmation unless `--non-interactive` is set. The tool never assumes the selected profile matches the running system.

## Safety rules

- Configuration files are backed up before modification.
- SSH is changed via `/etc/ssh/sshd_config.d/` (or a marked block) — `sshd_config` is never overwritten.
- `sshd -t` must succeed before SSH is reloaded. Failed validation restores the backup.
- The current SSH user and port are treated as protected. `AllowUsers` / `DenyUsers` / password-auth-off that would lock the session are blocked unless you confirm.
- Firewall rules always allow the current SSH port before default-deny is enabled.
- MFA and dangerous user actions require explicit confirmation. Empty-password accounts can be locked; users are never deleted.
- Unknown services are never disabled automatically.
- Mount options (`noexec`, `nosuid`) are recommended, not forced.
- IPv6 is never disabled automatically.
- Secrets (passwords, TOTP seeds, Wazuh registration keys, private keys) are never stored in git and are redacted from logs.
- The host is never rebooted unless `AUTO_REBOOT=true`.

## Configuration

Defaults live in `config/`:

| File | Purpose |
| --- | --- |
| `hardening.conf` | Global flags, essential services, reboot policy |
| `ssh.conf` | SSH drop-in settings |
| `firewall.conf` | Backend, extra ports, default deny |
| `mfa.conf` | TOTP MFA (off by default) |
| `wazuh.conf` | Manager address only — no keys |
| `auditd.conf` | auditd rules path and log rotation |
| `defense.conf` | Active-defense flags (blacklist, sticky /tmp, faillock, service disable) |

Profiles in `profiles/*.conf` enable module sets and override a few role-specific knobs (for example, web-server allows 80/443 and does not disable IP forwarding).

## Modules

| ID | What it does |
| --- | --- |
| `updates` | Refresh index, security updates, EOL / reboot reporting |
| `users` | Lock empty passwords, umask/TMOUT, 0750 homes — no deletions |
| `passwords` | login.defs aging, pwquality, faillock lockout |
| `sudo` | Audit + `visudo -cf` validated drop-in |
| `ssh` | Drop-in hardening, algorithm set optional |
| `pam_mfa` | Optional SSH TOTP via PAM |
| `firewall` | UFW / firewalld / nftables |
| `services` | Auto-disable telnet/rsh/NIS/TFTP; confirm avahi/cups |
| `filesystem` | Sticky `/tmp`, remount `/dev/shm` nodev,nosuid,noexec |
| `permissions` | Well-defined modes on shadow, sudoers, SSH keys |
| `kernel` | Blacklist unused protocols/filesystems, disable core dumps, ASLR |
| `sysctl` | `/etc/sysctl.d/99-server-hardening.conf` |
| `auditd` | Baseline rules, no duplicate key soup |
| `logging` | journald / rsyslog / logrotate / log modes |
| `fail2ban` | SSH jail |
| `time_sync` | chrony / timesyncd / ntpd |
| `network` | SYN cookies, rp_filter, no redirects, host.conf (IPv6 stays on) |
| `integrity` | AIDE install / init / check |
| `wazuh` | Optional agent install, configure, register, validate |
| `compliance` | Unified scored audit |
| `backups` | Local session retention |

## PAM MFA

MFA is **off** until you enable it. The module installs the correct package (`libpam-google-authenticator` or `google-authenticator`), adds a marked block to `/etc/pam.d/sshd`, and never overwrites the whole PAM file.

Enroll users yourself with `google-authenticator`. This tool does not generate or print TOTP secrets.

Keep a console or out-of-band root session until a second SSH login with MFA succeeds.

## Wazuh

Wazuh is optional and assumes a **remote manager**. The menu separates install, configure, register, and validate. Set `WAZUH_REGISTRATION_PASSWORD` in the environment if you register non-interactively; it is never written to disk by the toolkit.

## Rollback

```bash
sudo ./harden.sh --rollback
```

Sessions are stored under `backups/<timestamp>/` with metadata describing each copied file. Rollback restores those paths only.

## Tests

```bash
cd server-hardener
bash tests/test_all.sh
```

Tests cover OS family detection, SSH lockout guards, firewall port selection, PAM package selection, and log redaction. They do not require root.

## Uninstall

```bash
sudo ./uninstall.sh
```

This removes `/opt/server-hardener`. It does **not** undo hardening. Roll back first if you need the previous configuration.

## License

MIT — see [LICENSE](LICENSE).
