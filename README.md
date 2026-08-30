# Linux Server Hardener

**Version 1.0.1** · Author: Danny · [danny.hategekimana@trac.africa](mailto:danny.hategekimana@trac.africa)

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
sudo ./harden.sh --profile trac
sudo ./harden.sh --profile trac --set FIREWALL_ROLE=unifi
sudo ./harden.sh --profile web-server
sudo ./harden.sh --profile hardened --non-interactive
sudo ./harden.sh --modules updates,ssh,firewall --dry-run
sudo ./harden.sh --set FS_TMP_NOEXEC=true --set USER_TIGHTEN_HOMES=false
```

| Mode | Effect |
| --- | --- |
| *(default)* | Interactive menu, then apply after confirmation |
| `--audit` | Zero changes. Root not required when files are readable |
| `--dry-run` | Print the exact plan; write nothing |
| `--apply` | Apply selected modules |
| `--rollback` | Restore a previous backup session |
| `--report` | Print the latest generated report |
| `--profile NAME` | `basic`, `server`, `web-server`, `database-server`, `hardened`, `trac` |
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
| `org.conf` | TRAC site defaults (AllowUsers, sourced CIDRs, Wazuh, fail2ban) |
| `ssh.conf` | SSH drop-in settings |
| `firewall.conf` | Backend, restricted vs discovery ports, role (`generic`/`unifi`/`rpki`) |
| `mfa.conf` | TOTP MFA (off by default) |
| `wazuh.conf` | Manager address only — no keys |
| `auditd.conf` | auditd rules path and log rotation |
| `defense.conf` | Active-defense flags (blacklist, sticky /tmp, faillock, service disable) |

Profiles in `profiles/*.conf` enable module sets and override a few role-specific knobs (for example, web-server allows 80/443 and does not disable IP forwarding).

## Customize defenses

Interactive runs stop on a **defense options** screen after you pick modules. Each control is listed as ON or OFF. Toggle by number, then press Enter. Apply only runs after that list and the final confirmation.

Nothing is applied quietly. Every selected control is printed again as `Will apply` or `Skipped (turned off)` when the module runs.

Non-interactive example:

```bash
sudo ./harden.sh --profile server --non-interactive \
  --set USER_TIGHTEN_HOMES=true \
  --set KERNEL_BLACKLIST_USB=false \
  --set FS_TMP_NOEXEC=false
```

Home-directory tightening, USB-storage blacklist, `/tmp` noexec, IPv6 disable, and system-account nologin start **OFF** unless you turn them on.

## Modules

| ID | What it does |
| --- | --- |
| `updates` | Refresh index, security updates, unattended-upgrades on Debian/Ubuntu |
| `users` | Lock empty passwords, create AllowUsers, nologin extras — no deletions |
| `passwords` | login.defs aging, pwquality (minlen 8, mixed class), faillock lockout |
| `sudo` | Audit + `visudo -cf` validated drop-in |
| `ssh` | Drop-in hardening, `sshd -T` verify, second-session warning |
| `pam_mfa` | Optional SSH TOTP via PAM |
| `firewall` | UFW / firewalld / nftables — sourced UI ports, open discovery ports |
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

## TRAC site profile

`sudo ./harden.sh --profile trac` applies the organization controls:

- SSH: `PermitRootLogin no`, password + pubkey, no keyboard-interactive, `MaxAuthTries 3`, `AllowUsers sys-trac danny`
- Creates `sys-trac` and `danny` if missing (password prompted, never logged, never sent to Slack)
- Extra human accounts not in AllowUsers can be set to nologin; accounts are never deleted
- UFW: deny inbound, allow outbound; SSH/UI only from `10.0.0.0/8`, `41.242.140.0/22`, `196.223.240.0/21`
- `--set FIREWALL_ROLE=unifi` or `rpki` for sourced admin ports vs open AP/discovery ports
- Wazuh agent to `10.10.11.40`, auditd `execve` as root, Fail2ban sshd `maxretry=4` / `bantime=15m`
- Debian/Ubuntu `unattended-upgrades` via `20auto-upgrades` (no interactive `dpkg-reconfigure`)

Keep the first SSH session open, test a second login, and keep console access before restarting sshd.

## Wazuh

Wazuh is optional and assumes a **remote manager**. The menu separates install, configure, register, and validate. Set `WAZUH_REGISTRATION_PASSWORD` in the environment if you register non-interactively; it is never written to disk by the toolkit. The agent name defaults to the hostname. When enabled, `/var/log/audit/audit.log` is added as a localfile and the agent is restarted.

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

Copyright © 2026 Danny (danny.hategekimana@trac.africa).
