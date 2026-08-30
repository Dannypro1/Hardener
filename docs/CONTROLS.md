# Control mapping

Recommendations in this toolkit are aligned with widely used guidance. They are
**not** a certified CIS or NIST assessment. Use vendor benchmarks for formal audits.

| Area | Implementation | Primary references |
| --- | --- | --- |
| OS lifecycle / updates | `modules/updates.sh` | CIS 1.9, CIS Control 7 |
| Filesystem mounts | `modules/filesystem.sh` (sticky /tmp, /dev/shm remount) | CIS 1.1 |
| AIDE | `modules/integrity.sh` | CIS 1.4, CIS Control 3 |
| Time sync | `modules/time_sync.sh` | CIS 1.3, NIST AU-8 |
| Unnecessary services | `modules/services.sh` | CIS 2.2, CIS Control 4 |
| Network sysctl | `modules/sysctl.sh` | CIS 3.1, CIS 3.3 |
| Host firewall | `modules/firewall.sh` (sourced UI, open discovery) | CIS 3.5, CIS Control 12 |
| auditd | `modules/auditd.sh` (identity + root execve) | CIS 4.1, NIST AU-2 |
| Logging | `modules/logging.sh` | CIS 4.2, CIS 4.3 |
| SSH | `modules/ssh.sh` | CIS 5.1, NIST IA-2 |
| PAM / passwords | `modules/passwords.sh`, `modules/pam_mfa.sh` | CIS 5.3, NIST IA-5, IA-2(1) |
| sudo | `modules/sudo.sh` | CIS 5.2 |
| Users | `modules/users.sh` | CIS 5.4, NIST IA-2 |
| File permissions | `modules/permissions.sh` | CIS 6.1 |
| Fail2ban | `modules/fail2ban.sh` | CIS Control 13 |
| Wazuh | `modules/wazuh.sh` | CIS Control 8, NIST AU-6 |
| Backups / rollback | `lib/backup.sh`, `lib/rollback.sh` | CIS Control 11 |

## Intentional non-goals

- No automatic user deletion
- No automatic disable of unknown systemd units
- No automatic IPv6 disable
- No automatic `noexec` remounts on `/tmp` (`FS_TMP_NOEXEC=false`)
- No password authentication disable by default
- No MFA enablement without confirmation
- No Wazuh registration keys in source or logs
- No passwords copied from ubuntu/root or sent to Slack
