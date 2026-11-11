# GTFOBins Auto-Checker + Extended Linux Privilege Escalation Scanner

Self-contained shell script that scans a Linux system for privilege escalation vectors — cross-referenced against all **435 GTFOBins** entries, plus extended system misconfiguration checks. No dependencies, no internet needed on target.

> **Note:** This tool is read-only — it never exploits anything automatically. It only suggests commands you can run manually.

## Usage

```bash
chmod +x gtfo-check.sh
./gtfo-check.sh
```

## What it scans

### GTFOBins checks

| Check | Command | Description |
|-------|---------|-------------|
| SUID | `find / -perm -4000` | Binaries that run as owner (usually root) |
| SGID | `find / -perm -2000` | Binaries that run as group |
| Capabilities | `getcap -r /` | Binaries with Linux capabilities |
| Sudo | `sudo -n -l` | Sudo-allowed binaries (needs NOPASSWD or cached creds) |
| Writable files | `find / -writable` | Files owned by other users that you can write to |

### Extended privilege escalation checks

| Check | What it looks for |
|-------|-------------------|
| Kernel version | Prints kernel info + suggests `searchsploit` / known CVEs |
| Cron jobs | Writable cron scripts, readable crontabs, systemd timers |
| Writable PATH dirs | Directories in `$PATH` you can write to (command hijacking) |
| Group membership | docker, lxd, disk, adm, shadow, video group membership |
| /etc/passwd & shadow | Writable passwd, readable shadow, empty passwords, hashes in passwd |
| NFS exports | `no_root_squash` shares |
| Systemd services | Writable `.service` files (service hijacking) |
| LD_PRELOAD | sudo env_keep, LD_PRELOAD/LD_LIBRARY_PATH set, writable lib paths |
| Credential hunting | History files, SSH keys, `.env` files, config files with passwords |
| Internal services | Listening ports, root processes |
| Writable /etc | Interesting writable files in `/etc` (passwd, shadow, sudoers, profile, ld.so.preload, etc.) |
| Filesystem mounts | Missing `nosuid`/`noexec`, unmounted fstab partitions |

## Output

For each finding, the tool shows:
- **What was found** (binary, file, misconfiguration)
- **Why it matters** (context and risk)
- **Suggested command** (copy-paste ready, but never executed automatically)

### Example

```
══════════════════════════════════════════
  SUID Binaries (-perm -4000)
══════════════════════════════════════════
  ✓ python3 (shell,file-read,file-write)
    Path: /usr/bin/python3
    Exploit:
      python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

══════════════════════════════════════════
  Interesting Group Memberships
══════════════════════════════════════════
  ✗ Member of 'docker' group
    Full root access via Docker
    Suggestion:
      docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh

══════════════════════════════════════════
  12 findings total
  ├─ 2 GTFOBins exploitable
  ├─ 1 run-as-other-user (lateral movement)
  ├─ 5 extended privesc checks
  └─ 4 other interesting files
  Reference: https://gtfobins.github.io/
══════════════════════════════════════════
```

## Data source

All 435 entries from [GTFOBins](https://gtfobins.github.io/) are embedded in the script — no network access or external files required.
