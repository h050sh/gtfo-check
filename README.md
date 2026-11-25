# privcheck

Linux privilege escalation scanner. Cross-references **435 GTFOBins** entries and checks for common system misconfigurations — all in a single, self-contained shell script. No dependencies, no internet needed on target.

> **Read-only** — never exploits anything automatically. Only suggests commands you can run manually.

## Usage

```bash
chmod +x privcheck.sh
./privcheck.sh
```

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Print recon context (kernel, mounts, root processes, all capabilities) |
| `--no-color` | Disable ANSI colors (useful when piping to a file) |
| `-h`, `--help` | Show help |

| Variable | Description |
|----------|-------------|
| `LHOST=10.10.14.1` | Attacker IP substituted into reverse-shell / upload commands |
| `LPORT=4444` | Attacker port |

## What it scans

### GTFOBins

Finds binaries on the system that match known [GTFOBins](https://gtfobins.github.io/) entries, across five vectors:

| Vector | How | Description |
|--------|-----|-------------|
| SUID | `find / -perm -4000` | Binaries that run as owner (usually root) |
| SGID | `find / -perm -2000` | Binaries that run as group |
| Capabilities | `getcap -r /` | Binaries with Linux capabilities |
| Sudo | `sudo -n -l` | Sudo-allowed binaries (needs NOPASSWD or cached creds) |
| Writable files | `find / -writable` | Files owned by other users that you can write to |

### System misconfigurations

| Check | What it looks for |
|-------|-------------------|
| Kernel version | Prints kernel info, suggests `searchsploit` / known CVEs |
| Cron jobs | Writable cron scripts, readable crontabs, systemd timers |
| Writable PATH dirs | Directories in `$PATH` you can write to (command hijacking) |
| Group membership | docker, lxd, disk, adm, shadow, video group membership |
| /etc/passwd & shadow | Writable passwd, readable shadow, empty passwords, hashes in passwd |
| NFS exports | `no_root_squash` shares |
| Systemd services | Writable `.service` files (service hijacking) |
| LD_PRELOAD | sudo env_keep, LD_PRELOAD/LD_LIBRARY_PATH set, writable lib paths |
| Credentials | History files, SSH keys, `.env` files, config files with passwords |
| Internal services | Listening ports bound to localhost (MySQL, Redis, Postgres, etc.) |
| Writable /etc | Interesting writable files in `/etc` (passwd, shadow, sudoers, profile, ld.so.preload, etc.) |
| Filesystem mounts | Missing `nosuid`/`noexec`, unmounted fstab partitions |
| Recently modified | Files changed in the last 3 days in common directories |

## Output

Findings are grouped by severity (CRITICAL, HIGH, MEDIUM, INFO). Each one shows what was found, why it matters, and a copy-paste ready command.

```
╔══════════════════════════════════════════════════════╗
║  privcheck — privilege escalation report              ║
╚══════════════════════════════════════════════════════╝
  user: www-data   host: target   findings: 12

─── CRITICAL — instant root ───

  [1] python3 SUID (shell,file-read,file-write)
    Path: /usr/bin/python3
      $ python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

─── HIGH — likely root with one more step ───

  [2] Member of 'docker' group
    Full root access via Docker
      $ docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 CRITICAL  — start here
  1 HIGH
  5 MEDIUM
  4 INFO
  ref: https://gtfobins.github.io/
```

A "COPY-PASTE" block at the end collects all suggested commands for quick use.

## Data source

All 435 entries from [GTFOBins](https://gtfobins.github.io/) are embedded in the script — no network access or external files required.
