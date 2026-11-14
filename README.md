# GreenLeaf Microfinance – Secure Lending Portal

Security demo for **GreenLeaf Microfinance Cooperative** (fictional client): a hardened Ubuntu server, a mock Flask lending portal, vulnerability fixes (IDOR, SQL injection), live log detection, and a public deployment.

| # | Task | Status |
|---|------|--------|
| 1 | Set up and harden Ubuntu VM for security testing | ✅ Done (this README) |
| 2 | Develop a mock microfinance lending portal (Flask) | ⏳ Next |
| 3 | Identify and fix broken access control (IDOR) | ⏳ |
| 4 | Detect and mitigate SQL injection in loan search | ⏳ |
| 5 | Integrate detection script and alert dashboard | ⏳ |
| 6 | Deploy to PythonAnywhere and handover package | ⏳ |

---

## Task 1 – Ubuntu 22.04 VM Hardening

**Goal:** a VM that only accepts SSH **key** logins, blocks every port except 22/80/443, bans brute-force attackers automatically, and is administered by a non-root user.

### Hardening summary

| Control | Setting | Why |
|---|---|---|
| OS updates | `apt full-upgrade`, timezone set for accurate logs | Known vulnerabilities are patched before anything is exposed |
| Admin account | `gladmin`, member of `sudo`; root login disabled | Every admin action is traceable to a named user; `root` is never a login target |
| Firewall (UFW) | default **deny** incoming; allow **22, 80, 443** only | Anything not explicitly needed is unreachable, even if a service starts by mistake |
| SSH | `PasswordAuthentication no`, `PubkeyAuthentication yes`, `AuthenticationMethods publickey`, `PermitRootLogin no`, `AllowUsers gladmin`, `MaxAuthTries 3` | Password guessing becomes impossible; only one named account may log in |
| fail2ban | `sshd` jail, 3 failures in 10 min → 10 min ban | Brute-force sources are blocked automatically and every ban is logged |

### Lab setup

| Item | Value |
|---|---|
| Host | Windows 11, VirtualBox 7.x |
| Guest OS | **Ubuntu 22.04.5 LTS** (Jammy), kernel 6.8, hostname `ubanto` |
| Accounts | `anaszia` – installer account, console only (blocked from SSH by `AllowUsers`) · `gladmin` – SSH admin |
| Network | Adapter 1: **NAT** → `enp0s3`, `10.0.2.15` (internet for updates) · Adapter 2: **Host-only** ("VirtualBox Host-Only Ethernet Adapter") → `enp0s8` |
| VM IP | **`192.168.56.10`** (static, set with NetworkManager) |
| Host IP seen by the VM | `192.168.56.1` |

> **Why WSL2 was not used:** WSL2 shares the Windows network stack and does not behave like a real server for firewall and SSH testing. A VirtualBox VM also gives a proper snapshot as a deliverable.

> **Why the order differs slightly from the brief:** the admin user and SSH key are created **before** password login is disabled, and port 22 is allowed **before** UFW is enabled. Doing it the other way round locks you out of the server.

---

### Step 1 – VM network, SSH server and all updates

#### 1.1 VirtualBox network adapters (VM powered off)

**Settings → Network**
- Adapter 1 – Enabled, attached to **NAT**, cable connected
- Adapter 2 – Enabled, attached to **Host-only Adapter**, name **VirtualBox Host-Only Ethernet Adapter** (`192.168.56.1` on Windows), cable connected

The host had two host-only adapters (`192.168.56.1` and `#2` on `192.168.152.4`). The `#2` adapter did not pass traffic, so the standard one was used. Checked on Windows with:

```powershell
Get-NetIPConfiguration | Format-Table InterfaceDescription, IPv4Address
```

![VM settings](screenshots/task1/01-vm-settings.png)

#### 1.2 Bring up both interfaces and give the VM a fixed IP

```bash
sudo nmcli device connect enp0s3                 # NAT / internet
ping -c 3 google.com

sudo nmcli connection add type ethernet ifname enp0s8 con-name hostonly \
  ipv4.method manual ipv4.addresses 192.168.56.10/24 connection.autoconnect-priority 10
sudo nmcli connection up hostonly
ip -4 addr                                       # enp0s3 = 10.0.2.15, enp0s8 = 192.168.56.10
```

A static address means the IP never changes between reboots, so every SSH command and firewall test in this guide uses `192.168.56.10`.

#### 1.3 Install the SSH server

Ubuntu Desktop does not ship an SSH server, so it is installed and enabled at boot:

```bash
sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
systemctl status ssh
```

From Windows: `ping 192.168.56.10`, then `ssh anaszia@192.168.56.10` (accept the host fingerprint with `yes`).

#### 1.4 Apply all updates

```bash
sudo apt update
sudo apt full-upgrade -y
sudo apt autoremove -y
sudo timedatectl set-timezone Asia/Karachi   # correct timestamps in logs (needed in Task 5)
sudo reboot
```

After reboot:

```bash
lsb_release -a                 # Ubuntu 22.04.5 LTS
uname -r                       # 6.8.0-149-generic
apt list --upgradable          # "Listing... Done" and nothing else = fully patched
```

> The login banner offers an upgrade to 24.04. It was **deliberately not applied** – the brief specifies Ubuntu 22.04.

![OS version and updates](screenshots/task1/02-os-updates.png)

---

### Step 2 – Non-root sudo admin and SSH key

#### 2.1 Create the admin user (on the VM)

```bash
sudo adduser gladmin              # strong password – still needed for sudo
sudo usermod -aG sudo gladmin
id gladmin                        # groups include 27(sudo)
su - gladmin -c 'sudo whoami'     # prints: root
```

![Admin user](screenshots/task1/03-admin-user.png)

#### 2.2 Generate an Ed25519 key pair (Windows PowerShell)

```powershell
ssh-keygen -t ed25519 -C "gladmin@greenleaf-vm"
# C:\Users\<you>\.ssh\id_ed25519      PRIVATE key – stays on this PC, never shared or committed
# C:\Users\<you>\.ssh\id_ed25519.pub  PUBLIC key  – goes on the server
# protected with a passphrase
```

Ed25519 is used because it is modern, fast and much shorter than RSA for the same security.

#### 2.3 Install the public key on the VM (password login still enabled at this point)

```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh gladmin@192.168.56.10 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

`authorized_keys` is the server's list of keys allowed to log in as `gladmin`; `700`/`600` permissions are required or sshd ignores the file.

#### 2.4 Test the key before going further

```powershell
ssh gladmin@192.168.56.10
# Enter passphrase for key 'C:\Users\...\.ssh\id_ed25519':   <- key accepted, no account password asked
```

![Key generation and copy](screenshots/task1/04-ssh-key-copy.png)

---

### Step 3 – Firewall: allow only 22, 80, 443

```bash
sudo ufw status                          # Status: inactive
sudo ufw default deny incoming           # block everything coming in...
sudo ufw default allow outgoing          # ...but let the server reach the internet (updates)
sudo ufw allow 22/tcp  comment 'SSH'     # allowed FIRST so the SSH session is not cut off
sudo ufw allow 80/tcp  comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw logging low
sudo ufw enable                          # answer y
sudo ufw status verbose
```

Result:

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
22/tcp        ALLOW IN    Anywhere          # SSH
80/tcp        ALLOW IN    Anywhere          # HTTP
443/tcp       ALLOW IN    Anywhere          # HTTPS
22/tcp (v6)   ALLOW IN    Anywhere (v6)     # SSH
80/tcp (v6)   ALLOW IN    Anywhere (v6)     # HTTP
443/tcp (v6)  ALLOW IN    Anywhere (v6)     # HTTPS
```

![UFW status](screenshots/task1/05-ufw-status.png)

#### 3.1 Prove that other ports are blocked

Two throw-away web servers on the VM – one on an allowed port, one on a blocked port:

```bash
cd /tmp
sudo -v
sudo python3 -m http.server 80 &       # allowed by UFW
python3 -m http.server 8080 &          # NOT allowed by UFW
```

From Windows:

```powershell
curl.exe -m 5 http://192.168.56.10/          # HTML directory listing        -> port 80 reachable
curl.exe -m 5 http://192.168.56.10:8080/     # curl: (28) Connection timed out -> blocked by UFW
```

Both servers were running, but only the one on the allowed port was reachable – the firewall is doing its job. Cleanup: `sudo pkill -f http.server`.

![Port test](screenshots/task1/06-port-test.png)

---

### Step 4 – Harden SSH to key-only authentication

#### 4.1 Edit the main config, as the brief requires

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo sed -i -E 's/^#?\s*PubkeyAuthentication\s.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i -E 's/^#?\s*PasswordAuthentication\s.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i -E 's/^#?\s*KbdInteractiveAuthentication\s.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
sudo sed -i -E 's/^#?\s*PermitRootLogin\s.*/PermitRootLogin no/' /etc/ssh/sshd_config
grep -E '^(PubkeyAuthentication|PasswordAuthentication|KbdInteractiveAuthentication|PermitRootLogin)' /etc/ssh/sshd_config
```

Each `sed` finds the setting (commented out with `#` or not) and replaces the whole line with the hardened value.

#### 4.2 Add a drop-in that nothing can override

Ubuntu 22.04's `sshd_config` begins with `Include /etc/ssh/sshd_config.d/*.conf`, and sshd keeps the **first** value it reads. A file such as `50-cloud-init.conf` containing `PasswordAuthentication yes` would silently re-enable passwords. This file is named `00-…` so it is read first and wins.

```bash
ls /etc/ssh/sshd_config.d/        # check what is already there
sudo tee /etc/ssh/sshd_config.d/00-hardening.conf > /dev/null <<'EOF'
# GreenLeaf VM - SSH hardening (Task 1)
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
AllowUsers gladmin
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
EOF
```

Commented copy: [`hardening/sshd/00-hardening.conf`](hardening/sshd/00-hardening.conf).

| Setting | Effect |
|---|---|
| `AuthenticationMethods publickey` | The only accepted login method is a key |
| `PasswordAuthentication no`, `KbdInteractiveAuthentication no` | No password prompts of any kind |
| `PermitRootLogin no` | `root` cannot log in over SSH |
| `AllowUsers gladmin` | Only `gladmin` may log in; `anaszia` is console-only |
| `MaxAuthTries 3`, `LoginGraceTime 30` | Fewer guesses per connection, half-open logins dropped after 30 s |
| `ClientAliveInterval 300` / `CountMax 2` | Idle sessions closed after 10 minutes |
| `X11Forwarding no`, `AllowAgentForwarding no` | Features the server doesn't need are switched off |

#### 4.3 Test, then restart

```bash
sudo sshd -t && echo "CONFIG OK"     # syntax check – restart only if it passes
sudo systemctl restart ssh
sudo sshd -T | grep -Ei '^(pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|permitrootlogin|allowusers|maxauthtries) '
```

`sshd -T` prints the **effective** configuration, so it proves what the server really enforces:

```
permitrootlogin no
maxauthtries 3
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
allowusers gladmin
authenticationmethods publickey
```

![Effective SSH config](screenshots/task1/07-sshd-effective-config.png)

#### 4.4 Prove it (existing session kept open, tests run in a new PowerShell window)

```powershell
ssh gladmin@192.168.56.10
#   Enter passphrase for key ...   -> logged in with the key

ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password gladmin@192.168.56.10
#   gladmin@192.168.56.10: Permission denied (publickey).

ssh root@192.168.56.10
#   root@192.168.56.10: Permission denied (publickey).
```

The server no longer even offers password as a method – `(publickey)` is the only one listed.

![Key login works](screenshots/task1/08-ssh-key-login.png)
![Password and root login refused](screenshots/task1/09-ssh-password-denied.png)

---

### Step 5 – fail2ban: automatic brute-force bans

#### 5.1 Install and configure

```bash
sudo apt install -y fail2ban
sudo tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
# GreenLeaf VM - fail2ban (Task 1)
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
maxretry = 3
findtime = 10m
bantime  = 10m

[sshd]
enabled  = true
port     = 22
filter   = sshd[mode=aggressive]
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
EOF
sudo fail2ban-client -t                    # OK: configuration test is successful
sudo systemctl enable --now fail2ban
sudo systemctl restart fail2ban
sudo systemctl status fail2ban --no-pager  # active (running)
sudo fail2ban-client status sshd
```

- `jail.local` is used instead of editing `jail.conf`, because package updates overwrite `jail.conf`.
- `mode=aggressive` also counts key-only failures (`Connection closed by authenticating user … [preauth]`), which is what attacks look like once passwords are off.
- The 10-minute ban is deliberately short for a test VM; production would use longer, increasing bans.

#### 5.2 Simulate a brute-force attack

The host (`192.168.56.1`) bans itself during this test, so the checks and the unban are run from the **VirtualBox console** (logged in locally as `anaszia`).

From Windows – logins with a username that does not exist:

```powershell
1..5 | ForEach-Object { ssh -o ConnectTimeout=5 -o BatchMode=yes hacker@192.168.56.10 }
# first attempts:  hacker@192.168.56.10: Permission denied (publickey).
# after the limit: ssh: connect to host 192.168.56.10 port 22: Connection timed out   <- banned
```

![Attack from host](screenshots/task1/11-fail2ban-attack.png)

#### 5.3 Evidence (VirtualBox console)

```bash
sudo fail2ban-client status sshd                             # Banned IP list: 192.168.56.1
sudo grep -E 'Found|Ban' /var/log/fail2ban.log | tail -n 10
sudo grep 'Invalid user hacker' /var/log/auth.log | tail -n 5
sudo iptables -L f2b-sshd -n                                 # REJECT rule for 192.168.56.1 while banned
```

Recorded result:

```
2026-11-15 01:55:56,452 fail2ban.filter  [2857]: INFO    [sshd] Found 192.168.56.1 - 2026-11-15 01:55:56
...      (9 "Found" lines in total)
2026-11-15 01:55:57,069 fail2ban.actions [2857]: NOTICE  [sshd] Ban 192.168.56.1

Nov 15 01:55:56 ubanto sshd[2876]: Invalid user hacker from 192.168.56.1 port 51201
Nov 15 01:55:56 ubanto sshd[2878]: Invalid user hacker from 192.168.56.1 port 51202
Nov 15 01:55:56 ubanto sshd[2880]: Invalid user hacker from 192.168.56.1 port 51203
Nov 15 01:55:56 ubanto sshd[2882]: Invalid user hacker from 192.168.56.1 port 51204
```

The ban was placed within one second of the attack and lifted automatically after 10 minutes (`Total banned: 1`, `Currently banned: 0` afterwards). Manual unban if needed:

```bash
sudo fail2ban-client set sshd unbanip 192.168.56.1
```

![fail2ban status](screenshots/task1/10-fail2ban-status.png)
![fail2ban log](screenshots/task1/12-fail2ban-log.png)

---

### Step 6 – Verify everything and take the snapshot

#### 6.1 One-command verification

[`hardening/verify.sh`](hardening/verify.sh) checks every control above and prints PASS/FAIL. Copy it to the VM and run it:

```powershell
# Windows, from the repository folder
scp .\hardening\verify.sh gladmin@192.168.56.10:~/
```

```bash
# VM
sudo ADMIN_USER=gladmin bash ~/verify.sh | tee ~/verify-output.txt
```

```powershell
# Windows – bring the report back into the repo
scp gladmin@192.168.56.10:~/verify-output.txt .\evidence\
```

Expected last line: `23 passed, 0 failed`. (Ports like `127.0.0.53:53` and `127.0.0.1:631` in the listening list are local-only desktop services and cannot be reached from outside.)

![verify.sh output](screenshots/task1/13-verify-script.png)

#### 6.2 Reboot test

```bash
sudo reboot
# after boot:
ip -4 addr                           # 192.168.56.10 still there
systemctl is-active ssh fail2ban     # active / active
sudo ufw status | head -1            # Status: active
```

#### 6.3 VM snapshot

VirtualBox → VM → **Snapshots** → **Take** → name `task1-hardened-baseline`, description: *"Ubuntu 22.04.5 fully updated; static IP 192.168.56.10; UFW 22/80/443; SSH key-only (gladmin); fail2ban sshd jail."*
This is the clean starting point for Tasks 2–5 and the rollback point if anything breaks.

![VirtualBox snapshot](screenshots/task1/14-vm-snapshot.png)

---

### Automated alternative – `harden.sh`

[`hardening/harden.sh`](hardening/harden.sh) performs the updates, admin user, UFW, SSH hardening and fail2ban steps in one run, so the VM can be rebuilt identically:

```bash
sudo ADMIN_USER=gladmin bash hardening/harden.sh
# or install the key in the same run:
sudo ADMIN_USER=gladmin PUBKEY_FILE=/tmp/id_ed25519.pub bash hardening/harden.sh
```

Safety features:
- **Refuses to disable password login if the admin has no public key** (prevents lock-out).
- Backs up `sshd_config` and runs `sshd -t` before restarting; restores the backup if the test fails.
- Allows port 22 before enabling UFW.
- Safe to run more than once.

---

### Mentor checklist → evidence

| Mentor checks | Evidence |
|---|---|
| VM boots without errors and SSH accepts only key authentication | Step 4.4 (key works, password + root refused), `sshd -T` output (4.3), reboot test (6.2) |
| UFW allows 22, 80, 443 and denies all others | `ufw status verbose` (default deny incoming), port test 3.1 (8080 timed out while running) |
| fail2ban is active and logs blocked attempts | `fail2ban.log` Found/Ban lines, `auth.log` invalid-user lines, `fail2ban-client status sshd` (5.3) |
| README contains all commands and proof screenshots | This file + `screenshots/task1/` + `evidence/verify-output.txt` |

### Troubleshooting (problems hit while building this)

| Problem | Cause / fix |
|---|---|
| VM had only `enp0s3`, no host-only address | Adapter 2 was not attached → power off, set Adapter 2 to Host-only, start again |
| `ping 192.168.56.x` → "Destination host unreachable" | VM was on the `#2` host-only adapter, which didn't pass traffic → switched to the standard adapter (`192.168.56.1`) and set a static IP with `nmcli` |
| `enp0s3` lost its IP (no internet) | `sudo nmcli device connect enp0s3` |
| `sudo` in PowerShell says "Sudo is disabled on this machine" | That is Windows' own sudo – Linux commands must run in the VM (prompt `user@ubanto:~$`, not `PS C:\>`) |
| SSH times out after the attack test | The host is banned (expected) → unban from the VirtualBox console or wait 10 minutes |
| Locked out of SSH | VirtualBox console as `anaszia`: `sudo rm /etc/ssh/sshd_config.d/00-hardening.conf && sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config && sudo systemctl restart ssh` |
| `apt list --upgradable` shows packages "kept back" | Ubuntu phased updates – they install automatically in a few days; `sudo apt full-upgrade` again later |

### Repository layout

```
greenleaf-secure-lending-portal/
├── README.md                      # this guide
├── docs/
│   └── task1-submission-note.md   # short note: what I did and why
├── hardening/
│   ├── harden.sh                  # automated hardening
│   ├── verify.sh                  # PASS/FAIL evidence report
│   ├── sshd/00-hardening.conf     # SSH drop-in config (commented)
│   └── fail2ban/jail.local        # fail2ban sshd jail (commented)
├── evidence/
│   └── verify-output.txt          # saved output of verify.sh
└── screenshots/task1/             # proof images (see SHOTLIST.md)
```

---

*Intern: Anas Zia · Client: GreenLeaf Microfinance Cooperative (fictional) · Ezitech case study CS-501*
