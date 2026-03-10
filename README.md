# P2P Chat — Rust · X25519 · AES-256-GCM

A minimal encrypted peer-to-peer terminal chat.  
No servers, no accounts — two computers connect directly over TCP.  
Every message is **end-to-end encrypted** before it leaves your machine.

---

## Security

| What | Why |
|------|-----|
| **X25519 ECDH** | Fresh ephemeral key pair generated on every connection |
| **AES-256-GCM** | Authenticated encryption — each message is encrypted + integrity-checked |
| **SHA-256 KDF** | Derives the 256-bit AES key from the ECDH shared secret |
| **12-byte random nonce** | Unique per message — nonce reuse is impossible |

**What this protects:**
- Traffic interception is useless — everything on the wire is random-looking base64
- ISPs, routers, VPN providers cannot read message content
- If someone tampers with a message in transit, the GCM authentication tag fails and the message is dropped with a warning

**What this does NOT protect:**
- IP addresses are visible to each other and to your ISPs — this is direct P2P
- No identity verification (no PKI/certificates) — if you are unsure who you are talking to, agree on a shared secret through a separate channel first

---

## Requirements

- Windows 10 / 11
- [Rust](https://rustup.rs/) — installed with a single executable

---

## Installing Rust (one-time setup)

1. Go to **https://rustup.rs**
2. Download and run **`rustup-init.exe`**
3. Press **`1`** → Enter (default installation)
4. Wait ~2–5 minutes
5. **Close and reopen** PowerShell / CMD

Verify:
```
rustc --version
cargo --version
```
Both should print version numbers.

---

## Building

```powershell
cd C:\path\to\p2p_chat
cargo build --release
```

First build takes ~2–3 minutes (downloads and compiles dependencies).  
Output binary: `target\release\p2p_chat.exe`

---

## Usage

### Step 1 — Find your local IP

```
ipconfig
```
Look for **IPv4 Address** — usually `192.168.x.x`.

---

### Computer A — Host (waits for connection)

```powershell
.\target\release\p2p_chat.exe host --port 7777 --name Alice
```

### Computer B — Guest (connects to host)

```powershell
.\target\release\p2p_chat.exe connect --addr 192.168.1.10 --port 7777 --name Bob
```

Replace `192.168.1.10` with the actual IP of Computer A.

---

## Controls

| Key / Command | Action |
|---------------|--------|
| Type text + **Enter** | Send message |
| **Backspace** | Delete last character |
| `/quit` or `/q` + Enter | Leave the chat gracefully |
| **Ctrl-C** | Leave the chat immediately |

---

## Quick test on one computer (two PowerShell windows)

**Window 1:**
```powershell
cargo run --release -- host --name Alice
```

**Window 2:**
```powershell
cargo run --release -- connect --addr 127.0.0.1 --name Bob
```

Type in either window — messages appear in both, with no duplication.

---

## Chat over the Internet (different networks)

Forward the port on the **host's router**:

- External port: `7777` → Host's internal IP → Internal port: `7777` → Protocol: TCP

Find the host's external IP at https://whatismyip.com and share it with the guest.

Guest connects:
```powershell
.\p2p_chat.exe connect --addr <EXTERNAL_IP> --port 7777 --name Bob
```

---

## Windows Firewall

If the connection is refused, Windows Firewall may be blocking the port.

Open PowerShell **as Administrator** and run:
```powershell
netsh advfirewall firewall add rule name="P2P Chat" dir=in action=allow protocol=TCP localport=7777
```

Or via GUI: Windows Defender Firewall → Advanced Settings → Inbound Rules → New Rule → Port → TCP 7777 → Allow.

---

## Project structure

```
p2p_chat/
├── Cargo.toml        # Dependencies
└── src/
    └── main.rs       # All source code (~300 lines)
```

### Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime (TCP + concurrent tasks) |
| `crossterm` | Raw-mode terminal input, cursor control |
| `x25519-dalek` | X25519 Diffie-Hellman key exchange |
| `aes-gcm` | AES-256-GCM authenticated encryption |
| `sha2` | SHA-256 key derivation |
| `base64` | Wire encoding for ciphertext blobs |
| `rand` | Cryptographic RNG for nonces and keypairs |
| `serde` / `serde_json` | Message serialisation |
| `clap` | CLI argument parsing |
| `chrono` | Message timestamps |

---

## How it works

```
  Alice                              Bob
  ─────                              ───
  X25519 keygen                      X25519 keygen
  ── send pubkey_A ─────────────────►
                   ◄───────────────── send pubkey_B
  ECDH(secret_A, pubkey_B)           ECDH(secret_B, pubkey_A)
         └── SHA-256 ──► AES key     └── SHA-256 ──► AES key  (identical!)

  Terminal enters raw mode (crossterm)
  Keystrokes echoed manually into a shared input buffer

  On incoming message:
    lock(input_buffer)
    → erase input line from screen
    → print decrypted message
    → redraw input line          ← no duplication, atomic operation
    unlock(input_buffer)

  On Enter:
    take input_buffer contents
    → clear screen line
    → print formatted message locally
    → encrypt(nonce, JSON) → base64 → send over TCP
```

---
Made by Weksar (Korbut Serhii)