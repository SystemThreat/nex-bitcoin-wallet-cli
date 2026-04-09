# NEX Bitcoin Wallet CLI

A post-quantum self-custody command-line wallet for **NEX** — a Bitcoin fork with ML-DSA-65 signatures, SHA-256d mining, 5-minute blocks, and 100 NEX block rewards.

Single-file Swift tool that generates keys, signs transactions locally, and talks to a `nexd` node over JSON-RPC. No dependencies beyond the macOS system frameworks (`Foundation`, `CommonCrypto`, `Security`).

```
nex-wallet v1.0.0  —  Post-Quantum Self-Custody
Address:  nex1z... (Bech32m, Witness v2)
Chain:    NEX (Bitcoin fork, SHA-256d)
Sig:      ML-DSA-65 (FIPS 204)
```

---

## Features

- 🔐 **BIP-39 24-word seed phrase** — compatible with the NEX PWA wallet and Ledger app
- 🌐 **Witness v2 Bech32m addresses** (`nex1z...`) — post-quantum ready
- ✍️ **Local transaction signing** — seeds never leave your machine
- 📦 **Built-in coin control** — skips immature coinbase + mempool-spent UTXOs automatically
- 🔎 **Live balance queries** via node RPC (`scantxoutset`)
- 📲 **Terminal QR codes** for receive addresses
- 🔑 **macOS Keychain storage** by default (or portable mode via `NEX_WALLET_DIR` env var)
- ✅ **Pre-broadcast validation** with `testmempoolaccept` — see why a tx would fail before sending
- 🧪 **27 cryptographic self-tests** (`nex-wallet selftest`)
- 🧰 **Single-file build** — one `swiftc` command, no package manager, no dependencies

---

## Install

### Option A — Build from source
```bash
git clone https://github.com/SystemThreat/nex-bitcoin-wallet-cli.git
cd nex-bitcoin-wallet-cli
swiftc -O -o nex-wallet nex-wallet.swift
```
Requires macOS 14+ and Swift 5.9+ (comes with Xcode 15 or Command Line Tools).

### Option B — Use the pre-built binary
A pre-compiled `nex-wallet` binary for Apple Silicon macOS is included in the repository. Verify and run:
```bash
./nex-wallet selftest
```

### BIP-39 word list
The wallet needs a BIP-39 English word list at `~/.nex-wallet/bip39_english.txt` (one word per line, 2048 words). On first run, the wallet will print instructions if the file is missing.

You can download a standard copy from [bitcoin/bips BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt):
```bash
mkdir -p ~/.nex-wallet
curl -o ~/.nex-wallet/bip39_english.txt \
  https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
```

---

## Quick start

```bash
# 1. Configure node connection
nex-wallet config --node https://your-nex-node.example.com/rpc \
                  --user nex --pass YOUR_RPC_PASSWORD

# 2. Create a new wallet (writes down 24-word seed phrase)
nex-wallet create

# 3. Check node + wallet status
nex-wallet info

# 4. View your receive address with QR code
nex-wallet receive

# 5. Check balance
nex-wallet balance

# 6. Send NEX
nex-wallet send --to nex1z... --amount 10.5
```

---

## Commands

| Command | Purpose |
|---|---|
| `create` | Generate a new wallet — prints 24-word seed phrase once |
| `restore` | Restore wallet from an existing 24-word phrase |
| `import` | Import seed phrase (flexible parser — accepts numbered lists, comma-separated, or line-separated) |
| `address` | Show the receive address |
| `receive` | Show the receive address with a terminal QR code |
| `balance` | Query balance from the configured node |
| `send` | Build, sign locally, and broadcast a transaction |
| `claim` | Import and broadcast a BTC snapshot claim *(coming soon)* |
| `export` | Export the public key or seed phrase (interactive, requires confirmation) |
| `backup` | Re-display the seed phrase (requires confirmation) |
| `wipe` | Destroy all stored keys — requires typing `RESET` |
| `info` | Show wallet and node status |
| `selftest` | Run all cryptographic self-tests |
| `config` | Save node connection settings |
| `help` | Full command reference |

### `send` flags
```
--to <nex1z...>   Destination address (required)
--amount <NEX>    Amount in NEX (e.g., 10.5)
```

### `config` flags
```
--node <URL>      nexd JSON-RPC endpoint
--user <name>     RPC username
--pass <password> RPC password
```

---

## Portable mode

By default, the wallet stores keys in the macOS Keychain at `~/.nex-wallet/`. For a fully portable setup (e.g., on a removable encrypted drive), set the `NEX_WALLET_DIR` environment variable to a directory. In portable mode:

- Seeds are stored as files (instead of Keychain)
- All data lives under `$NEX_WALLET_DIR`
- Plug the drive into any Apple Silicon Mac and the wallet works
- Nothing is written to the host machine

```bash
# Example: wallet on an encrypted USB drive
export NEX_WALLET_DIR=/Volumes/MYDRIVE/nex-wallet-data
nex-wallet create
```

File permissions are automatically set to `0600` (owner read/write only) for all sensitive files.

---

## Key storage

### Default (non-portable) mode

| Data | Location | Protection |
|---|---|---|
| BIP-39 master seed | macOS Keychain (`com.nex.wallet.cli`) | Encrypted at rest by macOS |
| 24-word mnemonic | macOS Keychain | Encrypted at rest by macOS |
| Public key hash | `~/.nex-wallet/pubkey_hash.bin` | File permissions `0600` |
| Node config | `~/.nex-wallet/config.json` | File permissions `0600` |

### Portable mode (`NEX_WALLET_DIR` set)

| Data | Location | Protection |
|---|---|---|
| BIP-39 master seed | `$NEX_WALLET_DIR/master_seed.bin` | File permissions `0600` — use encrypted volume |
| 24-word mnemonic | `$NEX_WALLET_DIR/mnemonic.txt` | File permissions `0600` — use encrypted volume |
| Public key hash | `$NEX_WALLET_DIR/pubkey_hash.bin` | File permissions `0600` |
| Node config | `$NEX_WALLET_DIR/config.json` | File permissions `0600` |

**Important**: in portable mode, the wallet does NOT encrypt the seed files itself. Store them on an encrypted volume (APFS FileVault, VeraCrypt, LUKS) or equivalent.

---

## Cryptography

| Primitive | Algorithm |
|---|---|
| Entropy → mnemonic | SHA-256 checksum + BIP-39 wordlist |
| Mnemonic → seed | PBKDF2-HMAC-SHA512 (2048 iterations, salt `"mnemonic"`) |
| Seed → address program | `SHA-256(seed ‖ "NEX-CLI-KEY-0")` (32-byte hash) |
| Address encoding | Bech32m (BIP-350), witness version 2, HRP `nex` |
| Transaction witness | Path B seed-spend: raw 64-byte seed as witness item |
| Signature (future) | ML-DSA-65 (FIPS 204) — requires PQClean via bridging header |

### Path B vs. Path A witness

NEX supports two spending paths for witness v2:

**Path A — ML-DSA-65 signature** (full post-quantum):
```
witness = [signature_3309_bytes, pubkey_1952_bytes]
validation: SHA-256(pubkey) == program && verify_mldsa65(sig, pubkey)
```

**Path B — Seed recovery** (used by this CLI wallet):
```
witness = [seed_64_bytes]
validation: SHA-256(seed ‖ "NEX-CLI-KEY-0") == program
```

Path B is a simpler "seed-spend" fallback that this CLI implements today. Path A requires linking the PQClean library via a Swift bridging header and is planned for a future release.

---

## Compatibility

The CLI wallet uses the **same key derivation** as the NEX PWA wallet:

- ✅ Same BIP-39 mnemonic format (24 words)
- ✅ Same PBKDF2-HMAC-SHA512 seed derivation
- ✅ Same `SHA256(seed ‖ "NEX-CLI-KEY-0")` address derivation
- ✅ Same Path B witness spending

A seed phrase created in the PWA wallet produces the **exact same address** in the CLI, and vice versa. You can import the same seed into both wallets.

---

## Security notes

- **Never share your 24-word seed phrase.** Anyone with it controls your funds.
- **Back up the phrase on paper or metal**, never on a networked device.
- **Verify the destination address** in every `send` — the wallet shows it in the confirmation prompt.
- **RPC credentials are stored in plain JSON** at `config.json`. Keep the file permission at `0600`. Do not commit it anywhere.
- **The `nex-wallet` binary is not code-signed.** macOS Gatekeeper may block it on first run; allow it in System Settings → Privacy & Security if needed.
- **`wipe` is irreversible.** It deletes all Keychain entries and the wallet directory.

---

## Project layout

```
.
├── nex-wallet.swift    # Single-file Swift source (~68 KB, ~1,900 lines)
├── nex-wallet          # Pre-built arm64 macOS binary (optional)
├── README.md           # This file
├── LICENSE             # MIT License
└── .gitignore          # Excludes config.json, wallet data, build artifacts
```

---

## Related projects

- **NEX node (full consensus + wallet)** — [github.com/SystemThreat/NEX](https://github.com/SystemThreat/NEX)
- **NEX PWA wallet** — in the NEX repo under `wallet/`
- **Untraceablex block explorer** — [untraceablex.com](https://untraceablex.com)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**David Otero**  
[Distributed Ledger Technologies](https://www.distributedledgertechnologies.com)
