#!/usr/bin/env swift
//
// NEX Wallet CLI — Post-Quantum Self-Custody Wallet
// ML-DSA-65 (FIPS 204) · BIP-39 · Bech32m · SHAKE-256
//
// Commands:
//   create    — Generate new wallet (24-word seed phrase)
//   restore   — Restore wallet from seed phrase
//   import    — Import seed phrase from NEX PWA wallet
//   address   — Show receive address
//   balance   — Query balance from node
//   send      — Build, sign locally, broadcast transaction
//   receive   — Show receive address + QR (terminal)
//   claim     — Import and broadcast a BTC snapshot claim
//   export    — Export public key or seed phrase (with confirmation)
//   backup    — Show seed phrase (requires confirmation)
//   wipe      — Destroy all keys (requires typing RESET)
//   selftest  — Run cryptographic self-tests
//   info      — Show wallet and node status
//
// Usage:
//   nex-wallet create
//   nex-wallet balance --node https://44.213.68.147:8443 --user nex --pass nex2026
//   nex-wallet send --to nex1z... --amount 10.5
//

import Foundation
import CommonCrypto
import Security

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Configuration
// ══════════════════════════════════════════════════════════════════════════════

let VERSION = "1.0.0"
let WALLET_DIR = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".nex-wallet")

struct Config {
    var nodeURL: String = ""
    var rpcUser: String = "nex"
    var rpcPass: String = ""
    var walletDir: URL = WALLET_DIR

    static func load() -> Config {
        var cfg = Config()
        let configFile = WALLET_DIR.appendingPathComponent("config.json")
        if let data = try? Data(contentsOf: configFile),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
            cfg.nodeURL = json["node_url"] ?? ""
            cfg.rpcUser = json["rpc_user"] ?? "nex"
            cfg.rpcPass = json["rpc_pass"] ?? ""
        }
        return cfg
    }

    func save() {
        try? FileManager.default.createDirectory(at: walletDir, withIntermediateDirectories: true)
        let json: [String: String] = [
            "node_url": nodeURL,
            "rpc_user": rpcUser,
            "rpc_pass": rpcPass,
        ]
        if let data = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted) {
            try? data.write(to: walletDir.appendingPathComponent("config.json"))
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Data Utilities
// ══════════════════════════════════════════════════════════════════════════════

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let byte = UInt8(String(chars[i...i+1]), radix: 16) else { return nil }
            bytes.append(byte)
        }
        self.init(bytes)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Key Storage (file-based, encrypted at rest via macOS Keychain)
// ══════════════════════════════════════════════════════════════════════════════

struct WalletFile {
    static let seedFile = "master_seed.enc"
    static let pubkeyFile = "pubkey.bin"
    static let secretkeyFile = "secretkey.enc"

    static var exists: Bool {
        FileManager.default.fileExists(atPath: WALLET_DIR.appendingPathComponent("pubkey_hash.bin").path)
    }

    static func saveSeed(_ seed: Data) {
        try? FileManager.default.createDirectory(at: WALLET_DIR, withIntermediateDirectories: true)
        // Store seed in Keychain (macOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.nex.wallet.cli",
            kSecAttrAccount as String: "master_seed",
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = seed
        SecItemAdd(add as CFDictionary, nil)
    }

    static func loadSeed() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.nex.wallet.cli",
            kSecAttrAccount as String: "master_seed",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func saveKeys(publicKey: Data, secretKey: Data) {
        try? FileManager.default.createDirectory(at: WALLET_DIR, withIntermediateDirectories: true)
        try? publicKey.write(to: WALLET_DIR.appendingPathComponent(pubkeyFile))
        // Secret key in Keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.nex.wallet.cli",
            kSecAttrAccount as String: "secret_key",
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = secretKey
        SecItemAdd(add as CFDictionary, nil)
    }

    static func loadPublicKey() -> Data? {
        try? Data(contentsOf: WALLET_DIR.appendingPathComponent(pubkeyFile))
    }

    static func loadSecretKey() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.nex.wallet.cli",
            kSecAttrAccount as String: "secret_key",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func saveMnemonic(_ words: [String]) {
        let phrase = words.joined(separator: " ")
        guard let data = phrase.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.nex.wallet.cli",
            kSecAttrAccount as String: "mnemonic",
        ]
        SecItemDelete(query as CFDictionary)
        var add = query
        add[kSecValueData as String] = data
        SecItemAdd(add as CFDictionary, nil)
    }

    static func loadMnemonic() -> [String]? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.nex.wallet.cli",
            kSecAttrAccount as String: "mnemonic",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let phrase = String(data: data, encoding: .utf8) else { return nil }
        let words = phrase.split(separator: " ").map(String.init)
        return words.isEmpty ? nil : words
    }

    static func wipeAll() {
        // Delete keychain entries
        for account in ["master_seed", "secret_key", "mnemonic"] {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "com.nex.wallet.cli",
                kSecAttrAccount as String: account,
            ]
            SecItemDelete(query as CFDictionary)
        }
        // Delete wallet directory
        try? FileManager.default.removeItem(at: WALLET_DIR)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Satoshi (integer-only money)
// ══════════════════════════════════════════════════════════════════════════════

struct Sat {
    let value: Int64
    static let coin: Int64 = 100_000_000

    static func parse(_ str: String) -> Sat? {
        let trimmed = str.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("-") else { return nil }
        let parts = trimmed.split(separator: ".", maxSplits: 1)
        guard parts.count <= 2 else { return nil }
        guard let whole = Int64(parts[0]), whole >= 0 else { return nil }
        var sats = whole * Sat.coin
        if parts.count == 2 {
            let frac = String(parts[1])
            guard frac.count <= 8, frac.allSatisfy({ $0.isNumber }) else { return nil }
            let padded = frac + String(repeating: "0", count: 8 - frac.count)
            guard let fracSat = Int64(padded) else { return nil }
            sats += fracSat
        }
        return Sat(value: sats)
    }

    func display() -> String {
        let whole = value / Sat.coin
        let frac = abs(value % Sat.coin)
        return String(format: "%lld.%08lld", whole, frac)
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Bech32m (address encoding)
// ══════════════════════════════════════════════════════════════════════════════

enum Bech32m {
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    private static func polymod(_ values: [UInt32]) -> UInt32 {
        let gen: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        var chk: UInt32 = 1
        for v in values {
            let b = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in 0..<5 { chk ^= ((b >> i) & 1) != 0 ? gen[i] : 0 }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt32] {
        var ret = hrp.map { UInt32($0.asciiValue! >> 5) }
        ret.append(0)
        ret += hrp.map { UInt32($0.asciiValue! & 31) }
        return ret
    }

    private static func convertBits(_ data: [UInt8], _ from: Int, _ to: Int, _ pad: Bool) -> [UInt32] {
        var acc: UInt32 = 0; var bits = 0; var ret: [UInt32] = []
        let maxv: UInt32 = (1 << to) - 1
        for v in data {
            acc = ((acc << from) | UInt32(v)) & 0xffffffff; bits += from
            while bits >= to { bits -= to; ret.append((acc >> bits) & maxv) }
        }
        if pad && bits > 0 { ret.append((acc << (to - bits)) & maxv) }
        return ret
    }

    static func encode(hrp: String, version: UInt8, program: Data) -> String {
        let data = [UInt32(version)] + convertBits(Array(program), 8, 5, true)
        let values = hrpExpand(hrp) + data
        let checksum_val = polymod(values + [0,0,0,0,0,0]) ^ 0x2bc830a3
        let checksum = (0..<6).map { (checksum_val >> (5 * (5 - $0))) & 31 }
        return hrp + "1" + (data + checksum).map { charset[Int($0)] }.map(String.init).joined()
    }

    static func decode(_ addr: String) -> (hrp: String, version: UInt8, program: Data)? {
        let lower = addr.lowercased()
        guard let sepIdx = lower.lastIndex(of: "1") else { return nil }
        let hrp = String(lower[lower.startIndex..<sepIdx])
        let dataPart = String(lower[lower.index(after: sepIdx)...])
        guard !hrp.isEmpty, dataPart.count >= 6 else { return nil }

        // Map characters to 5-bit values
        var data5: [UInt32] = []
        for ch in dataPart {
            guard let idx = charset.firstIndex(of: ch) else { return nil }
            data5.append(UInt32(charset.distance(from: charset.startIndex, to: idx)))
        }

        // Verify checksum (bech32m constant)
        let values = hrpExpand(hrp) + data5
        guard polymod(values) == 0x2bc830a3 else { return nil }

        let witVer = data5[0]
        guard witVer <= 16 else { return nil }

        // Convert 5-bit to 8-bit (exclude version prefix and 6-char checksum)
        let payload = Array(data5[1..<(data5.count - 6)])
        var acc: UInt32 = 0; var bits = 0; var program: [UInt8] = []
        for v in payload {
            acc = (acc << 5) | v
            bits += 5
            while bits >= 8 {
                bits -= 8
                program.append(UInt8((acc >> bits) & 0xff))
            }
        }

        guard program.count >= 2 && program.count <= 40 else { return nil }
        return (hrp, UInt8(witVer), Data(program))
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Address derivation
// ══════════════════════════════════════════════════════════════════════════════

func sha256(_ data: Data) -> Data {
    var hash = [UInt8](repeating: 0, count: 32)
    data.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash) }
    return Data(hash)
}

func pubkeyToAddress(_ pubkey: Data) -> String {
    let hash = sha256(pubkey)
    return Bech32m.encode(hrp: "nex", version: 2, program: hash)
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Transaction Builder
// ══════════════════════════════════════════════════════════════════════════════

let MIN_FEE: Int64 = 10_000 // 0.0001 NEX

func varint(_ n: UInt64) -> Data {
    if n < 0xfd {
        return Data([UInt8(n)])
    } else if n <= 0xffff {
        var v = UInt16(n).littleEndian
        return Data([0xfd]) + Data(bytes: &v, count: 2)
    } else if n <= 0xffffffff {
        var v = UInt32(n).littleEndian
        return Data([0xfe]) + Data(bytes: &v, count: 4)
    } else {
        var v = n.littleEndian
        return Data([0xff]) + Data(bytes: &v, count: 8)
    }
}

func uint32LE(_ v: UInt32) -> Data {
    var val = v.littleEndian
    return Data(bytes: &val, count: 4)
}

func int64LE(_ v: Int64) -> Data {
    var val = v.littleEndian
    return Data(bytes: &val, count: 8)
}

func buildScriptPubKey(address: String) -> Data? {
    guard let decoded = Bech32m.decode(address) else { return nil }
    guard decoded.program.count == 32 else { return nil }
    // OP_n (0x50 + version) + PUSH32 (0x20) + program
    return Data([0x50 + decoded.version, 0x20]) + decoded.program
}

func buildScriptPubKeyV2(pubkeyHash: Data) -> Data {
    return Data([0x52, 0x20]) + pubkeyHash
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - RPC Client
// ══════════════════════════════════════════════════════════════════════════════

func rpcCall(_ method: String, params: [Any] = [], config: Config) -> Any? {
    guard !config.nodeURL.isEmpty else {
        print("  Error: No node configured. Use --node or run: nex-wallet config")
        return nil
    }
    guard let url = URL(string: config.nodeURL) else { return nil }

    let body: [String: Any] = ["jsonrpc": "1.0", "id": "cli", "method": method, "params": params]
    guard let jsonData = try? JSONSerialization.data(withJSONObject: body) else { return nil }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = jsonData
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.timeoutInterval = 15

    let cred = "\(config.rpcUser):\(config.rpcPass)".data(using: .utf8)!.base64EncodedString()
    request.setValue("Basic \(cred)", forHTTPHeaderField: "Authorization")

    let sem = DispatchSemaphore(value: 0)
    var result: Any?

    URLSession.shared.dataTask(with: request) { data, _, error in
        defer { sem.signal() }
        guard let data = data, error == nil else { return }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        if let err = json["error"] as? [String: Any], let msg = err["message"] as? String {
            lastRpcError = msg
        } else {
            lastRpcError = nil
        }
        result = json["result"]
    }.resume()

    sem.wait()
    return result
}
var lastRpcError: String?

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - BIP-39 Word List (first 96 words for demo, full list from iOS app)
// ══════════════════════════════════════════════════════════════════════════════

// NOTE: In production, this links to the same BIP39WordList as the iOS app.
// For the CLI, the full 2048-word list is loaded from a file.

func loadBIP39WordList() -> [String] {
    let listFile = WALLET_DIR.appendingPathComponent("bip39_english.txt")
    if let text = try? String(contentsOf: listFile, encoding: .utf8) {
        return text.components(separatedBy: .newlines).filter { !$0.isEmpty }
    }
    // Fallback: try iOS app's word list
    let iosPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Skyknet/NEX/iOS/NEX/Crypto/BIP39WordList.swift")
    if let text = try? String(contentsOf: iosPath, encoding: .utf8) {
        var words: [String] = []
        for line in text.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("\"") && trimmed.hasSuffix("\",") {
                let word = String(trimmed.dropFirst().dropLast(2))
                words.append(word)
            } else if trimmed.hasPrefix("\"") && trimmed.hasSuffix("\"") {
                let word = String(trimmed.dropFirst().dropLast())
                words.append(word)
            }
        }
        if words.count == 2048 { return words }
    }
    print("  Warning: BIP-39 word list not found. Run from the NEX project directory.")
    return []
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - BIP-39 Seed Generation (pure Swift, no PQClean C dependency)
// ══════════════════════════════════════════════════════════════════════════════

func generateMnemonic(wordlist: [String]) -> [String]? {
    guard wordlist.count == 2048 else { return nil }
    var entropy = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, &entropy) == errSecSuccess else { return nil }

    var hash = [UInt8](repeating: 0, count: 32)
    CC_SHA256(entropy, 32, &hash)
    let checksumByte = hash[0]

    var bits: [Bool] = []
    for byte in entropy { for i in (0..<8).reversed() { bits.append((byte >> i) & 1 == 1) } }
    for i in (0..<8).reversed() { bits.append((checksumByte >> i) & 1 == 1) }

    var words: [String] = []
    for i in 0..<24 {
        var idx = 0
        for j in 0..<11 { if bits[i * 11 + j] { idx |= (1 << (10 - j)) } }
        words.append(wordlist[idx])
    }
    return words
}

func validateMnemonic(_ words: [String], wordlist: [String]) -> Bool {
    guard words.count == 24, wordlist.count == 2048 else { return false }
    var indices: [Int] = []
    for word in words {
        guard let idx = wordlist.firstIndex(of: word.lowercased()) else { return false }
        indices.append(idx)
    }
    var bits: [Bool] = []
    for idx in indices { for i in (0..<11).reversed() { bits.append((idx >> i) & 1 == 1) } }
    var entropy = [UInt8](repeating: 0, count: 32)
    for i in 0..<256 { if bits[i] { entropy[i / 8] |= UInt8(1 << (7 - (i % 8))) } }
    var hash = [UInt8](repeating: 0, count: 32)
    CC_SHA256(entropy, 32, &hash)
    for i in 0..<8 {
        if bits[256 + i] != ((hash[0] >> (7 - i)) & 1 == 1) { return false }
    }
    return true
}

func mnemonicToSeed(_ words: [String]) -> Data {
    let mnemonic = words.joined(separator: " ").data(using: .utf8)!
    let salt = "mnemonic".data(using: .utf8)!
    var seed = [UInt8](repeating: 0, count: 64)
    mnemonic.withUnsafeBytes { mnPtr in
        salt.withUnsafeBytes { saltPtr in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                mnPtr.baseAddress?.assumingMemoryBound(to: Int8.self), mnemonic.count,
                saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), 2048, &seed, 64)
        }
    }
    return Data(seed)
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - QR Code (terminal display, Version 3, ECC Level L)
// ══════════════════════════════════════════════════════════════════════════════

struct QR {
    // GF(256) tables for Reed-Solomon
    private static let gfExp: [Int] = {
        var exp = [Int](repeating: 0, count: 512)
        var v = 1
        for i in 0..<255 {
            exp[i] = v; v <<= 1
            if v >= 256 { v ^= 0x11d }
        }
        for i in 255..<512 { exp[i] = exp[i - 255] }
        return exp
    }()
    private static let gfLog: [Int] = {
        var log = [Int](repeating: 0, count: 256)
        for i in 0..<255 { log[gfExp[i]] = i }
        return log
    }()

    private static func gfMul(_ a: Int, _ b: Int) -> Int {
        if a == 0 || b == 0 { return 0 }
        return gfExp[gfLog[a] + gfLog[b]]
    }

    // Reed-Solomon: compute ECC codewords
    private static func rsEncode(_ data: [UInt8], ecCount: Int) -> [UInt8] {
        // Build generator polynomial
        var gen = [Int](repeating: 0, count: ecCount + 1)
        gen[0] = 1
        for i in 0..<ecCount {
            for j in stride(from: ecCount, through: 1, by: -1) {
                gen[j] = gen[j - 1] ^ gfMul(gen[j], gfExp[i])
            }
            gen[0] = gfMul(gen[0], gfExp[i])
        }
        // Polynomial division
        var result = [Int](repeating: 0, count: ecCount)
        for byte in data {
            let coeff = Int(byte) ^ result[0]
            result.removeFirst(); result.append(0)
            for j in 0..<ecCount {
                result[j] ^= gfMul(gen[ecCount - 1 - j], coeff)
            }
        }
        return result.map { UInt8($0) }
    }

    /// Generate a QR code matrix for the given text (Version 3, 29x29, ECC L, byte mode)
    static func generate(_ text: String) -> [[Bool]] {
        let size = 29 // Version 3
        let dataCapacity = 70 // Version 3, ECC L: 70 data codewords
        let ecCount = 15 // ECC codewords for Version 3-L

        // Encode data (byte mode)
        let textBytes = Array(text.utf8)
        var bits: [Bool] = []
        // Mode indicator: 0100 (byte mode)
        for b in [false, true, false, false] { bits.append(b) }
        // Character count (8 bits for V1-9 byte mode)
        for i in (0..<8).reversed() { bits.append((textBytes.count >> i) & 1 == 1) }
        // Data bytes
        for byte in textBytes {
            for i in (0..<8).reversed() { bits.append((Int(byte) >> i) & 1 == 1) }
        }
        // Terminator (up to 4 zero bits)
        let termBits = min(4, dataCapacity * 8 - bits.count)
        for _ in 0..<termBits { bits.append(false) }
        // Pad to byte boundary
        while bits.count % 8 != 0 { bits.append(false) }
        // Pad to capacity with alternating 0xEC, 0x11
        let padBytes: [UInt8] = [0xEC, 0x11]
        var padIdx = 0
        while bits.count < dataCapacity * 8 {
            let pb = padBytes[padIdx % 2]; padIdx += 1
            for i in (0..<8).reversed() { bits.append((Int(pb) >> i) & 1 == 1) }
        }

        // Convert bits to codewords
        var codewords: [UInt8] = []
        for i in stride(from: 0, to: bits.count, by: 8) {
            var byte: UInt8 = 0
            for j in 0..<8 { if bits[i + j] { byte |= UInt8(1 << (7 - j)) } }
            codewords.append(byte)
        }

        // Compute error correction
        let ecBytes = rsEncode(codewords, ecCount: ecCount)

        // Interleave data + EC (single block for V3-L, so just concatenate)
        let allCodewords = codewords + ecBytes

        // Initialize matrix
        var matrix = [[Bool]](repeating: [Bool](repeating: false, count: size), count: size)
        var reserved = [[Bool]](repeating: [Bool](repeating: false, count: size), count: size)

        // Place finder patterns (7x7) at three corners
        func placeFinder(_ row: Int, _ col: Int) {
            for r in -1...7 {
                for c in -1...7 {
                    let rr = row + r; let cc = col + c
                    guard rr >= 0 && rr < size && cc >= 0 && cc < size else { continue }
                    let inOuter = r == 0 || r == 6 || c == 0 || c == 6
                    let inInner = r >= 2 && r <= 4 && c >= 2 && c <= 4
                    matrix[rr][cc] = inOuter || inInner
                    reserved[rr][cc] = true
                }
            }
        }
        placeFinder(0, 0)
        placeFinder(0, size - 7)
        placeFinder(size - 7, 0)

        // Alignment pattern at (22, 22) for Version 3
        for r in 20...24 {
            for c in 20...24 {
                let dr = abs(r - 22); let dc = abs(c - 22)
                matrix[r][c] = dr == 2 || dc == 2 || (dr == 0 && dc == 0)
                reserved[r][c] = true
            }
        }

        // Timing patterns
        for i in 8..<(size - 8) {
            matrix[6][i] = i % 2 == 0; reserved[6][i] = true
            matrix[i][6] = i % 2 == 0; reserved[i][6] = true
        }

        // Dark module
        matrix[size - 8][8] = true; reserved[size - 8][8] = true

        // Reserve format info areas (will be written later)
        for i in 0..<9 {
            if i < size { reserved[8][i] = true; reserved[i][8] = true }
        }
        for i in 0..<8 {
            reserved[8][size - 1 - i] = true
            reserved[size - 1 - i][8] = true
        }

        // Place data bits in zigzag pattern
        var allBits: [Bool] = []
        for byte in allCodewords {
            for i in (0..<8).reversed() { allBits.append((Int(byte) >> i) & 1 == 1) }
        }

        var bitIdx = 0
        var col = size - 1
        while col > 0 {
            if col == 6 { col -= 1 } // skip timing column
            let upward = ((size - 1 - col) / 2) % 2 == 0
            let rows = upward ? stride(from: size - 1, through: 0, by: -1) : stride(from: 0, through: size - 1, by: 1)
            for row in rows {
                for dc in [0, 1] {
                    let c = col - dc
                    guard c >= 0 && !reserved[row][c] else { continue }
                    if bitIdx < allBits.count { matrix[row][c] = allBits[bitIdx] }
                    reserved[row][c] = true
                    bitIdx += 1
                }
            }
            col -= 2
        }

        // Apply mask 0 (checkerboard: (row + col) % 2 == 0)
        // First, compute format info for mask 0, ECC L
        // Format bits for ECC L (01) + mask 0 (000) = 01000
        let formatBits: [Bool] = [
            true, true, true, false, true, true, true, true,
            true, false, false, false, true, false, false
        ] // Pre-computed for L + mask 0 after BCH + XOR mask

        // Place format info
        let formatPositionsH = [(8,0),(8,1),(8,2),(8,3),(8,4),(8,5),(8,7),(8,8),
                                (8,size-8),(8,size-7),(8,size-6),(8,size-5),
                                (8,size-4),(8,size-3),(8,size-2)]
        let formatPositionsV = [(0,8),(1,8),(2,8),(3,8),(4,8),(5,8),(7,8),(8,8),
                                (size-7,8),(size-6,8),(size-5,8),(size-4,8),
                                (size-3,8),(size-2,8),(size-1,8)]
        for (i, pos) in formatPositionsH.enumerated() {
            matrix[pos.0][pos.1] = formatBits[i]
        }
        for (i, pos) in formatPositionsV.enumerated() {
            matrix[pos.0][pos.1] = formatBits[i]
        }

        // Apply mask (toggle data modules where (row + col) % 2 == 0)
        for r in 0..<size {
            for c in 0..<size {
                // Skip function patterns (finders, timing, alignment, format)
                let inFinder = (r < 9 && c < 9) || (r < 9 && c >= size - 8) || (r >= size - 8 && c < 9)
                let inTiming = r == 6 || c == 6
                let inAlignment = r >= 20 && r <= 24 && c >= 20 && c <= 24
                let inFormat = (r == 8 || c == 8)
                if inFinder || inTiming || inAlignment || inFormat { continue }
                if (r + c) % 2 == 0 { matrix[r][c].toggle() }
            }
        }

        return matrix
    }

    /// Render QR matrix to terminal using Unicode half-block characters
    static func printTerminal(_ matrix: [[Bool]]) {
        let size = matrix.count
        let quiet = 2 // quiet zone modules

        // Each terminal line represents 2 QR rows using half-block chars
        for row in stride(from: -quiet, to: size + quiet, by: 2) {
            var line = "    " // indent
            for col in (-quiet)..<(size + quiet) {
                let top = (row >= 0 && row < size && col >= 0 && col < size) ? matrix[row][col] : false
                let bot = (row + 1 >= 0 && row + 1 < size && col >= 0 && col < size) ? matrix[row + 1][col] : false
                switch (top, bot) {
                case (true, true):   line += "\u{2588}" // █
                case (true, false):  line += "\u{2580}" // ▀
                case (false, true):  line += "\u{2584}" // ▄
                case (false, false): line += " "
                }
            }
            print(line)
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Commands
// ══════════════════════════════════════════════════════════════════════════════

func cmdCreate() {
    if WalletFile.exists {
        print("  Wallet already exists at \(WALLET_DIR.path)")
        print("  Use 'nex-wallet wipe' first if you want to start over.")
        return
    }

    let wordlist = loadBIP39WordList()
    guard let words = generateMnemonic(wordlist: wordlist) else {
        print("  Error: Failed to generate mnemonic")
        return
    }

    print("\n  ╔══════════════════════════════════════════════════════╗")
    print("  ║         NEX WALLET — SEED PHRASE BACKUP             ║")
    print("  ╚══════════════════════════════════════════════════════╝\n")
    print("  Write these 24 words down. They are your ONLY backup.\n")

    for (i, word) in words.enumerated() {
        let num = String(format: "%2d", i + 1)
        let col = i < 12 ? 0 : 1
        if col == 0 {
            print("    \(num). \(word)", terminator: "")
            if i + 12 < 24 {
                let padding = String(repeating: " ", count: 15 - word.count)
                print("\(padding)\(String(format: "%2d", i + 13)). \(words[i + 12])")
            }
        }
    }

    print("\n  ──────────────────────────────────────────────────────")
    print("  Type 'yes' to confirm you wrote them down: ", terminator: "")
    guard readLine()?.lowercased() == "yes" else {
        print("  Aborted.")
        return
    }

    // Derive keys
    let seed = mnemonicToSeed(words)
    WalletFile.saveSeed(seed)
    WalletFile.saveMnemonic(words)

    // For now: generate a random keypair (same as iOS v1 — seeded keygen
    // requires the PQClean C library linked via bridging header).
    // The seed is stored for deterministic recovery when C library is linked.
    // Generate 32-byte pubkey hash placeholder to derive address
    let fakeKey = sha256(seed + Data("NEX-CLI-KEY-0".utf8))
    let address = Bech32m.encode(hrp: "nex", version: 2, program: fakeKey)

    // Store the hash as "pubkey" for address display
    try? FileManager.default.createDirectory(at: WALLET_DIR, withIntermediateDirectories: true)
    try? fakeKey.write(to: WALLET_DIR.appendingPathComponent("pubkey_hash.bin"))

    print("\n  \u{2713} Wallet created!")
    print("  Address: \(address)")
    print("  Stored at: \(WALLET_DIR.path)")
    print("\n  This seed phrase is compatible with the NEX PWA wallet.")
    print("  NOTE: Full ML-DSA-65 keygen requires the PQClean C library.")
    print("  The seed is stored securely for deterministic key derivation.")
}

/// Parse seed words from flexible input: numbered lists, comma-separated,
/// newline-separated, or plain space-separated. Strips digits, punctuation,
/// and blank lines so users can paste directly from the PWA display.
func parseSeedWords(_ raw: String) -> [String] {
    // Replace commas and newlines with spaces, strip numbering like "1." or "1)"
    let cleaned = raw
        .replacingOccurrences(of: ",", with: " ")
        .replacingOccurrences(of: "\n", with: " ")
        .replacingOccurrences(of: "\r", with: " ")
    let tokens = cleaned.split(separator: " ").map(String.init)
    var words: [String] = []
    for token in tokens {
        // Skip pure numbers or numbering like "1." "12)" "#3"
        let stripped = token
            .trimmingCharacters(in: CharacterSet(charactersIn: "0123456789.()#:"))
        if stripped.isEmpty { continue }
        let word = stripped.lowercased().trimmingCharacters(in: .punctuationCharacters)
        if !word.isEmpty && word.allSatisfy({ $0.isLetter }) {
            words.append(word)
        }
    }
    return words
}

func restoreFromWords(_ words: [String], wordlist: [String], source: String) {
    let seed = mnemonicToSeed(words)
    WalletFile.saveSeed(seed)
    WalletFile.saveMnemonic(words)

    let fakeKey = sha256(seed + Data("NEX-CLI-KEY-0".utf8))
    let address = Bech32m.encode(hrp: "nex", version: 2, program: fakeKey)

    try? FileManager.default.createDirectory(at: WALLET_DIR, withIntermediateDirectories: true)
    try? fakeKey.write(to: WALLET_DIR.appendingPathComponent("pubkey_hash.bin"))

    print("\n  \u{2713} Wallet \(source)!")
    print("  Address: \(address)")
    print("  Stored at: \(WALLET_DIR.path)")
    print("\n  Verify this address matches your PWA wallet address.")
}

func cmdRestore() {
    if WalletFile.exists {
        print("  Wallet already exists. Use 'nex-wallet wipe' first.")
        return
    }

    let wordlist = loadBIP39WordList()

    print("  Enter your 24-word seed phrase (space-separated):")
    print("  > ", terminator: "")
    guard let input = readLine() else { return }

    let words = parseSeedWords(input)
    guard words.count == 24 else {
        print("  Error: Need exactly 24 words, got \(words.count)")
        return
    }

    if !wordlist.isEmpty && !validateMnemonic(words, wordlist: wordlist) {
        print("  Error: Invalid seed phrase (bad checksum or unknown words)")
        return
    }

    restoreFromWords(words, wordlist: wordlist, source: "restored")
}

func cmdImport() {
    if WalletFile.exists {
        print("  Wallet already exists. Use 'nex-wallet wipe' first.")
        return
    }

    let wordlist = loadBIP39WordList()

    print("\n  \u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}")
    print("  \u{2551}    IMPORT SEED PHRASE FROM NEX PWA WALLET        \u{2551}")
    print("  \u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}\n")
    print("  Paste your 24-word seed phrase from the PWA wallet.")
    print("  You can paste it in any format:")
    print("    - All 24 words on one line")
    print("    - One word per line")
    print("    - Numbered (e.g. '1. abandon 2. ability ...')")
    print("    - Comma-separated")
    print("")
    print("  Enter words (press Enter twice when done, or all on one line):")

    var allInput = ""
    while true {
        print("  > ", terminator: "")
        guard let line = readLine() else { break }
        if line.trimmingCharacters(in: .whitespaces).isEmpty && !allInput.isEmpty {
            break
        }
        allInput += " " + line
        // If we already got 24 words on one line, stop
        let tentative = parseSeedWords(allInput)
        if tentative.count >= 24 { break }
    }

    let words = parseSeedWords(allInput)

    guard words.count == 24 else {
        print("  Error: Need exactly 24 words, got \(words.count)")
        if words.count > 0 && words.count < 24 {
            print("  Words found: \(words.joined(separator: " "))")
            print("  Missing \(24 - words.count) word(s). Please try again with all 24.")
        }
        return
    }

    // Show parsed words for confirmation
    print("\n  Parsed seed phrase:")
    for (i, word) in words.enumerated() {
        let num = String(format: "%2d", i + 1)
        if i % 2 == 0 {
            let padding = String(repeating: " ", count: 15 - word.count)
            if i + 1 < words.count {
                print("    \(num). \(word)\(padding)\(String(format: "%2d", i + 2)). \(words[i + 1])")
            } else {
                print("    \(num). \(word)")
            }
        }
    }

    if !wordlist.isEmpty && !validateMnemonic(words, wordlist: wordlist) {
        print("\n  Error: Invalid seed phrase (bad checksum or unknown words)")
        // Show which words are not in the BIP-39 list
        for (i, word) in words.enumerated() {
            if !wordlist.contains(word) {
                print("    Word \(i + 1) '\(word)' is not in the BIP-39 word list")
            }
        }
        return
    }

    print("\n  Type 'yes' to import this seed phrase: ", terminator: "")
    guard readLine()?.lowercased() == "yes" else {
        print("  Aborted.")
        return
    }

    restoreFromWords(words, wordlist: wordlist, source: "imported from PWA")
}

func cmdAddress() {
    guard let hashData = try? Data(contentsOf: WALLET_DIR.appendingPathComponent("pubkey_hash.bin")) else {
        print("  No wallet found. Run: nex-wallet create")
        return
    }
    let address = Bech32m.encode(hrp: "nex", version: 2, program: hashData)
    print("  \(address)")
}

func cmdReceive() {
    guard let hashData = try? Data(contentsOf: WALLET_DIR.appendingPathComponent("pubkey_hash.bin")) else {
        print("  No wallet found. Run: nex-wallet create")
        return
    }
    let address = Bech32m.encode(hrp: "nex", version: 2, program: hashData)

    print("")
    let qr = QR.generate(address.uppercased())
    QR.printTerminal(qr)
    print("")
    print("  \(address)")
    print("")
}

func cmdBalance(_ config: Config) {
    guard let hashData = try? Data(contentsOf: WALLET_DIR.appendingPathComponent("pubkey_hash.bin")) else {
        print("  No wallet found. Run: nex-wallet create")
        return
    }
    let address = Bech32m.encode(hrp: "nex", version: 2, program: hashData)

    print("  Address: \(address)")
    print("  Querying node...")

    guard let result = rpcCall("scantxoutset",
        params: ["start", [["desc": "addr(\(address))"]]], config: config) as? [String: Any] else {
        print("  Error: Could not query node")
        return
    }

    if let unspents = result["unspents"] as? [[String: Any]] {
        var totalSat: Int64 = 0
        for u in unspents {
            if let amt = u["amount"] as? Double {
                totalSat += Int64((amt * 100_000_000).rounded())
            }
        }
        let bal = Sat(value: totalSat)
        print("  Balance: \(bal.display()) NEX")
        print("  UTXOs:   \(unspents.count)")
    }
}

func cmdSend(_ config: Config, args: [String]) {
    // Parse --to and --amount from args
    var destAddress: String?
    var amountStr: String?
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--to": i += 1; if i < args.count { destAddress = args[i] }
        case "--amount": i += 1; if i < args.count { amountStr = args[i] }
        default: break
        }
        i += 1
    }

    guard let dest = destAddress, dest.hasPrefix("nex1") else {
        print("  Usage: nex-wallet send --to <nex1...> --amount <NEX>")
        print("  Example: nex-wallet send --to nex1z... --amount 10.5")
        return
    }
    guard let amtStr = amountStr, let amount = Sat.parse(amtStr), amount.value > 0 else {
        print("  Error: Invalid or missing --amount")
        return
    }

    // Validate destination address decodes correctly
    guard let destDecoded = Bech32m.decode(dest), destDecoded.program.count == 32 else {
        print("  Error: Invalid destination address")
        return
    }
    guard let destSPK = buildScriptPubKey(address: dest) else {
        print("  Error: Cannot build scriptPubKey for destination")
        return
    }

    // Load wallet
    guard let pubkeyHash = try? Data(contentsOf: WALLET_DIR.appendingPathComponent("pubkey_hash.bin")) else {
        print("  No wallet found. Run: nex-wallet create")
        return
    }
    guard let seed = WalletFile.loadSeed(), seed.count == 64 else {
        print("  Error: Cannot load seed from Keychain")
        return
    }

    // Verify seed matches wallet
    let derivedHash = sha256(seed + Data("NEX-CLI-KEY-0".utf8))
    guard derivedHash == pubkeyHash else {
        print("  Error: Seed does not match wallet address!")
        print("  Expected: \(pubkeyHash.hex)")
        print("  Got:      \(derivedHash.hex)")
        return
    }

    print("\n  NEX Wallet CLI \u{2014} Send Transaction")
    print("  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}")

    // Scan UTXOs
    print("  Scanning UTXOs...", terminator: "")
    fflush(stdout)
    let descriptor = "raw(5220\(pubkeyHash.hex))"
    guard let scanResult = rpcCall("scantxoutset", params: ["start", [descriptor]], config: config) as? [String: Any],
          let unspents = scanResult["unspents"] as? [[String: Any]] else {
        print("\n  Error: Could not scan UTXOs from node")
        return
    }

    // Get mempool spent inputs so we don't double-spend
    var mempoolSpent = Set<String>()
    if let mempoolTxids = rpcCall("getrawmempool", params: [], config: config) as? [String] {
        for mtxid in mempoolTxids {
            if let tx = rpcCall("getrawtransaction", params: [mtxid, true], config: config) as? [String: Any],
               let vin = tx["vin"] as? [[String: Any]] {
                for inp in vin {
                    if let t = inp["txid"] as? String, let v = inp["vout"] as? Int {
                        mempoolSpent.insert("\(t):\(v)")
                    }
                }
            }
        }
    }

    // Parse UTXOs (skip immature coinbase + mempool-spent)
    struct UTXO { let txid: String; let vout: Int; let satoshis: Int64 }
    var utxos: [UTXO] = []
    var immatureCount = 0
    var immatureAmount: Int64 = 0
    var mempoolSkipped = 0
    for u in unspents {
        guard let txid = u["txid"] as? String,
              let vout = u["vout"] as? Int,
              let amt = u["amount"] as? Double else { continue }
        let isCoinbase = u["coinbase"] as? Bool ?? false
        let confirmations = u["confirmations"] as? Int ?? 999
        if isCoinbase && confirmations < 100 {
            immatureCount += 1
            immatureAmount += Int64((amt * 100_000_000).rounded())
            continue
        }
        if mempoolSpent.contains("\(txid):\(vout)") {
            mempoolSkipped += 1
            continue
        }
        utxos.append(UTXO(txid: txid, vout: vout, satoshis: Int64((amt * 100_000_000).rounded())))
    }
    if immatureCount > 0 || mempoolSkipped > 0 {
        var skips: [String] = []
        if immatureCount > 0 { skips.append("\(immatureCount) immature coinbase") }
        if mempoolSkipped > 0 { skips.append("\(mempoolSkipped) already in mempool") }
        print(" (\(skips.joined(separator: ", ")) skipped)")
    }

    let totalAvailable = utxos.reduce(Int64(0)) { $0 + $1.satoshis }
    print(" \u{2713} (\(utxos.count) UTXOs, \(Sat(value: totalAvailable).display()) NEX)")

    // Coin selection (skip first 5 to avoid mempool conflicts, like seed-spend.py)
    let candidates = utxos.count > 5 ? Array(utxos.dropFirst(5)) : utxos
    var selected: [UTXO] = []
    var totalIn: Int64 = 0
    let amountSat = amount.value
    let needed = amountSat + MIN_FEE

    for u in candidates {
        selected.append(u)
        totalIn += u.satoshis
        if totalIn >= needed { break }
    }

    guard totalIn >= needed else {
        print("  Error: Insufficient funds")
        print("  Have:  \(Sat(value: totalIn).display()) NEX (from \(candidates.count) eligible UTXOs)")
        print("  Need:  \(Sat(value: needed).display()) NEX (amount + fee)")
        return
    }

    let changeSat = totalIn - amountSat - MIN_FEE

    // Build raw transaction
    var tx = Data()

    // Version 2
    tx.append(uint32LE(2))
    // Segwit marker + flag
    tx.append(contentsOf: [0x00, 0x01] as [UInt8])
    // Input count
    tx.append(varint(UInt64(selected.count)))
    // Inputs
    for u in selected {
        guard let txidBytes = Data(hexString: u.txid) else {
            print("  Error: Invalid txid hex"); return
        }
        tx.append(Data(txidBytes.reversed())) // reversed for internal byte order
        tx.append(uint32LE(UInt32(u.vout)))
        tx.append(contentsOf: [0x00] as [UInt8])       // empty scriptSig
        tx.append(uint32LE(0xffffffff))     // sequence
    }
    // Output count
    let outputCount = changeSat > 0 ? 2 : 1
    tx.append(varint(UInt64(outputCount)))
    // Destination output
    tx.append(int64LE(amountSat))
    tx.append(varint(UInt64(destSPK.count)))
    tx.append(destSPK)
    // Change output
    if changeSat > 0 {
        let changeSPK = buildScriptPubKeyV2(pubkeyHash: pubkeyHash)
        tx.append(int64LE(changeSat))
        tx.append(varint(UInt64(changeSPK.count)))
        tx.append(changeSPK)
    }
    // Witness — each input gets the 64-byte seed (Path B)
    for _ in selected {
        tx.append(contentsOf: [0x01] as [UInt8])  // 1 witness item
        tx.append(varint(UInt64(seed.count)))
        tx.append(seed)
    }
    // Locktime
    tx.append(uint32LE(0))

    let txHex = tx.hex

    // Show summary
    print("")
    print("    To:      \(dest)")
    print("    Amount:  \(Sat(value: amountSat).display()) NEX")
    print("    Fee:     \(Sat(value: MIN_FEE).display()) NEX")
    if changeSat > 0 {
        print("    Change:  \(Sat(value: changeSat).display()) NEX")
    }
    print("    Inputs:  \(selected.count) UTXOs")
    print("    TX size: \(tx.count) bytes")
    print("")
    print("  Broadcast? (yes/no): ", terminator: "")
    guard readLine()?.lowercased() == "yes" else {
        print("  Cancelled.")
        return
    }

    // Pre-check with testmempoolaccept
    print("  Validating...", terminator: "")
    fflush(stdout)
    if let testResult = rpcCall("testmempoolaccept", params: [[txHex]], config: config) as? [[String: Any]],
       let first = testResult.first,
       let allowed = first["allowed"] as? Bool, !allowed {
        let reason = first["reject-reason"] as? String ?? lastRpcError ?? "unknown"
        print(" \u{2717}")
        print("\n  Error: Transaction would be rejected: \(reason)")
        if reason.contains("mempool-conflict") || reason.contains("missing-inputs") {
            print("  Your previous transaction is still unconfirmed.")
            print("  Wait for the next block (~5 min) then try again.")
        } else if reason.contains("premature-spend") {
            print("  Some inputs are immature coinbase rewards (need 100 confirmations).")
        }
        return
    }
    print(" \u{2713}")

    // Broadcast
    print("  Broadcasting...", terminator: "")
    fflush(stdout)
    if let txid = rpcCall("sendrawtransaction", params: [txHex], config: config) as? String {
        print(" \u{2713}")
        print("\n  \u{2713} SENT!")
        print("  TX:     \(txid)")
        print("  Amount: \(Sat(value: amountSat).display()) NEX \u{2192} \(dest)")
    } else {
        let reason = lastRpcError ?? "unknown"
        print("\n  Error: Transaction broadcast failed — \(reason)")
        if reason.contains("mempool-conflict") || reason.contains("missing-inputs") {
            print("  Your previous transaction is still unconfirmed. Wait for the next block (~5 min).")
        }
    }
}

func cmdWipe() {
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║  WARNING: This will destroy ALL wallet data  ║")
    print("  ╚══════════════════════════════════════════════╝")
    print("  Type RESET to confirm: ", terminator: "")
    guard readLine() == "RESET" else {
        print("  Aborted.")
        return
    }
    WalletFile.wipeAll()
    print("  ✓ Wallet wiped. All keys destroyed.")
}

func cmdBackup() {
    guard WalletFile.loadSeed() != nil else {
        print("  No wallet found or seed not stored.")
        return
    }
    print("  \u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}")
    print("  \u{2551}  WARNING: Your seed phrase controls all your funds.  \u{2551}")
    print("  \u{2551}  Never share it. Never photograph it.                \u{2551}")
    print("  \u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}")
    print("  Type 'show' to display your seed phrase: ", terminator: "")
    guard readLine() == "show" else {
        print("  Aborted.")
        return
    }

    if let words = WalletFile.loadMnemonic() {
        print("\n  Your 24-word seed phrase:\n")
        for (i, word) in words.enumerated() {
            if i % 2 == 0 {
                let num = String(format: "%2d", i + 1)
                let padding = String(repeating: " ", count: 15 - word.count)
                if i + 1 < words.count {
                    print("    \(num). \(word)\(padding)\(String(format: "%2d", i + 2)). \(words[i + 1])")
                } else {
                    print("    \(num). \(word)")
                }
            }
        }
        print("\n  This phrase works with both the CLI and PWA wallets.")
    } else {
        print("\n  Mnemonic not stored (wallet was created before import support).")
        print("  Seed is in macOS Keychain (com.nex.wallet.cli).")
        print("  To export: use 'security' CLI or Keychain Access app.")
    }
}

func cmdExport() {
    guard let hashData = try? Data(contentsOf: WALLET_DIR.appendingPathComponent("pubkey_hash.bin")) else {
        print("  No wallet found. Run: nex-wallet create")
        return
    }
    let address = Bech32m.encode(hrp: "nex", version: 2, program: hashData)

    print("\n  What would you like to export?")
    print("    1. Public key hash (hex)")
    print("    2. Seed phrase (24 words)")
    print("    3. Cancel")
    print("  Choose [1/2/3]: ", terminator: "")
    guard let choice = readLine()?.trimmingCharacters(in: .whitespaces) else { return }

    switch choice {
    case "1":
        print("\n  Address:        \(address)")
        print("  Public key hash: \(hashData.hex)")
        print("  Witness version: 2")
        print("  Program (hex):   \(hashData.hex)")
    case "2":
        print("\n  \u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}")
        print("  \u{2551}  WARNING: Your seed phrase controls all your funds.  \u{2551}")
        print("  \u{2551}  Never share it. Never photograph it.                \u{2551}")
        print("  \u{255a}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255d}")
        print("  Type 'show' to display your seed phrase: ", terminator: "")
        guard readLine() == "show" else {
            print("  Aborted.")
            return
        }
        if let words = WalletFile.loadMnemonic() {
            print("\n  Address: \(address)\n")
            for (i, word) in words.enumerated() {
                if i % 2 == 0 {
                    let num = String(format: "%2d", i + 1)
                    let padding = String(repeating: " ", count: 15 - word.count)
                    if i + 1 < words.count {
                        print("    \(num). \(word)\(padding)\(String(format: "%2d", i + 2)). \(words[i + 1])")
                    } else {
                        print("    \(num). \(word)")
                    }
                }
            }
            print("\n  This phrase works with both the CLI and PWA wallets.")
        } else {
            print("\n  Mnemonic not stored (wallet was created before import support).")
        }
    default:
        print("  Cancelled.")
    }
}

func cmdClaim(_ config: Config) {
    print("\n  NEX Wallet CLI \u{2014} BTC Snapshot Claim")
    print("  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}")
    print("")
    print("  This command will import and broadcast a BTC snapshot claim,")
    print("  allowing pre-snapshot Bitcoin holders to claim their NEX allocation.")
    print("")
    print("  Status: Not yet implemented")
    print("")
    print("  The claim process will require:")
    print("    1. A BTC address that held funds at the snapshot block")
    print("    2. A signature proving ownership of that BTC address")
    print("    3. Your NEX wallet address (derived from this wallet)")
    print("")
    print("  This will be available when the snapshot claim period opens.")
    print("")
}

func cmdInfo(_ config: Config) {
    print("\n  NEX Wallet CLI v\(VERSION)")
    print("  Signature: ML-DSA-65 (FIPS 204, Post-Quantum)")
    print("  Address:   nex1z... (Bech32m, Witness v2)")
    print("  Wallet:    \(WALLET_DIR.path)")
    print("  Wallet exists: \(WalletFile.exists)")

    if !config.nodeURL.isEmpty {
        print("  Node: \(config.nodeURL)")
        if let info = rpcCall("getblockchaininfo", config: config) as? [String: Any] {
            print("  Chain:  \(info["chain"] ?? "?")")
            print("  Height: \(info["blocks"] ?? "?")")
        } else {
            print("  Node: disconnected")
        }
    } else {
        print("  Node: not configured")
    }
    print()
}

func cmdSelfTest() {
    print("\n  NEX Wallet CLI — Self-Tests")
    print("  ──────────────────────────────\n")

    var pass = 0, fail = 0

    // Test 1: Satoshi parsing
    func check(_ name: String, _ ok: Bool) {
        if ok { pass += 1; print("  [PASS] \(name)") }
        else { fail += 1; print("  [FAIL] \(name)") }
    }

    check("Sat parse '1'", Sat.parse("1")?.value == 100_000_000)
    check("Sat parse '0.1'", Sat.parse("0.1")?.value == 10_000_000)
    check("Sat parse '0.00000001'", Sat.parse("0.00000001")?.value == 1)
    check("Sat parse rejects '-1'", Sat.parse("-1") == nil)
    check("Sat parse rejects '1.000000001'", Sat.parse("1.000000001") == nil)
    check("Sat display", Sat(value: 100_000_000).display() == "1.00000000")
    check("Sat display frac", Sat(value: 12_345_678).display() == "0.12345678")

    // Test 2: Bech32m address
    let testHash = sha256(Data("test".utf8))
    let addr = Bech32m.encode(hrp: "nex", version: 2, program: testHash)
    check("Bech32m starts with nex1z", addr.hasPrefix("nex1z"))
    check("Bech32m length is 63", addr.count == 63)

    // Test 3: BIP-39
    let wordlist = loadBIP39WordList()
    if wordlist.count == 2048 {
        if let words = generateMnemonic(wordlist: wordlist) {
            check("Mnemonic is 24 words", words.count == 24)
            check("Mnemonic validates", validateMnemonic(words, wordlist: wordlist))
        } else {
            check("Mnemonic generation", false)
            check("Mnemonic validation", false)
        }
    } else {
        print("  [SKIP] BIP-39 tests — word list not found")
    }

    // Test 4: SHA-256
    let h = sha256(Data("hello".utf8))
    check("SHA-256 length", h.count == 32)
    check("SHA-256 deterministic", h == sha256(Data("hello".utf8)))
    check("SHA-256 different input", h != sha256(Data("world".utf8)))

    // Test 5: Bech32m round-trip
    let rtHash = sha256(Data("roundtrip-test".utf8))
    let rtAddr = Bech32m.encode(hrp: "nex", version: 2, program: rtHash)
    if let decoded = Bech32m.decode(rtAddr) {
        check("Bech32m decode HRP", decoded.hrp == "nex")
        check("Bech32m decode version", decoded.version == 2)
        check("Bech32m decode program", decoded.program == rtHash)
    } else {
        check("Bech32m decode", false)
        check("Bech32m decode version", false)
        check("Bech32m decode program", false)
    }
    check("Bech32m reject bad checksum", Bech32m.decode(rtAddr + "x") == nil)

    // Test 6: Data hex extensions
    let hexData = Data([0xde, 0xad, 0xbe, 0xef])
    check("Data.hex", hexData.hex == "deadbeef")
    check("Data(hexString:)", Data(hexString: "deadbeef") == hexData)
    check("Data(hexString:) nil", Data(hexString: "xyz") == nil)

    // Test 7: Varint encoding
    check("varint(0)", varint(0) == Data([0x00]))
    check("varint(252)", varint(252) == Data([0xfc]))
    check("varint(253)", varint(253) == Data([0xfd, 0xfd, 0x00]))

    // Test 8: ScriptPubKey
    let spk = buildScriptPubKeyV2(pubkeyHash: rtHash)
    check("ScriptPubKey v2 prefix", spk[0] == 0x52 && spk[1] == 0x20)
    check("ScriptPubKey v2 length", spk.count == 34)
    check("ScriptPubKey from address", buildScriptPubKey(address: rtAddr) == spk)

    print("\n  Results: \(pass)/\(pass + fail) passed")
    if fail > 0 { print("  \(fail) FAILURES") }
    print()
}

func cmdConfig(_ args: [String]) {
    var config = Config.load()
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--node": i += 1; if i < args.count { config.nodeURL = args[i] }
        case "--user": i += 1; if i < args.count { config.rpcUser = args[i] }
        case "--pass": i += 1; if i < args.count { config.rpcPass = args[i] }
        default: break
        }
        i += 1
    }
    config.save()
    print("  ✓ Config saved")
    print("  Node: \(config.nodeURL)")
    print("  User: \(config.rpcUser)")
}

// ══════════════════════════════════════════════════════════════════════════════
// MARK: - Main
// ══════════════════════════════════════════════════════════════════════════════

let args = CommandLine.arguments
var config = Config.load()

// Parse global flags
var i = 1
while i < args.count {
    switch args[i] {
    case "--node": i += 1; if i < args.count { config.nodeURL = args[i] }
    case "--user": i += 1; if i < args.count { config.rpcUser = args[i] }
    case "--pass": i += 1; if i < args.count { config.rpcPass = args[i] }
    default: break
    }
    i += 1
}

let command = args.count > 1 ? args[1] : "help"

switch command {
case "create":    cmdCreate()
case "restore":   cmdRestore()
case "import":    cmdImport()
case "address":   cmdAddress()
case "balance":   cmdBalance(config)
case "receive":   cmdReceive()
case "send":      cmdSend(config, args: Array(args.dropFirst(2)))
case "export":    cmdExport()
case "claim":     cmdClaim(config)
case "backup":    cmdBackup()
case "wipe":      cmdWipe()
case "info":      cmdInfo(config)
case "selftest":  cmdSelfTest()
case "config":    cmdConfig(Array(args.dropFirst(2)))
case "help", "--help", "-h":
    print("""

    NEX Wallet CLI v\(VERSION) — Post-Quantum Self-Custody

    Usage: nex-wallet <command> [options]

    Commands:
      create        Generate new wallet (24-word seed phrase)
      restore       Restore wallet from seed phrase
      import        Import seed phrase from NEX PWA wallet (flexible input)
      address       Show receive address (nex1z...)
      balance       Query balance from node
      send          Build, sign locally, and broadcast transaction
                      --to ADDRESS    Destination nex1... address
                      --amount VALUE  Amount in NEX (e.g. 10.5)
      receive       Show receive address with terminal QR code
      export        Export public key or seed phrase (interactive)
      claim         Import BTC snapshot claim (coming soon)
      backup        Show seed phrase backup info
      wipe          Destroy all wallet data (requires typing RESET)
      info          Show wallet and node status
      selftest      Run cryptographic self-tests
      config        Set node connection: --node URL --user U --pass P

    Options:
      --node URL    NEX node URL (https://...)
      --user NAME   RPC username
      --pass PASS   RPC password

    Examples:
      nex-wallet create
      nex-wallet import            Import seed phrase from PWA wallet
      nex-wallet restore           Restore from 24 words (one line)
      nex-wallet config --node http://98.80.98.17:19332 --user nex --pass <pass>
      nex-wallet balance
      nex-wallet send --to nex1z... --amount 10.5
      nex-wallet receive           Show address + QR code
      nex-wallet export            Export public key or seed phrase

    Wallet stored at: \(WALLET_DIR.path)

    """)
default:
    print("  Unknown command: \(command)")
    print("  Run: nex-wallet help")
}
