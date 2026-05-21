# Roadmap: pwnMyCTF

## Milestones

- ✅ **v1.0 MVP** — Phases 1-8 (shipped 2026-05-18)
- 🚧 **v1.1 Advanced Capabilities** — Phases 9-14 (in progress)

## Phases

<details>
<summary>✅ v1.0 MVP (Phases 1-8) — SHIPPED 2026-05-18</summary>

- [x] Phase 1: Core Infrastructure (1/1 plan) — completed 2025-05-17
- [x] Phase 2: Detection Pipeline (1/1 plan) — completed 2025-05-17
- [x] Phase 3: Web & OSINT Solvers (1/1 plan) — completed 2025-05-17
- [x] Phase 4: Crypto Solver (1/1 plan) — completed 2025-05-17
- [x] Phase 5: Forensics Solver (1/1 plan) — completed 2026-05-17
- [x] Phase 6: Reverse Solver (1/1 plan) — completed 2026-05-17
- [x] Phase 7: PWN Solver (1/1 plan) — completed 2026-05-17
- [x] Phase 8: Advanced Patterns (1/1 plan) — completed 2026-05-17

</details>

### 🚧 v1.1 Advanced Capabilities (In Progress)

- [ ] Phase 9: Encoding Pipeline (8/8 requirements)
- [ ] Phase 10: Classical Ciphers (10/10 requirements)
- [ ] Phase 11: XOR & Modern Crypto (15/15 requirements)
- [ ] Phase 12: Binary Exploitation (6/6 requirements)
- [ ] Phase 13: Forensics & Steganography (8/8 requirements)
- [ ] Phase 14: Web Attacks & Platform Integration (14/14 requirements)

---

## Phase Details

### Phase 9: Encoding Pipeline

**Goal:** Implement comprehensive multi-layer encoding detection and decoding pipeline
**Depends on:** Phase 1 (Core Infrastructure)
**Requirements:** ENC-01 to ENC-08

**Success Criteria:**
1. Detects all base variants (16, 32, 36, 58, 62, 64, 85, Z85) from input
2. Decodes binary/octal/hex representations correctly
3. Handles URL and HTML/XML encoding
4. Detects and decodes Unicode variants (UTF-8, UTF-16, codepoints)
5. Recursively decodes up to 10 layers of encoding automatically
6. Detects custom alphabets and reverse strings

**Plans:**
- [ ] 09-01-PLAN.md — Encoding detection and decoding pipeline

---

### Phase 10: Classical Ciphers

**Goal:** Implement classical cipher detection and cracking capabilities
**Depends on:** Phase 9
**Requirements:** CIPHER-01 to CIPHER-10

**Success Criteria:**
1. Detects and bruteforces Caesar cipher (all 26 shifts)
2. Handles ROT13 and ROT47 decoding
3. Decrypts Atbash (alphabet reversal)
4. Cracks Vigenere cipher using Kasiski/IOC analysis
5. Decrypts Rail Fence and Columnar Transposition ciphers
6. Handles Playfair and Hill (matrix) ciphers
7. Detects and decodes Bacon and Morse code

**Plans:**
- [ ] 10-01-PLAN.md — Classical cipher detection and cracking

---

### Phase 11: XOR & Modern Crypto

**Goal:** Implement advanced cryptanalysis for XOR, hashes, and modern ciphers
**Depends on:** Phase 10
**Requirements:** XOR-01 to XOR-05, MODERN-01 to MODERN-10, HASH-01 to HASH-05, PRNG-01 to PRNG-04

**Success Criteria:**
1. Detects single-byte XOR keys via frequency analysis
2. Finds multi-byte XOR key length using Hamming distance
3. Cracks repeating-key XOR ciphers
4. Detects AES ECB patterns and performs CBC bit flipping
5. Implements padding oracle attack for CBC mode
6. Cracks RSA vulnerabilities (small e, Wiener's, common modulus)
7. Performs DH and ECC attacks
8. Implements hash length extension attacks
9. Recovers MT19937 state from outputs
10. Uses Z3 for custom cipher constraint solving

**Plans:**
- [ ] 11-01-PLAN.md — XOR and modern crypto attacks

---

### Phase 12: Binary Exploitation

**Goal:** Implement pwntools-based binary exploitation capabilities
**Depends on:** Phase 6 (Reverse Solver), Phase 7 (PWN Solver)
**Requirements:** BIN-01 to BIN-06

**Success Criteria:**
1. Constructs ROP chains using pwntools
2. Integrates libc database and finds one_gadget addresses
3. Handles remote tube connections for network challenges
4. Exploits format string vulnerabilities
5. Provides heap exploitation helpers
6. Patches ELF binaries and manipulates symbols

**Plans:**
- [ ] 12-01-PLAN.md — Binary exploitation with pwntools

---

### Phase 13: Forensics & Steganography

**Goal:** Implement advanced forensics and steganography detection
**Depends on:** Phase 5 (Forensics Solver)
**Requirements:** FORENSIC-01 to FORENSIC-08

**Success Criteria:**
1. Extracts LSB hidden data from PNG images
2. Detects JPEG steganography (JSteg, F5, OutGuess)
3. Performs audio spectrogram analysis
4. Analyzes memory dumps for key extraction
5. Parses PCAP files and reconstructs traffic
6. Carves files using entropy analysis
7. Extracts EXIF metadata including GPS coordinates
8. Detects polyglot files (PNG+ZIP, PDF+ZIP)

**Plans:**
- [ ] 13-01-PLAN.md — Advanced forensics and steganography

---

### Phase 14: Web Attacks & Platform Integration

**Goal:** Implement advanced web attacks and CTF platform automation
**Depends on:** Phase 3 (Web & OSINT Solvers)
**Requirements:** WEB-01 to WEB-07, PLATFORM-01 to PLATFORM-03, DETECT-01 to DETECT-04

**Success Criteria:**
1. Performs blind SQL injection (boolean and time-based)
2. Manipulates JWT tokens (alg:none, weak secret, kid)
3. Detects and exploits SSTI vulnerabilities
4. Exploits SSRF with gopher protocol
5. Reads files via XXE injection
6. Exploits race conditions and HTTP smuggling
7. Integrates with CTFd API for challenge polling
8. Auto-submits flags to CTF platforms
9. Analyzes entropy to detect encrypted regions
10. Maintains extended magic byte database

**Plans:**
- [ ] 14-01-PLAN.md — Web attacks and platform integration

---

## Progress Table

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|---------------|--------|-----------|
| 1. Core Infrastructure | v1.0 | 1/1 | Complete | 2025-05-17 |
| 2. Detection Pipeline | v1.0 | 1/1 | Complete | 2025-05-17 |
| 3. Web & OSINT Solvers | v1.0 | 1/1 | Complete | 2025-05-17 |
| 4. Crypto Solver | v1.0 | 1/1 | Complete | 2025-05-17 |
| 5. Forensics Solver | v1.0 | 1/1 | Complete | 2026-05-17 |
| 6. Reverse Solver | v1.0 | 1/1 | Complete | 2026-05-17 |
| 7. PWN Solver | v1.0 | 1/1 | Complete | 2026-05-17 |
| 8. Advanced Patterns | v1.0 | 1/1 | Complete | 2026-05-17 |
| 9. Encoding Pipeline | v1.1 | 0/1 | Not started | - |
| 10. Classical Ciphers | v1.1 | 0/1 | Not started | - |
| 11. XOR & Modern Crypto | v1.1 | 0/1 | Not started | - |
| 12. Binary Exploitation | v1.1 | 0/1 | Not started | - |
| 13. Forensics & Stego | v1.1 | 0/1 | Not started | - |
| 14. Web & Platform | v1.1 | 0/1 | Not started | - |

## Coverage Map

| Phase | Requirements | Count |
|-------|--------------|-------|
| 1 - Core Infrastructure | CORE-01 to CORE-09 | 9 |
| 2 - Detection Pipeline | DET-01 to DET-04 | 4 |
| 3 - Web & OSINT Solvers | WEB-01 to WEB-07, OSINT-01 to OSINT-05 | 12 |
| 4 - Crypto Solver | CRYPTO-01 to CRYPTO-05 | 5 |
| 5 - Forensics Solver | FOREN-01 to FOREN-06 | 6 |
| 6 - Reverse Solver | REV-01 to REV-06 | 6 |
| 7 - PWN Solver | PWN-01 to PWN-05 | 5 |
| 8 - Advanced Patterns | (Enhancement) | 0 |
| 9 - Encoding Pipeline | ENC-01 to ENC-08 | 8 |
| 10 - Classical Ciphers | CIPHER-01 to CIPHER-10 | 10 |
| 11 - XOR & Modern Crypto | XOR, MODERN, HASH, PRNG requirements | 19 |
| 12 - Binary Exploitation | BIN-01 to BIN-06 | 6 |
| 13 - Forensics & Stego | FORENSIC-01 to FORENSIC-08 | 8 |
| 14 - Web & Platform | WEB-01 to WEB-07, PLATFORM, DETECT requirements | 11 |

**Total:** 47 v1 requirements + 58 v1.1 requirements = 105 total requirements

---

*Roadmap updated: 2026-05-18*
*Full details: .planning/milestones/v1.0-ROADMAP.md*