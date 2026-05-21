# pwnMyCTF

## What This Is

An autonomous CTF challenge solver in pure Python — give it a challenge (file, URL, directory) and get the flag. All categories supported (Web, Crypto, PWN, Reverse, Forensics, OSINT). Fully automatic detection and solving unless `--force` override specified.

## Core Value

Flag extraction with zero user interaction — analyze input, detect type, solve, output.

## Current Milestone: v1.1 Advanced Capabilities

**Goal:** Transform pwnMyCTF from basic flag extractor to serious CTF weapon with full crypto analysis, binary exploitation, advanced forensics, and web attack capabilities.

**Target features:**
1. Multi-layer encoding pipeline (Base16-85, binary, hex, URL, Unicode, custom)
2. Classical ciphers (Caesar, Vigenere, Playfair, Hill, Bacon, Morse)
3. XOR cryptanalysis (single-byte, multi-byte, frequency analysis)
4. Modern encryption (RSA attacks, padding oracle, DH/ECDH)
5. Hash attacks (identification, length extension, custom reverse)
6. PRNG attacks (MT, LCG, Xorshift prediction)
7. Binary exploitation (pwntools integration, ROP, heap)
8. Advanced forensics (steganography, memory, PCAP)
9. Web attacks (blind SQLi, JWT, SSTI, SSRF)
10. CTF platform integration (CTFd API)

## Requirements

### Validated

- ✓ All Core Infrastructure requirements (CORE-01 to CORE-09) — v1.0
- ✓ All Detection requirements (DET-01 to DET-04) — v1.0
- ✓ All Web Solver requirements (WEB-01 to WEB-07) — v1.0
- ✓ All OSINT Solver requirements (OSINT-01 to OSINT-05) — v1.0
- ✓ All Crypto Solver requirements (CRYPTO-01 to CRYPTO-05) — v1.0
- ✓ All Forensics Solver requirements (FOREN-01 to FOREN-06) — v1.0
- ✓ All Reverse Solver requirements (REV-01 to REV-06) — v1.0
- ✓ All PWN Solver requirements (PWN-01 to PWN-05) — v1.0

### Active

(v1.1 requirements in .planning/REQUIREMENTS.md)

### Out of Scope

- [AI/LLM integration] — Pure bash/Python only, no external API calls
- [Docker sandbox] — No containerization
- [GUI] — CLI tool only

## Context

CTF (Capture The Flag) competitions involve solving security challenges across multiple categories. v1.1 transforms the tool from basic flag extraction to comprehensive CTF solving with advanced crypto, binary exploitation, and web attack capabilities.

## Constraints

- **Python 3**: Core language for all advanced capabilities
- **Pure Python**: No compiled binaries, only Python and standard Unix tools
- **Tool Discovery**: Auto-detect required tools (z3, pwntools, etc.)
- **Dependency Management**: Install missing packages via pip when needed

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Pure Python architecture | Full crypto, binary, web tool support | In progress |
| Modular solver classes | Consistent interface across categories | In progress |
| Auto-install dependencies | Reduce setup friction | Planned |
| CTF platform integration | Automate solve-submit loop | Planned |

---

*Last updated: 2026-05-18 after v1.1 milestone start*

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state