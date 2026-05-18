# pwnMyCTF

## What This Is

An autonomous CTF challenge solver in pure bash — give it a challenge (file, URL, directory) and get the flag. All categories supported (Web, Crypto, PWN, Reverse, Forensics, OSINT). Fully automatic detection and solving unless `--force` override specified.

## Core Value

Flag extraction with zero user interaction — analyze input, detect type, solve, output.

## Current State

**v1.0 MVP shipped:** 2026-05-18
- 47 v1 requirements complete
- 8 phases executed and archived
- PR created: https://github.com/izpan/pwnMyCTF/pull/1

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

- [ ] v2 requirements deferred (see .planning/milestones/v1.0-REQUIREMENTS.md)

### Out of Scope

- [AI integration] — Pure bash only, no AI/LLM
- [Docker] — No containerization
- [Python Deps Required] — Optional pwntools allowed but not required

## Context

CTF (Capture The Flag) competitions involve solving security challenges across multiple categories. Challenges come as files, URLs to web services, or directories with multiple artifacts. The solver needs to analyze the input, determine what category/type it is, and apply appropriate techniques to extract the flag.

## Constraints

- **Pure bash**: No compiled binaries, only bash scripts and standard Unix tools
- **No AI**: No LLM or ML integration
- **No Docker**: No containerized solutions
- **No required deps**: Optional pwntools allowed but not required

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Modular pipeline architecture | Each category has specialized solvers | ✓ Validated in v1.0 |
| Auto-detect unless forced | Reduces friction for common case | ✓ Validated in v1.0 |
| Flag-first output | CTF tools should output flags | ✓ Validated in v1.0 |
| Bash-native categories first | Web, OSINT highest confidence | ✓ Validated in v1.0 |
| PWN last with managed expectations | Pure bash cannot replicate pwntools | ✓ Validated in v1.0 |

## Next Steps

- Merge PR #1 when ready
- `/gsd-new-milestone` to start v1.1 planning

---

*Last updated: 2026-05-18 after v1.0 milestone completion*

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