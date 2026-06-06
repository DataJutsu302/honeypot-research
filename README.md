# mdrfckr Cryptomining Botnet — Independent Sensor Corroboration (May–June 2026)

**Analyst:** Daryl Jiminez, SANS ISC Intern  
**Observation Window:** 2026-05-15 → 2026-06-04 (21 days)  
**Sensor:** Single DShield/Cowrie sensor, Raspberry Pi 5  
**Related ISC Diary:** [New Malware Libraries means New Signatures](https://isc.sans.edu) — published 2026-05-15

---

## Overview

On 2026-05-15 — the same day a fellow SANS ISC intern published a diary documenting a new libssh 0.11.x hassh fingerprint for the long-running mdrfckr/Outlaw cryptomining campaign — my independent DShield sensor began capturing the same campaign. This diary presents 21 days of single-sensor observation data as independent corroboration of that finding, extends the observation window 14 days beyond the published report, and documents the simultaneous presence of both the 2022-era and 2026-era hassh fingerprints on a single sensor.

The mdrfckr campaign is not new. The authorized_keys SHA-256 `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` has been on VirusTotal since July 2018 and has not changed. The Outlaw/Dota attribution, recon playbook, and competitor-eviction behavior are documented across Trend Micro (2018/2020), Anomali, Yoroi, Juniper, CounterCraft, Cybereason, and Kaspersky reporting, as well as the port22.dk two-part hassh analysis (2022–2023) and multiple SANS ISC handler diaries.

What this observation adds is narrow but specific: independent second-sensor confirmation of the April 2026 hassh `03a80b21afa810682a776a7d42e5e6fb` (libssh 0.11.1), evidence that both hassh generations are running concurrently through June 2026, and a detailed session-level breakdown of the full automated compromise playbook as captured in Cowrie logs.

---

## Key Numbers

| Metric | Value |
|---|---|
| Observation window | 2026-05-15 → 2026-06-04 (21 days) |
| Total mdrfckr persistence attempts | 106 |
| Unique source IPs | 97 |
| authorized_keys SHA-256 | a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 |
| 2022-era hassh (libssh 0.9.x) hits | 2,306 |
| 2026-era hassh (libssh 0.11.1) hits | 111 |
| Session duration (full playbook) | ~22 seconds |

---

## Hassh Observations

The published diary asked whether other DShield operators had independently observed the April 2026 hassh `03a80b21afa810682a776a7d42e5e6fb`. This sensor confirms it.

| Hassh | Client Banner | Hits on This Sensor | Period |
|---|---|---|---|
| `f555226df1963d1d3c09daf865abdc9a` | libssh 0.9.5 / 0.9.6 | 2,306 | May–June 2026 |
| `03a80b21afa810682a776a7d42e5e6fb` | libssh 0.11.1 | 111 | May–June 2026 |

Both generations are active simultaneously on this sensor through June 4, 2026 — suggesting the botnet operator has not fully migrated infrastructure to the newer client version and is running mixed tooling.

---

## Full Kill Chain — Session Analysis

The following is a complete session reconstruction from Cowrie logs for session `8af652604719` (src_ip: 163.7.8.79, 2026-05-23). This session is representative of the observed playbook across all 106 attempts.

| Timestamp (UTC) | Event | Detail |
|---|---|---|
| 01:06:43 | Connection | SSH connection established |
| 01:06:44 | Login success | root / Aa123123123 |
| 01:06:45 | Defensive disarm | `chattr -ia .ssh; lockr -ia .ssh` — removes immutable flags from .ssh directory |
| 01:06:46 | Persistence | SSH public key injected into `~/.ssh/authorized_keys` |
| 01:06:53 | Credential rotation | `echo "root:SfbCmZU2eqXG"\|chpasswd` — root password changed |
| 01:06:54 | Defense evasion | `rm -rf /tmp/secure.sh; pkill -9 secure.sh; echo > /etc/hosts.deny` — competitor cleanup |
| 01:06:52–01:07:04 | Reconnaissance | CPU cores, CPU model, RAM, disk, architecture, crontab, logged users |
| 01:07:05 | Session closed | Total duration: ~22 seconds |

**Total time from connection to full persistence establishment: ~3 seconds (steps 1–4).**

The entire sequence is automated. No human operates at this speed. The script fires immediately upon successful authentication and executes a fixed playbook regardless of the target environment.

### Competitor Eviction

The `pkill -9 secure.sh; pkill -9 auth.sh` commands are designed to terminate competing miners' persistence scripts. This behavior indicates the botnet is operating in an environment where multiple automated actors are competing for the same compromised resources. The mdrfckr operator's script is designed to evict competitors and claim exclusive access.

### Cryptomining Profiling

The recon sequence — CPU core count, CPU model, RAM, disk size, architecture (`uname -m`) — is a standard cryptomining suitability assessment. The attacker is evaluating whether the compromised system is worth mining on and which mining binary architecture to deploy. The Raspberry Pi 5 (ARM architecture) would have been identified as a low-value mining target.

---

## Source Infrastructure

97 unique source IPs were observed writing the mdrfckr key across the 21-day window. Whois analysis of the IP list shows:

| Provider | Count | Notes |
|---|---|---|
| ACEVILLEPTELTD-SG | 7 | Singapore-based hosting, most dominant |
| VOLCANO-ENGINE | 2 | ByteDance cloud infrastructure |
| MSFT (Azure) | 2 | Legitimate cloud provider abused |
| PONYNET | 2 | Known bulletproof hosting |
| Latin American ISPs | 5+ | Likely compromised consumer/business machines |

The mix of dedicated cloud VPS infrastructure and Latin American consumer ISPs suggests a two-layer botnet: attacker-controlled cloud nodes running the scanning/exploitation tooling, alongside previously compromised machines being reused as attack infrastructure.

Full IP list: [iocs/mdrfckr_ips.txt](./iocs/mdrfckr_ips.txt)

---

## Detection Guidance

Per the published diary, hassh-based detection rules written against the 2022-era fingerprint `f555226df1963d1d3c09daf865abdc9a` will miss the 2026-era traffic. This sensor confirms both are active simultaneously, meaning detection rules should cover both values.

**Most reliable indicators (unchanged since 2018):**
- authorized_keys SHA-256: `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`
- Public key comment string: `mdrfckr`
- Recon command sequence: `/proc/cpuinfo`, `free -m`, `df -h`, `uname -m`, `crontab -l`, `w`
- Competitor cleanup: `pkill -9 secure.sh`, `pkill -9 auth.sh`, `echo > /etc/hosts.deny`

**Current hassh values to monitor:**
- `f555226df1963d1d3c09daf865abdc9a` (2022-era, still active)
- `03a80b21afa810682a776a7d42e5e6fb` (2026-era, confirmed on this sensor)

---

## Indicators of Compromise

| Type | Value |
|---|---|
| authorized_keys SHA-256 | a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 |
| Public key comment | mdrfckr |
| Hassh (2022-era) | f555226df1963d1d3c09daf865abdc9a |
| Hassh (2026-era) | 03a80b21afa810682a776a7d42e5e6fb |
| SSH client banner (2026) | SSH-2.0-libssh_0.11.1 |
| Payload host (May 9 session) | 8.217.26.62 |
| Payload URL | http://8.217.26.62:7156/linux |
| Payload SHA-256 | 4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865 |
| Domain | m3.mdl66.xyz |

Full IP list: [iocs/mdrfckr_ips.txt](./iocs/mdrfckr_ips.txt)

---

## References

- Trend Micro, Outlaw/Dota reporting (2018/2020)
- port22.dk, "mdrfckrs — part one" (2023): https://blog.port22.dk/mdrfckrs-part-one/
- port22.dk, "mdrfckrs — part two" (2023): https://blog.port22.dk/mdrfckrs-part-two/
- Jesse La Grew, SANS ISC Diary 29878 (May 2023): https://isc.sans.edu/diary/29878
- Gokul Prema Thangavel, SANS ISC Guest Diary (May 2026): https://isc.sans.edu
- VirusTotal: https://www.virustotal.com/gui/file/a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2

---

*Drafting assistance from Claude (Anthropic). All log review, hassh verification, IP enumeration, and comparison against prior reporting conducted from sensor logs and cited public sources.*
