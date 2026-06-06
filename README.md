# mdrfckr SSH Persistence Campaign — Independent Sensor Corroboration (May–June 2026)

**Analyst:** Daryl Jiminez, SANS ISC Intern  
**Observation Window:** 2026-05-15 → 2026-06-04 (21 days)  
**Sensor:** Single DShield/Cowrie sensor, Raspberry Pi 5  
**Related ISC Diary:** [New Malware Libraries means New Signatures](https://isc.sans.edu) — published 2026-05-15

---

## Overview

On 2026-05-15 — the same day a fellow SANS ISC intern published a diary documenting a new libssh 0.11.x hassh fingerprint for the long-running mdrfckr campaign — my independent DShield sensor began capturing sessions writing the same authorized_keys SHA-256. This diary presents 21 days of single-sensor observation data as independent corroboration of that finding, extends the observation window 14 days beyond the published report, and documents the simultaneous presence of both the 2022-era and 2026-era hassh fingerprints on a single sensor.

The mdrfckr campaign is not new. The authorized_keys SHA-256 `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` has been on VirusTotal since July 2018 and has not changed. Attribution to the Outlaw/Dota threat group, along with the recon playbook and competitor-eviction behavior, is documented across Trend Micro (2018/2020), Anomali, Yoroi, Juniper, CounterCraft, Cybereason, and Kaspersky reporting, as well as the port22.dk two-part hassh analysis (2022–2023) and multiple SANS ISC handler diaries. This diary does not re-establish that attribution — it relies on it.

What this observation adds is narrow but specific: independent second-sensor confirmation of the April 2026 hassh `03a80b21afa810682a776a7d42e5e6fb` (libssh 0.11.1), evidence that both hassh generations are running concurrently through June 2026, and a detailed session-level breakdown of the post-authentication command playbook as captured in Cowrie logs.

---

## Key Numbers

| Metric | Value |
|---|---|
| Observation window | 2026-05-15 → 2026-06-04 (21 days) |
| Total mdrfckr key-write attempts | 106 |
| Unique source IPs | 97 |
| authorized_keys SHA-256 | a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 |
| 2022-era hassh (libssh 0.9.x) hits | 2,306 |
| 2026-era hassh (libssh 0.11.1) hits | 111 |
| Observed session duration (full playbook) | ~22 seconds |

---

## Hassh Observations

The published diary asked whether other DShield operators had independently observed the April 2026 hassh `03a80b21afa810682a776a7d42e5e6fb`. This sensor confirms it across 111 sessions between May 15 and June 4, 2026.

| Hassh | Client Banner | Hits on This Sensor | Period |
|---|---|---|---|
| `f555226df1963d1d3c09daf865abdc9a` | libssh 0.9.5 / 0.9.6 | 2,306 | May–June 2026 |
| `03a80b21afa810682a776a7d42e5e6fb` | libssh 0.11.1 | 111 | May–June 2026 |

Both hassh values are active simultaneously on this sensor through June 4, 2026. This is consistent with an infrastructure that has partially migrated to the newer libssh version while retaining older tooling — though this sensor cannot confirm operator intent from hassh data alone.

---

## Session Analysis — Observed Post-Authentication Playbook

The following is a complete session reconstruction from Cowrie logs for session `8af652604719` (src_ip: 163.7.8.79, 2026-05-23). This command sequence was observed consistently across successful sessions in the dataset.

| Timestamp (UTC) | Event ID | Observed Detail |
|---|---|---|
| 01:06:43 | cowrie.session.connect | SSH connection established |
| 01:06:44 | cowrie.login.success | root / Aa123123123 |
| 01:06:45 | cowrie.command.input | `chattr -ia .ssh; lockr -ia .ssh` |
| 01:06:46 | cowrie.command.input | `.ssh` directory removed, recreated, mdrfckr public key written to `authorized_keys` |
| 01:06:46 | cowrie.session.file_download | authorized_keys written — SHA-256: `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` |
| 01:06:53 | cowrie.command.input | `echo "root:SfbCmZU2eqXG"\|chpasswd` |
| 01:06:54 | cowrie.command.input | `rm -rf /tmp/secure.sh; pkill -9 secure.sh; echo > /etc/hosts.deny` |
| 01:06:52–01:07:04 | cowrie.command.input | System recon commands (see below) |
| 01:07:05 | cowrie.session.closed | Total session duration: ~22 seconds |

**Time from login to authorized_keys write: ~2 seconds.** The command sequence executed without pause, consistent with automated scripted execution rather than manual interaction.

### Defensive Disarm

The first command after login — `chattr -ia .ssh` — removes immutable file attributes from the `.ssh` directory. This is a known defensive countermeasure removal technique documented in prior mdrfckr reporting. The secondary command `lockr -ia .ssh` failed in this session (`cowrie.command.failed`), indicating the tool was not present in the emulated environment.

### Persistence Mechanism

The session wrote the following public key to `~/.ssh/authorized_keys`:

```
ssh-rsa AAAAB3NzaC1yc2EAAAABJ... mdrfckr
```

This key and its SHA-256 (`a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`) match the indicator published by Trend Micro in 2018 and documented consistently across all subsequent mdrfckr reporting. The key has not changed in this campaign across four years of public observation.

### Credential Rotation

Root password was changed via `chpasswd` immediately after key injection. This action, if successful on a real system, would lock out the legitimate administrator while preserving attacker access via the injected SSH key.

### Process Cleanup

The commands `pkill -9 secure.sh` and `pkill -9 auth.sh` target scripts associated with competing automated campaigns. This behavior is consistent with what prior researchers have described as competitor eviction — the script terminates other actors' persistence tooling to claim exclusive access to the compromised resource. This sensor cannot independently confirm the identity or intent of the processes being killed beyond what the command strings suggest.

### Post-Authentication Reconnaissance

The following recon commands were observed in sequence:

```bash
cat /proc/cpuinfo | grep name | wc -l
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
ls -lh $(which ls)
crontab -l
w
uname -m
cat /proc/cpuinfo | grep model | grep name | wc -l
uname -a
whoami
lscpu | grep Model
df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
```

This sequence collects CPU core count, CPU model, available memory, disk capacity, system architecture, current users, and existing cron jobs. Per Trend Micro's published Outlaw analysis, this profile is consistent with pre-deployment system evaluation for cryptomining suitability. **No mining binary was observed deploying in any captured session on this sensor** — Cowrie's emulated environment does not execute real binaries, so deployment behavior beyond the command stage was not observable.

---

## Source Infrastructure

97 unique source IPs were observed writing the mdrfckr key across the 21-day window. Whois analysis shows a mix of provider types:

| Provider | Count | Notes |
|---|---|---|
| ACEVILLEPTELTD-SG | 7 | Singapore-based VPS hosting |
| VOLCANO-ENGINE | 2 | ByteDance cloud platform |
| MSFT (Azure) | 2 | Microsoft Azure — legitimate cloud abused |
| PONYNET | 2 | Budget hosting provider |
| Latin American ISPs (Telefónica Brasil, Total Play MX, others) | 5+ | Consumer/business ISP blocks |

The presence of both dedicated VPS infrastructure and consumer ISP address space is consistent with prior mdrfckr reporting describing a mixed botnet — attacker-controlled scanning nodes alongside previously compromised third-party machines. This sensor cannot confirm this structure from whois data alone; it is an inference consistent with the published research.

Full IP list: [iocs/mdrfckr_ips.txt](./iocs/mdrfckr_ips.txt)

---

## What This Observation Does Not Claim

- **Attribution beyond the published record.** Outlaw/Dota attribution comes from Trend Micro and subsequent vendor research, not from this sensor's data alone.
- **Confirmed cryptomining deployment.** The recon sequence is consistent with mining profiling per prior research, but no mining binary execution was observed on this sensor.
- **Botnet scale.** 97 unique IPs from a single sensor is a lower bound, not a population estimate.
- **Operator intent or identity.** Command strings and infrastructure patterns are documented as observed, not interpreted beyond what the log data directly supports.

---

## Detection Guidance

Per the published diary, hassh-based detection rules written against the 2022-era fingerprint `f555226df1963d1d3c09daf865abdc9a` will not match the 2026-era traffic. This sensor confirms both are active simultaneously, meaning detection coverage requires both values.

**Most reliable indicators (unchanged since 2018 per published research):**
- authorized_keys SHA-256: `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`
- Public key comment string: `mdrfckr`
- Recon command sequence: `/proc/cpuinfo`, `free -m`, `df -h`, `uname -m`, `crontab -l`, `w`
- Cleanup commands: `pkill -9 secure.sh`, `pkill -9 auth.sh`, `echo > /etc/hosts.deny`

**Current hassh values observed on this sensor:**
- `f555226df1963d1d3c09daf865abdc9a` (2022-era, still active June 2026)
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
| Associated domain | m3.mdl66.xyz |

Full IP list: [iocs/mdrfckr_ips.txt](./iocs/mdrfckr_ips.txt)

---

## References

- Trend Micro, Outlaw/Dota reporting (2018/2020): https://www.trendmicro.com/en/research/20/b/outlaw-updates-kit-to-kill-older-miner-versions-targets-more-systems.html
- port22.dk, "mdrfckrs — part one" (2023): https://blog.port22.dk/mdrfckrs-part-one/
- port22.dk, "mdrfckrs — part two" (2023): https://blog.port22.dk/mdrfckrs-part-two/
- Jesse La Grew, SANS ISC Diary 29878 (May 2023): https://isc.sans.edu/diary/29878
- Gokul Prema Thangavel, SANS ISC Guest Diary (May 2026): https://isc.sans.edu
- VirusTotal: https://www.virustotal.com/gui/file/a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2

---

*Drafting assistance from Claude (Anthropic). All log review, hassh verification, IP enumeration, session reconstruction, and comparison against prior reporting conducted from sensor logs and cited public sources.*
