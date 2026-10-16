# Cloud SOC Detection Lab — Wazuh on AWS

A home security operations lab built on AWS. I stood up a **Wazuh SIEM** on an
EC2 instance, simulated **SSH brute-force and account-compromise attacks**
against it, and wrote (and debugged) a **custom detection rule** that catches a
compromise the built-in rules miss — mapped to **MITRE ATT&CK**.

The most valuable part of this project isn't that the rule works; it's the
**detection-engineering log** below, where the first two versions of the rule
*didn't* fire and I had to read what the SIEM actually logged to fix them. That's
the real job.

---

## Architecture

| Component | Detail |
| --- | --- |
| Platform | AWS EC2, `m7i-flex.large` (2 vCPU, 8 GB RAM), region us-east-2 |
| OS | Ubuntu Server 24.04 LTS |
| SIEM | Wazuh 4.14, single-node all-in-one (server + indexer + dashboard) |
| Attacker | `hydra` and `nmap` run on the host; attacks target the monitored box |
| Access control | Security group restricts SSH (22) and dashboard (443) to my IP only |
| Cost control | Instance stopped when idle; whole lab ran inside the AWS free-tier credits |

> Single-host design: the Wazuh manager monitors its own `/var/log/auth.log`, so
> attacks launched on the box are detected with no separate agent. A production
> version would use a dedicated attacker host and scope detections by source IP
> (see "Hardening" below).

---

## Attack simulations

| # | Technique | Tooling | MITRE ATT&CK |
| --- | --- | --- | --- |
| 1 | SSH brute force (failed) | `hydra -l labuser -P wordlist ssh://127.0.0.1` | T1110.001 Password Guessing |
| 2 | Brute force that succeeds (compromise) | wordlist containing the weak password | T1110.001 + T1078 Valid Accounts |

Wazuh automatically tagged the activity under **Password Guessing, Brute Force,
SSH, and Valid Accounts** in its MITRE ATT&CK view.

---

## The custom detection rule

Built-in rules flag the failed logins, but they do **not** specifically alert on
the dangerous case: *a login that succeeds right after a brute-force burst.* That
is what rule `100101` detects. Full rule in [`rules/local_rules.xml`](rules/local_rules.xml):

```xml
<rule id="100101" level="12" timeframe="300">
  <if_group>authentication_success</if_group>
  <if_matched_sid>5763</if_matched_sid>
  <description>Possible compromise: successful login within 5 min of an SSH brute-force burst [T1110.001/T1078]</description>
  <mitre>
    <id>T1110.001</id>
    <id>T1078</id>
  </mitre>
</rule>
```

Install at `/var/ossec/etc/rules/local_rules.xml`, then
`sudo systemctl restart wazuh-manager`.

---

## Detection-engineering log (the real work)

The rule took three iterations. Each failure taught something about matching
detections to what the SIEM *actually* produces, not what you assume it does.

**v1 — matched the wrong brute-force rule.**
I keyed the correlation off rule `5712` (the brute-force ID most tutorials cite).
It never fired. Reading the live events showed this build raises **`5763`**
("sshd: brute force trying to get access to the system") for the burst, not 5712.

**v2 — matched the wrong success event.**
I switched the parent to `5763` and required the successful login to be sshd
rule `5715` with a matching source IP. Still nothing. Grepping
`/var/ossec/logs/alerts/alerts.log` revealed that on Ubuntu the successful login
is reported by **PAM as rule `5501`** ("PAM: Login session opened") — and PAM
session events **carry no source IP**. My `same_srcip` condition could never match.

**v3 — correlate on the group and time window (works).**
Final rule matches the **`authentication_success` group** (which includes the PAM
success) and correlates it to a `5763` brute force within a 300-second window.
It fired at **level 12** on the simulated compromise.

Lesson: *the log you think you're matching often isn't the one your SIEM keys on.*
Verify against `alerts.log`, not assumptions.

---

## Results

Rule `100101` firing at level 12 on the simulated compromise, with the MITRE IDs
attached. See [`screenshots/`](screenshots/):

- `01-mitre-attack.png` — MITRE ATT&CK techniques auto-detected (Password Guessing, Brute Force, SSH, Valid Accounts), plus the failed/successful auth counts
- `02-custom-rule-100101-dashboard.png` — the level-12 "Possible compromise" alerts (rule 100101) in Threat Hunting
- `03-custom-rule-100101-terminal.png` — the same rule firing in `/var/ossec/logs/alerts/alerts.log`, showing it correlates the PAM success with the brute-force burst

---

## How to reproduce (summary)

1. Launch an Ubuntu 24.04 EC2 instance (8 GB RAM); lock the security group to your IP.
2. Install Wazuh: `curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a`
3. Enable password auth (lab only), create a victim user, install `hydra`/`nmap`.
4. Run the brute-force then the successful-guess attack.
5. Drop `rules/local_rules.xml` in `/var/ossec/etc/rules/`, restart the manager, re-run the attacks.
6. Confirm rule `100101` fires: `sudo grep "Rule: 100101" /var/ossec/logs/alerts/alerts.log`

---

## Hardening / what I'd improve for production

- **Dedicated attacker host** so source IPs are real and detections can scope by IP.
- **Scope by source IP** using the sshd-native success event (5715) once a real
  remote login path exists, instead of correlating only by time window.
- **Add Suricata** on the host to feed network-layer detections (port scans,
  exploit attempts) into Wazuh, covering T1046 and beyond.
- **Re-disable password authentication** and rely on keys after the lab.
- **Tune for false positives** — the time-window correlation can fire on a
  legitimate login shortly after an attack; in production I'd require the same
  source IP and a short burst threshold.

---

## Skills demonstrated

Cloud deployment (AWS EC2, security groups, cost control) · SIEM administration
(Wazuh) · detection engineering (custom correlation rules) · MITRE ATT&CK
mapping · attack simulation (hydra, nmap) · log analysis and debugging.
