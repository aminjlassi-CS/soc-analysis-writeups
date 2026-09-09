# SOC138 – Detected Suspicious XLS File
## A Walkthrough Lesson for Tier 1 Analysts

**Author:** Amin Jlassi
**Case:** Event ID 77 | 2021-03-13 20:20:58 (UTC+03:00)
**Verdict:** True Positive
**Purpose:** This document works through a training scenario built on a real, publicly documented malware sample, and explains *why* each step matters rather than just what to click. It is written for analysts new to Tier 1 SOC work.

---

**Note on data:** This walkthrough is built on a publicly available malware sample. The file hash, CVE, and external C2 address are real and can be verified on VirusTotal. Internal host names and private IP addresses have been generalized.

---

## How to read this document

Each section has two parts:

- **What happened** — the fact from the case.
- **Why it matters** — the reasoning an analyst applies to that fact.

The second part is what separates an analyst from a ticket-closer. Anyone can read a field value. The job is knowing what that value changes about your decision.

---

## 1. The alert

**What happened:** A detection rule named `SOC138 – Detected Suspicious XLS File` fired at 20:20:58 on 13 March 2021, severity Medium, type Malware, on host HOST-A.

**Why it matters:**

An alert is a *hypothesis*, not a conclusion. The rule saw something matching a pattern it was told to care about — in this case, an Excel file with characteristics associated with malicious documents. The rule does not know whether the file is actually malicious, whether it executed, or whether anything bad resulted. Your job is to test the hypothesis with evidence.

Three outcomes are possible:

| Verdict | Meaning |
|---|---|
| **True Positive** | The alert correctly identified real malicious activity. |
| **False Positive** | The alert fired on benign activity. Common causes: legitimate macro-enabled business templates, security tools' own test files, admin scripts. |
| **True Positive – Blocked** | Real malicious activity, but controls stopped it. Still a true positive; the response differs. |

Never decide the verdict first and then look for evidence to support it. Gather the facts, then let them produce the verdict.

**Note on severity:** The severity assigned by the alert rule is a *starting* value based on the rule's assumptions. It is set before anyone looks at the case. If your investigation finds facts the rule couldn't know, you are expected to adjust severity and say why. We do exactly that in Section 9.

---

## 2. The file

**What happened:**

| Attribute | Value |
|---|---|
| File name | `ORDER SHEET & SPEC.xlsm` |
| Size | 2.66 MB |
| MD5 | `7ccf88c0bbe3b29bf19d877c4596a8d4` |

**Why it matters:**

### 2.1 The extension is `.xlsm`, not `.xls`

This is not a trivial distinction and it is the single most instructive detail in the case.

| Extension | What it is | Can it hold macros? |
|---|---|---|
| `.xls` | Legacy binary Excel format (pre-2007) | Yes |
| `.xlsx` | Modern Excel, XML-based | **No** — macros are stripped |
| `.xlsm` | Modern Excel, **macro-enabled** | Yes |

Microsoft split `.xlsx` and `.xlsm` deliberately in Office 2007 precisely so that macro-carrying files would be visibly distinguishable. When an attacker sends `.xlsm`, they are sending a file whose *entire purpose* is to carry executable code. A spreadsheet of order quantities does not need VBA macros. The format itself is a signal.

The alert rule is named "Suspicious XLS File" because it covers the family of Excel formats. Writing "`.xls/.xlsm`" in your report, as if unsure, is a missed opportunity — you have the exact filename, so name the exact format and explain what it implies.

**But do not stop at the macro.** This sample also carries the tag `cve-2017-11882`. That is an exploit for a stack-overflow flaw in the Microsoft Equation Editor (`EQNEDT32.EXE`), a component Office used to render mathematical formulas. It is delivered inside an embedded OLE object rather than through VBA.

The difference is decisive:

| Execution path | Requires user to enable macros? |
|---|---|
| AutoOpen VBA macro | **Yes** — the user must click "Enable Content" |
| CVE-2017-11882 exploit | **No** — opening the file is enough on an unpatched host |

This sample has both. An analyst who reasons "the user says they never enabled macros, so nothing ran" would reach the wrong conclusion. On a host missing the November 2017 Office patch, the document executes code on open, silently.

The lesson generalises: **check the CVE tags before you reason about user behaviour.** Exploit-based delivery removes the user from the equation entirely.


### 2.2 The filename is social engineering

`ORDER SHEET & SPEC.xlsm` is chosen to look like routine business correspondence. Attackers use invoice, order, shipping, resume, and payroll themes because those are files that employees are *expected* to open without thinking. The filename is part of the attack, and worth noting in a report.

### 2.3 The file size is a weak signal

2.66 MB is large for a spreadsheet holding a small amount of data — and VirusTotal's bundle metadata shows why it matters. The archive contains **38 files that expand to 2.01 GB**.

An `.xlsx`/`.xlsm` file is a ZIP archive. A ratio of roughly 750:1 between compressed and uncompressed size is not how normal spreadsheets behave. Many email gateways and sandboxes impose a maximum decompression size and simply skip anything that exceeds it, logging it as unscannable rather than blocking it. The padding is there to buy that outcome.

Where the alert gives you a suspicious file size, check the bundle metadata on VirusTotal's Details tab. A large expansion ratio is a deliberate evasion technique and belongs in your report.

---

## 3. Hashes — and a trap to avoid

**What happened:** The alert supplied an MD5 hash. The VirusTotal page for the sample was reached through a SHA-256 hash.

**Why it matters:**

A hash is a fixed-length fingerprint of a file's contents. Change one byte, and the hash changes completely. This makes hashes the standard way to identify a specific file across tools and organizations.

Three algorithms appear commonly:

| Algorithm | Length | Notes |
|---|---|---|
| MD5 | 32 hex characters | Fast, widely used in tooling. Cryptographically broken — collisions can be manufactured. Fine for lookups, not for proving authenticity. |
| SHA-1 | 40 hex characters | Also broken. Being phased out. |
| SHA-256 | 64 hex characters | Current standard. Preferred where the choice exists. |

**The trap:** MD5 and SHA-256 of the *same file* look completely different. If your alert gives you `7ccf88c0…` (32 chars, MD5) and your VirusTotal link is `7bcd31bd…` (64 chars, SHA-256), you cannot tell by eye whether they refer to the same file. You must open the **Details** tab on VirusTotal and confirm that the MD5 listed there matches the one from your alert.

Skipping this check means you might be reading threat intelligence for an entirely different piece of malware and attributing it to your incident. Every downstream conclusion — the C2 addresses, the behaviour, the severity — would be wrong.

Always record which algorithm you are citing. Write `MD5: 7ccf88c0…`, not just `hash: 7ccf88c0…`.

**How it resolved in this case.** The Details tab listed all three hashes for the sample:

```
MD5     7ccf88c0bbe3b29bf19d877c4596a8d4   ← matches the alert
SHA-1   23f0506d857d38c3cd5354b80afc725b5f034744
SHA-256 7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813
```

The MD5 matched the value from the alert, confirming the VirusTotal page describes the same file. Record all three in your IOC list — different tools in your environment will expect different algorithms, and giving Tier 2 the full set saves them a lookup.

---

## 4. VirusTotal — reading it properly

**What happened:** The hash was submitted to VirusTotal, which classified the file as malicious and listed associated C2 infrastructure.

**Why it matters:**

VirusTotal aggregates results from many antivirus engines plus sandbox behaviour and community data. It is a reference, not an oracle. Read it with these points in mind:

### 4.1 The detection ratio needs context

A ratio of 32 out of 64 engines is meaningful. A ratio of 3 out of 64 is not, on its own — a handful of detections, especially from engines that lean on heuristics, can indicate a generic packer rather than a specific threat. Look at *what* the engines named it. If several independent vendors give it a consistent family name, that is much stronger than a scattering of generic "Trojan.Generic" hits.

Always record the ratio in your report. "Highly malicious" is an opinion; "45/64" is evidence.

**Community score.** Alongside the engine ratio, VirusTotal shows a crowd-sourced score — here, **−10**. Negative values mean the security community has voted the file as harmful. It carries less weight than engine detections but adds corroboration, particularly for samples where the engine count is borderline.

**Analysis dates matter.** The Details tab shows this sample was created 2020-02-01 and first submitted to VirusTotal 2021-01-28 — roughly six weeks before the incident on 2021-03-13. That is a finding in itself: the file was publicly known malicious before it was delivered, yet both the network and endpoint controls let it through. That is a control-gap issue for security engineering, separate from the incident response.

Also check the **last analysis** date. If the ratio you are citing came from a re-scan years after the incident, say so. Detection rates change over time and a 2026 result does not tell you what your AV would have caught in 2021.

### 4.2 Never upload the file itself

Submit the **hash**, not the file, unless your organisation's policy explicitly permits uploads. Files uploaded to VirusTotal become available to paying subscribers. If the document contains customer data, internal pricing, or anything confidential, uploading it is a data-disclosure incident of your own making. Hash lookups leak nothing.

### 4.3 The Relations tab is where the investigation lives

The Detection tab tells you *whether* the file is bad. The **Relations** tab tells you what to hunt for:

| Section | What you do with it |
|---|---|
| **Contacted IP addresses** | Search proxy/firewall logs for internal hosts reaching these. This is how you find victims the original alert missed. |
| **Contacted domains / URLs** | Search DNS and proxy logs. Malware often resolves a domain rather than connecting to a bare IP — searching only for IPs will miss it. |
| **Dropped files** | Hashes of secondary payloads. Hand these to Tier 2 for endpoint sweeps. |
| **Execution parents** | Files that contained or delivered this one. Often reveals the delivery vector. |

### 4.4 Threat intel ages

The C2 infrastructure listed on VirusTotal may have been sinkholed, taken down, or re-registered since the sample was analysed. An IP that was C2 in 2021 might belong to a legitimate hosting customer now. Check the dates on the analysis, and treat old indicators as leads to verify rather than facts to assert.

---

## 5. Reading behavioural tags

**What happened:** VirusTotal listed a row of tags on the sample: `macros`, `auto-open`, `cve-2017-11882`, `exploit`, `run-file`, `write-file`, `executes-dropped-file`, `run-dll`, `exe-pattern`, `calls-wmi`, `detect-debug-environment`, `long-sleeps`, `checks-user-input`, `clipboard`.

**Why it matters:**

These tags come from sandbox detonation and static analysis. Each one is a behaviour someone observed. Read as a group, they describe what the malware actually does — which is what Tier 2 needs and what turns a report from "the file is bad" into a set of specific things to look for.

Group them by purpose:

| Purpose | Tags | What it tells you |
|---|---|---|
| **Execution** | `macros`, `auto-open`, `macro-run-file` | Code runs automatically when the document opens (if macros are enabled) |
| **Exploitation** | `cve-2017-11882`, `exploit` | A second execution path that bypasses the macro warning entirely |
| **Payload delivery** | `write-file`, `executes-dropped-file`, `exe-pattern` | It drops an executable to disk and runs it — so there is a *second* file to hunt for |
| **Living-off-the-land** | `run-dll`, `calls-wmi` | Uses built-in Windows binaries (`rundll32.exe`, WMI) rather than dropping obvious tooling. Harder to spot; maps to T1218.011 and T1047 |
| **Anti-analysis** | `detect-debug-environment`, `long-sleeps` | Checks whether it is being watched, and stalls to outlast sandbox timeouts (T1497) |
| **Data access** | `checks-user-input`, `clipboard` | Reads user input and clipboard contents — possible credential theft |

Three practical consequences:

1. **`executes-dropped-file` means the hash you have is not the whole story.** There is a second payload on disk. Ask Tier 2 for its hash and add it to the IOC list.
2. **`long-sleeps` means a quiet host is not a clean host.** The malware may deliberately do nothing for hours. Do not release a contained host because "nothing happened yet."
3. **`detect-debug-environment` means sandbox results may be incomplete.** If the sample detected the analysis environment, it may have withheld its real behaviour. Absence of observed C2 in a sandbox report is not evidence of absence in production.

**Alternate filenames** on the same page also carry information. This sample appeared as `ORDER SHEET & SPEC.xlsm`, `ORDER_SHEET_SPEC.xlsm`, and `Nouvelle version du cahier des charges.xlsm`. Multiple languages indicate a broad distribution campaign rather than targeted delivery — and give your mail-gateway search additional strings to hunt for.

---

## 6. Log correlation — turning intel into findings

**What happened:** C2 addresses from VirusTotal were checked against internal traffic logs. Host HOST-B (10.20.30.58) was found connecting to 209.197.3.8 on port 80.

**Why it matters:**

This is the core Tier 1 skill: taking an external indicator and asking *did anything inside our network touch this?*

### 6.1 Reading the connection

```
Source:      10.20.30.58 : 49874      (HOST-B, ephemeral port)
Destination: 209.197.3.8  : 80         (C2, HTTP)
Log source:  Proxy
```

- **Source port 49874** is an *ephemeral port* — a temporary, high-numbered port (typically 49152–65535 on Windows) that the OS assigns to outbound connections. It carries no meaning. Do not report it as significant; it changes on every connection.
- **Destination port 80** is HTTP. Malware favours 80 and 443 because that traffic is expected to leave every network on earth. A connection to an odd port stands out; a connection to port 80 blends into the noise. This is why indicator-based hunting matters — you cannot spot this by looking for unusual ports.
- **Port 80 means unencrypted.** This is useful: if you have full packet capture or proxy content logging, the actual C2 traffic may be readable. On port 443 it would not be. Note this for Tier 2.

### 6.2 Match your timestamps

Every log entry you cite must fall in a window that makes sense relative to the alert. If your alert is dated 2021 and your proxy row is dated 2023, something is wrong — wrong log pulled, wrong timezone, or wrong environment. A reviewer will catch it, and it undermines everything else in the report.

Timezones are the usual culprit. This alert is stamped `+03:00`; your proxy might log in UTC. A three-hour offset can make a connection appear to precede the alert that should have caused it. Normalise everything to one timezone and say which one you used.

### 6.3 Don't over-claim

The evidence here supports two *separate* statements:

- The malicious file was delivered to HOST-A.
- HOST-B connected to a C2 address associated with that file.

It does **not** support "both hosts connected to C2." Writing that would be an unsupported claim, and Tier 2 would waste time looking for HOST-A's beacon traffic that you never actually found. Report what you observed, per host, and flag the gap explicitly as an open question.

That gap — how did HOST-B get infected if HOST-A received the file? — is a genuine finding in its own right. Possible answers: HOST-B received the same attachment separately, the infection moved laterally, or HOST-B is compromised by something unrelated sharing infrastructure. Naming the question is the correct Tier 1 action. Answering it is Tier 2's job.

---

## 7. Device Action — the field that decides everything

**What happened:** `Device Action: Allowed`

**Why it matters:**

This single field determines what kind of incident you are dealing with.

| Value | Meaning | Implication |
|---|---|---|
| **Blocked / Denied** | Security control stopped the traffic or transfer | The attack failed at this stage. Still investigate, but the fire is out. |
| **Allowed** | The control permitted it through | The file reached the host. The connection completed. Treat as live. |

"Allowed" means your perimeter did not stop this. The file arrived. If the C2 connection was also allowed, data could have left and instructions could have come back.

Analysts routinely forget to state this in the write-up. It is the first thing an incident responder looks for, because it changes their opening move from "verify and document" to "assume compromise and contain."

**Related field: quarantine status.** In this case the malware was **not quarantined**, meaning endpoint protection did not isolate the file after delivery. Two independent controls — network and endpoint — both failed to stop it. That is worth stating plainly, and it is a control-gap finding your security engineering team should hear about, separate from the incident itself.

---

## 8. MITRE ATT&CK — using it rather than citing it

**What happened:** The alert maps to `T1112 – Modify Registry`.

**Why it matters:**

MITRE ATT&CK is a catalogue of observed adversary behaviours, organised by tactic (the goal) and technique (the method). Its value is that it converts a vague statement like "the malware does bad things" into a specific, checkable claim.

`T1112 – Modify Registry` tells you the sample writes to the Windows registry. For macro-based Office malware, that typically means one of:

- **Disabling macro security** — setting `VBAWarnings` under the Office Trust Center keys so future documents run macros without prompting.
- **Establishing persistence** — writing to `Run` / `RunOnce` keys so the payload restarts after reboot.
- **Storing configuration** — some families keep C2 addresses or campaign IDs in obscure registry values.

That converts directly into an instruction for Tier 2: *check Run keys and Office Trust Center settings on both hosts.* A technique ID pasted into a report with no interpretation gives the next analyst nothing. The interpretation is the value you add.

### One alert, several techniques

The alert supplied only T1112, but the behavioural tags support a fuller mapping. Building it yourself is normal analyst work:

| Technique | Evidence from the sample |
|---|---|
| **T1566.001** – Phishing: Spearphishing Attachment | Business-themed filename, delivered as an attachment |
| **T1204.002** – User Execution: Malicious File | AutoOpen macro requiring the user to enable content |
| **T1203** – Exploitation for Client Execution | CVE-2017-11882 embedded exploit |
| **T1218.011** – System Binary Proxy Execution: Rundll32 | `run-dll` tag |
| **T1047** – Windows Management Instrumentation | `calls-wmi` tag |
| **T1112** – Modify Registry | Supplied by the alert |
| **T1497** – Virtualization/Sandbox Evasion | `detect-debug-environment`, `long-sleeps` |
| **T1071.001** – Application Layer Protocol: Web | C2 over HTTP port 80 |

Laid out this way, the mapping is no longer decoration — it is a coverage check. Each row is a place your detections either fire or do not, and a gap in the table is a detection-engineering ticket.

---

## 9. Severity — when to raise it

**What happened:** Alert severity was Medium. The investigation supports High.

**Why it matters:**

Severity should reflect what you found, not what the rule guessed before anyone looked. Here, three findings justify raising it:

1. The file transfer was **allowed** — not a blocked attempt.
2. The file was **not quarantined** — it stayed on the host.
3. **Successful outbound C2 communication** was observed — the infrastructure is live and reachable from inside.

The rule that assigned "Medium" knew none of these things.

**The discipline:** if you change severity, state the reason in the same section. An unexplained "Severity: High" in a report whose ticket says "Medium" looks like an error rather than a judgement. Show the reasoning and it becomes analysis.

---

## 10. Containment — scope and limits

**What happened:** Both hosts were network-isolated. The incident was escalated to Tier 2.

**Why it matters:**

### 10.1 Why isolation, and why not more

Network isolation cuts the host off from the local network and the internet while leaving it powered on. It stops C2 communication, blocks data exfiltration, and prevents lateral movement — while preserving the machine's state for forensics.

What you should *not* do at Tier 1:

- **Do not power the machine off.** Volatile memory contains running processes, injected code, decryption keys, and network state. Powering down destroys all of it.
- **Do not reimage.** That deletes the evidence needed to understand what happened and whether it spread.
- **Do not delete the file.** It is evidence, and Tier 2 may want to detonate it in a sandbox.

Containment is a holding action. Eradication and recovery come after investigation.

### 10.2 Containing on suspicion is correct

HOST-B's infection vector was unconfirmed at the time of containment. Isolating anyway was the right call: a host confirmed to be talking to C2 infrastructure is a live risk regardless of how it got there. The cost of isolating a machine for a few hours is far lower than the cost of letting an active compromise run while you finish investigating.

### 10.3 Verify your host identifiers

Isolation is executed against an IP address or hostname. A single mistyped digit — `10.20.30.4` instead of `10.20.30.41` — isolates an uninvolved employee's workstation while the compromised host stays online. Read the IP off the alert field, copy it, and check it against the containment action before you submit.

---

## 11. Writing the escalation

Tier 2 reads your report to decide where to start. Structure it so they can act without re-doing your work:

1. **What triggered this** — alert name, event ID, time, host.
2. **What the file is** — name, format, hash with algorithm named, VirusTotal ratio.
3. **What controls did** — allowed or blocked, quarantined or not.
4. **What you observed, per host** — separate findings, separately evidenced.
5. **What you did** — containment actions with timestamps.
6. **What you could not determine** — open questions, stated plainly.
7. **Verdict, with one line of justification.**

Two habits worth building:

- **Every claim gets evidence.** "Two hosts connected to C2" is a claim. The proxy log rows are the evidence. If you cannot point to the evidence, soften the claim.
- **State the unknowns.** Analysts sometimes hide gaps because they look like failure. The opposite is true: an unstated gap becomes an assumption someone else acts on. A named gap becomes the next investigative step.

---

## 12. Summary — the reasoning chain

```
Alert fires on suspicious Excel file (hypothesis)
        ↓
Extract hash → confirm maliciousness via VirusTotal (is it real?)
        ↓
Verify hash algorithms match (am I looking at the right file?)
        ↓
Pull C2 indicators from Relations tab (what should I hunt for?)
        ↓
Correlate against internal logs (did anyone touch it?)
        ↓
Check Device Action + quarantine status (did controls stop it?)
        ↓
    Blocked ─────────────→ True Positive, attack contained by controls
        ↓
    Allowed
        ↓
Contain affected hosts (stop the bleeding)
        ↓
Assess severity against findings (does Medium still fit?)
        ↓
Escalate with evidence and open questions (hand off cleanly)
        ↓
Verdict: True Positive
```

---

## 13. Practice questions

Test yourself before reading back through:

1. Why does `.xlsm` matter more than `.xls` in a report?
2. Your alert gives a 32-character hash and your VirusTotal link uses a 64-character hash. What must you check, and what breaks if you skip it?
3. What does `Device Action: Allowed` change about your response?
4. Why is source port 49874 not worth reporting?
5. Why is a C2 connection over port 80 harder to spot than one over port 4444 — and what advantage does port 80 give the investigator?
6. Why should you never power off a compromised host at Tier 1?
7. Your evidence shows the file on Host A and C2 traffic from Host B. Write the finding without over-claiming.
8. The rule assigned Medium severity. Under what conditions should you raise it, and what must accompany the change?
9. A user insists they never clicked "Enable Content." Why is that not sufficient to rule out execution for this sample?
10. The sample is tagged `executes-dropped-file`. What does that add to your IOC list that you do not currently have?
11. A contained host has shown no suspicious activity for six hours. Which tag on this sample argues against releasing it?
12. A 2.66 MB spreadsheet expands to 2.01 GB. What is that likely designed to defeat?
