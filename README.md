# SOC138 – Detected Suspicious XLS File
## A Walkthrough Lesson for Tier 1 Analysts

| Field | Value |
| --- | --- |
| Author | Amin Jlassi |
| Case | Event ID 77 — 2021-03-13 20:20:58 (UTC+03:00) |
| Verdict | True Positive |

**Purpose:** This document works through a training scenario built on a real, publicly documented malware sample, and explains *why* each step matters rather than just what to click. It is written for analysts new to Tier 1 SOC work.

---

**Note on data:** This walkthrough is a training scenario built on a publicly available malware sample. The file hashes and CVE reference are real and can be verified on VirusTotal. The external IP address is the one the analyst associated with the sample during the exercise; its relationship to the sample and its function are not independently established here. Internal host names and private IP addresses have been generalized.

---

## What this is

A step-by-step walkthrough of a malicious-document alert, written for analysts new to Tier 1 SOC work. It covers alert triage, hash verification, threat-intelligence enrichment, IOC correlation against logs, containment, severity assessment, MITRE ATT&CK mapping, and escalation writing — with the reasoning behind each step rather than just the actions.

The formal incident report for the same case is in [reports/](reports/). Sources are listed in [References](#references) at the end.

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
| --- | --- |
| **True Positive** | The alert correctly identified real malicious activity. |
| **False Positive** | The alert fired on benign activity. Common causes: legitimate macro-enabled business templates, security tools' own test files, admin scripts. |
| **True Positive – Blocked** | Real malicious activity, but controls stopped it. Still a true positive; the response differs. |

Never decide the verdict first and then look for evidence to support it. Gather the facts, then let them produce the verdict.

**Note on severity:** The severity assigned by the alert rule is a *starting* value based on the rule's assumptions. It is set before anyone looks at the case. If your investigation finds facts the rule couldn't know, you are expected to adjust severity and say why. We do exactly that in Section 9.

---

## 2. The file

**What happened:**

| Attribute | Value |
| --- | --- |
| File name | `ORDER SHEET & SPEC.xlsm` |
| Size | 2,793,487 bytes (2.66 MiB; shown as "2.66 MB" by the alert and VirusTotal) |
| MD5 | `7ccf88c0bbe3b29bf19d877c4596a8d4` |

**Why it matters:**

### 2.1 The extension is `.xlsm`, not `.xls`

The distinction is worth understanding precisely, because it is easy to over-read.

| Extension | What it is | Can it hold macros? |
| --- | --- | --- |
| `.xls` | Legacy binary Excel format (pre-2007) | Yes |
| `.xlsx` | Modern Excel, XML-based | **No** — macros are stripped |
| `.xlsm` | Modern Excel, **macro-enabled** | Yes |

Microsoft split `.xlsx` and `.xlsm` in Office 2007 so that macro-carrying files would be visibly distinguishable. What the extension tells you, precisely, is that the *format can store VBA macro code*. It does not tell you that macros are present in this particular file, that they are malicious, or that they ran. Those are three separate questions, each needing its own evidence.

Be careful not to over-read it. Macros are legitimate and common — finance teams, reporting tools, and internal templates use them constantly, and plenty of real business workbooks arrive as `.xlsm`. The format is not evidence of malice on its own. What raises its significance is the combination: a macro-capable file, arriving unexpectedly, with a business-themed name, automatic-execution behavior, exploit indicators, and a malicious reputation verdict. Any one of those alone means little. Together they are the case.

The alert rule is named "Suspicious XLS File" because it covers the family of Excel formats. Writing "`.xls/.xlsm`" in your report, as if unsure, is a missed opportunity — you have the exact filename, so name the exact format and explain what it implies.

**But do not stop at the macro.** This sample also carries the tag `cve-2017-11882`. That is an exploit for a stack-overflow flaw in the Microsoft Equation Editor (`EQNEDT32.EXE`), a component Office used to render mathematical formulas. It is delivered inside an embedded OLE object rather than through VBA.

The difference is decisive:

| Execution path | Depends on the user enabling macros? |
| --- | --- |
| Potential automatic macro execution | **Usually** — in a default configuration the user must click "Enable Content." Trusted Locations, Trusted Publishers, or Group Policy can allow macros to run without that prompt |
| CVE-2017-11882 exploit | **No** — on a vulnerable, unprotected Office installation, opening the file may be enough |

VirusTotal's tags *suggest* two potential execution mechanisms: potential automatic macro execution and Equation Editor exploitation. The word matters: the tags come from automated analysis, and this walkthrough has not examined the VBA code or the OLE object directly, so no specific procedure is named. They are potential mechanisms, not confirmed working chains, and execution on any real host is unconfirmed. Even so, an analyst who reasons "the user says they never enabled macros, so nothing ran" is relying on a premise that these potential mechanisms do not support — an exploit path would not need the macro prompt.

Note the qualifier. Exploitation is not automatic: it depends on the Office version, whether the November 2017 patch is applied, and whether protections such as Protected View were in effect. The correct conclusion is not "it definitely ran" — it is "macro settings alone cannot rule execution out, so patch status has to be checked."

The lesson generalizes: **check the CVE tags before you reason about user behavior.** Exploit-based delivery can remove the user's decision from the chain entirely.


### 2.2 The filename is social engineering

`ORDER SHEET & SPEC.xlsm` is chosen to look like routine business correspondence. Attackers use invoice, order, shipping, resume, and payroll themes because those are files that employees are *expected* to open without thinking. The filename is part of the attack, and worth noting in a report.

### 2.3 The file size is a weak signal

2,793,487 bytes (2.66 MiB, or 2.79 MB) is large for a spreadsheet holding a small amount of data — and VirusTotal's bundle metadata shows why it matters. (A unit note in passing: both the alert and VirusTotal label the file "2.66 MB," which is the MiB figure with the wrong unit. Record the byte count when you can; it removes the ambiguity.) The archive contains **38 files that expand to 2.01 GB**.

An `.xlsx`/`.xlsm` file is a ZIP archive. A large gap between compressed and uncompressed size is not how normal spreadsheets behave. Decompression limits in a gateway or sandbox can prevent complete inspection of an oversized archive — but whether the file is then blocked, quarantined, or delivered depends entirely on the product and its configuration. Do not assume it is silently passed.

So a ratio like this **may indicate decompression-based evasion**. Note the hedge: you have observed a characteristic, not proven an intention. Embedded images and legacy objects can inflate a workbook for entirely ordinary reasons. Write it as an observation worth flagging, and let the sandbox and endpoint evidence establish whether evasion was the point.

Where the alert gives you a suspicious file size, check the bundle metadata on VirusTotal's Details tab.

---

## 3. Hashes — and a trap to avoid

**What happened:** The alert supplied an MD5 hash. The VirusTotal page for the sample was reached through a SHA-256 hash.

**Why it matters:**

A hash is a fixed-length fingerprint of a file's contents. Change one byte, and the hash changes completely. This makes hashes the standard way to identify a specific file across tools and organizations.

Three algorithms appear commonly:

| Algorithm | Length | Notes |
| --- | --- | --- |
| MD5 | 32 hex characters | Fast, widely used in tooling. Cryptographically broken — collisions can be manufactured. Fine for lookups, not for proving authenticity. |
| SHA-1 | 40 hex characters | Also broken. Being phased out. |
| SHA-256 | 64 hex characters | Current standard. Preferred where the choice exists. |

**The trap:** MD5 and SHA-256 of the *same file* look completely different. If your alert gives you `7ccf88c0…` (32 chars, MD5) and your VirusTotal link is `7bcd31bd…` (64 chars, SHA-256), you cannot tell by eye whether they refer to the same file. You must open the **Details** tab on VirusTotal and confirm that the MD5 listed there matches the one from your alert.

Skipping this check means you might be reading threat intelligence for an entirely different piece of malware and attributing it to your incident. Every downstream conclusion — the C2 addresses, the behavior, the severity — would be wrong.

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

**What happened:** The hash was searched on VirusTotal. The report showed a high detection ratio and, on the Relations tab, network infrastructure seen during the sample's analysis.

**Why it matters:**

VirusTotal aggregates results from many antivirus engines plus sandbox behavior and community data. It is a reference, not an oracle. Read it with these points in mind:

### 4.1 The detection ratio needs context

A ratio of 32 out of 64 engines is a strong signal. A ratio of 3 out of 64 needs more work before you can say anything — but it does not mean the file is clean. A single detection from a reliable vendor, especially one naming a specific malware family, can be more informative than a dozen generic heuristic hits. Low ratios are also normal for genuinely new samples that most engines have not caught up with yet.

So do not treat the number as the answer. Look at *what* the engines named it. Several independent vendors converging on a consistent family name is strong. A scattering of "Trojan.Generic" is weak. One credible vendor naming a known family is worth investigating regardless of the count.

Always record the ratio in your report. "Highly malicious" is an opinion; "45/64" is evidence.

**Community score.** Alongside the engine ratio, VirusTotal shows a crowd-sourced score — here, **−10**. Negative values mean the security community has voted the file as harmful. It carries less weight than engine detections but adds corroboration, particularly for samples where the engine count is borderline.

**Analysis dates matter, and they are three different things.** VirusTotal records a *first submission* date, a *last analysis* date, and the *current results*. They are not interchangeable.

- First submission for this sample: 2021-01-28, roughly six weeks before the incident date of 2021-03-13. That establishes the sample was known to the platform by then. It does **not** establish what the detection ratio was on that date, or that anyone had classified it malicious.
- Last analysis: previously reported as 2026-09-09, though that exact timestamp is not independently verified from the retained evidence. The 45/64 figure comes from a re-scan years after the incident date; treat it as "what engines detect at the time of the analysis you are reading," and record the analysis date from the page in front of you rather than relying on a figure carried over from notes.
- The file creation timestamp of 2020-02-01 is document metadata and can be altered or inherited from a template. Treat it as weak.

So the defensible statement is: the sample existed in VirusTotal before the incident. Saying "it was publicly known malicious and the controls still let it through" reads well but claims a historical verdict the data does not show. If you want to make a control-coverage argument, you need time-specific reputation data, and you need to know which controls actually inspected the file.

### 4.2 Search the hash; upload the file only if authorized

Submit the **hash**, not the file, unless your organization's policy explicitly permits uploads. Files uploaded to VirusTotal become available to paying subscribers. If the document contains customer data, internal pricing, or anything confidential, uploading it is a data-disclosure incident of your own making.

A hash lookup is far safer, but it is not silent. The service records the query, and the fact that a particular hash was searched at a particular time is itself information about your organization. For most work this is an acceptable trade. Where it is not — a sensitive investigation, or intelligence you do not want to signal interest in — use an internal or offline reputation source instead.

### 4.3 The Relations tab is where the investigation lives

The Detection tab tells you *whether* the file is bad. The **Relations** tab tells you what to hunt for:

| Section | What you do with it |
| --- | --- |
| **Contacted IP addresses** | Search proxy/firewall logs for internal hosts reaching these. This is how you find victims the original alert missed. |
| **Contacted domains / URLs** | Search DNS and proxy logs. Malware often resolves a domain rather than connecting to a bare IP — searching only for IPs will miss it. |
| **Dropped files** | Hashes of secondary payloads. Hand these to Tier 2 for endpoint sweeps. |
| **Execution parents** | Files that contained or delivered this one. Often reveals the delivery vector. |

### 4.4 Threat intel ages

The C2 infrastructure listed on VirusTotal may have been sinkholed, taken down, or re-registered since the sample was analyzed. An IP that was C2 in 2021 might belong to a legitimate hosting customer now. Check the dates on the analysis, and treat old indicators as leads to verify rather than facts to assert.

---

## 5. Reading behavioral tags

**What happened:** VirusTotal listed a row of tags on the sample: `macros`, `auto-open`, `cve-2017-11882`, `exploit`, `run-file`, `write-file`, `executes-dropped-file`, `run-dll`, `exe-pattern`, `calls-wmi`, `detect-debug-environment`, `long-sleeps`, `checks-user-input`, `clipboard`.

**Why it matters:**

These are reported VirusTotal indicators, from its sandbox detonation and static analysis. The underlying analysis traces were not independently examined here; the tags provide leads for further investigation, not findings about your hosts.

Keep the distinction sharp: a tag is a lead. `run-dll` suggests DLL-based execution; it does not prove `rundll32.exe` ran on the machine in front of you. Only endpoint process telemetry establishes that. Write these into a report as things to check, not things that happened.

Group them by purpose:

| Purpose | Tags | What it tells you |
| --- | --- | --- |
| **Execution** | `macros`, `auto-open`, `macro-run-file` | Reported tags suggest macro-based automatic execution in the sandbox. On a real host this depends on macro settings and Office protections |
| **Exploitation** | `cve-2017-11882`, `exploit` | Reported tags suggest a possible non-macro execution path on a vulnerable Office installation |
| **Payload delivery** | `write-file`, `executes-dropped-file`, `exe-pattern` | Reported tags suggest the sample dropped and executed a second file; the underlying sandbox trace was not independently examined. An artifact type to hunt for, not proof a second file exists on your host |
| **Living-off-the-land** | `run-dll`, `calls-wmi` | Suggests use of built-in Windows binaries (`rundll32.exe`, WMI) rather than obvious dropped tooling. Harder to spot; points toward T1218.011 and T1047, to be confirmed with process telemetry |
| **Anti-analysis** | `detect-debug-environment`, `long-sleeps` | Reported tags suggest a debugger check and stalling to outlast sandbox timeouts. These map to two different techniques — T1622 (Debugger Evasion) and T1497.003 (Time Based Checks) — each to be confirmed against the underlying behavior separately |
| **Sandbox evasion / data access** | `checks-user-input`, `clipboard` | `checks-user-input` can serve sandbox evasion (checking for a real user) as readily as data theft; `clipboard` access suggests possible data or credential collection. Which one applies is not established by the tag alone |

Three practical consequences:

1. **Dropped file.** `executes-dropped-file` means the hash you have may not be the whole story. The tag reports that the sample dropped and executed another file in analysis; this walkthrough did not examine the underlying trace, and it does not establish that a second file exists on your hosts. What it gives you is an artifact type to hunt for, and a request for Tier 2: obtain the dropped file's hash so it becomes a searchable indicator.
2. **Delayed behavior.** `long-sleeps` means a quiet host is not necessarily a clean host. The malware may deliberately do nothing for hours. Do not release a contained host because "nothing happened yet."
3. **Incomplete sandbox picture.** `detect-debug-environment` means sandbox results may be incomplete. If the sample detected the analysis environment, it may have withheld its real behavior. Absence of observed C2 in a sandbox report is not evidence of absence in production.

**Alternate filenames** on the same page also carry information. This sample appeared as `ORDER SHEET & SPEC.xlsm`, `ORDER_SHEET_SPEC.xlsm`, and `Nouvelle version du cahier des charges.xlsm`. Filenames in more than one language **may indicate distribution across multiple language groups**, though the list only tells you how submitters named the file — not how it was distributed or to whom. The practical value is concrete regardless: each variant is another string for your mail-gateway search.

---

## 6. Log correlation — turning intel into findings

**What happened:** Addresses from the sample's VirusTotal Relations tab were checked against internal traffic logs. A proxy record dated 2023-04-17 lists HOST-B (10.20.30.58) and destination 209.197.3.8:80. Its action value was not captured. The completed exchange, the sample association, and the record's relevance to the 2021 alert all remain unverified — the significance of that is worked through in 6.2 and 6.3.

**Why it matters:**

This is the core Tier 1 skill: taking an external indicator and asking *did anything inside our network touch this?*

### 6.1 Reading the connection

```
Source:      10.20.30.58 : 49874      (HOST-B, ephemeral port)
Destination: 209.197.3.8  : 80         (destination address and port from the record)
Log source:  Proxy
```

- **Source port 49874** is an *ephemeral port* — a temporary, high-numbered port (typically 49152–65535 on Windows) that the OS assigns to outbound connections. It is not suspicious in itself. Record source and destination addresses and ports, protocol, and timestamp together; they are your correlation key across systems. But account for NAT and proxy behavior when correlating — a device in the path can rewrite the source address and port, and ephemeral ports are reused over time, so the same pair can refer to different connections at different moments.
- **Destination port 80** is conventionally HTTP. Malware favors 80 and 443 because that traffic is expected to leave every network. A connection to an odd port stands out; a connection to port 80 blends into the noise. This is why indicator-based hunting matters — you cannot spot this by looking for unusual ports.
- **Port 80 usually carries plaintext HTTP** — which means that with full packet capture or proxy content logging, the C2 traffic may be readable. Two caveats. A port number is a convention, not a guarantee: anything can be sent over 80, including TLS or a custom protocol. And plaintext HTTP can still carry an encrypted or encoded payload inside the body. Note it for Tier 2 as a possibility worth checking, not as a certainty.

### 6.2 Match your timestamps

Every log entry you cite must fall in a window that makes sense relative to the alert.

**This case has a live example.** The alert is stamped 2021-03-13. The proxy record is stamped 2023-04-17. Two years apart. That is not a rounding problem — either the wrong log range was pulled, or the record belongs to a different event, or the export is unreliable. It remains unresolved in this case data.

What matters is what you do about it. You do not quietly drop the record, and you do not cite it as though the dates line up. You report the discrepancy and state that the record cannot corroborate the alert until it is reconciled. An unresolved gap that is *named* is a finding; the same gap left unmentioned is a hole a reviewer will find for you.

**And you follow the consequence through.** If the record cannot be correlated, it cannot support anything downstream: not the severity argument, not the ATT&CK mapping, not the verdict. In this case that means HOST-B's traffic is *excluded from the incident findings* pending validation of the source data, and HOST-B's status becomes "unresolved" rather than "suspected compromise." The sections that follow show where that exclusion has to propagate. It is easy to note a discrepancy in one paragraph and keep leaning on the evidence three sections later; the reviewer will notice.

Timezones are the usual culprit for smaller offsets. This alert is stamped `+03:00`; your proxy might log in UTC. A three-hour shift can make a connection appear to precede the alert that should have caused it. Normalize everything to one timezone and say which one you used.

### 6.3 Don't over-claim

Before the timestamp problem surfaced, the evidence appeared to support two *separate* statements:

- The malicious file was delivered to HOST-A.
- HOST-B generated outbound traffic to an address associated with that file.

Even at that stage, it did **not** support "both hosts connected to C2." Writing that would have been an unsupported claim, and Tier 2 would have wasted time looking for HOST-A's beacon traffic that was never found. Report what you observed, per host, and flag the gap explicitly.

After the timestamp problem, the second statement falls away entirely until the record is validated. The lesson holds either way: each host gets its own finding, evidenced separately, and a finding that loses its evidence is withdrawn rather than softened.

**Check where the association came from, too.** Before you write "an address associated with the malicious sample," be sure you actually saw it on the Relations tab, and say so. It is easy to carry a linkage forward from memory or from a colleague's note and end up presenting it as verified. If you cannot point to where the association came from, write it as pending confirmation. The same discipline applies to the evidence behind every noun in your report.

**One more phrase to watch: "successful C2 communication."** It bundles three separate questions, and each needs its own evidence:

1. *Was traffic attempted?* A proxy row records a connection attempt. Repeated rows show repeated attempts, not a completed exchange.
2. *Did communication occur?* This needs bytes transferred in both directions or a completed session. Read an HTTP response carefully — a proxy can generate its own response (a block page, an error) without the destination ever answering.
3. *Was it command and control?* This is a claim about the *purpose* of the exchange, and nothing above establishes it. Regular intervals are suggestive but not proof — legitimate software polls on a schedule too. A known C2 protocol signature or commands observed in the traffic get you closer. Appearing in a VirusTotal contacted-IP list establishes that the sample contacted the address in a sandbox — not that the address is attacker-owned or serves a C2 function.

Absent evidence for all three, do not assert permission, protocol, or association that the fields do not show. Write what the record actually contains: *a proxy record lists the host and destination address:port; its action value was not captured, and the completed exchange, sample association, and relevance to the alert remain unverified.* It is longer, and it is what you can defend.

The question to ask is not "how did HOST-B get infected?" — that presumes an infection the evidence does not establish. It is "does the evidence establish that HOST-B was compromised at all?" As the case stands, the answer is no: the only record is out of window and its action value was not captured. Correcting the date would not by itself establish infection; it would only make the connection attempt relevant enough to investigate. The prior question for Tier 2 is whether a correctly dated record for HOST-B exists inside the incident window.

---

## 7. Device Action — the field that shapes your response

**What happened:** `Device Action: Allowed` on the alert event.

**Why it matters:**

This single field shapes what kind of incident you are dealing with.

**First, check what the field describes.** Device Action appears on multiple record types — a mail gateway verdict, an endpoint control decision, a proxy connection. The value tells you what *that specific control* did about *that specific event*. In this case it sits on the alert event for HOST-A, so it describes the document transfer, not HOST-B's later proxy traffic. Do not carry one record's Device Action across to a different event; check each record separately and say in your report which is which.

| Value | Meaning | Implication |
| --- | --- | --- |
| **Blocked / Denied** | Security control stopped the traffic or transfer | This stage of the attack was prevented. Still investigate — other stages, hosts, or delivery attempts may have succeeded. |
| **Allowed** | The control reports it permitted this event | The event was not blocked by this control. Confirm from the relevant logs what actually followed — delivery, connection, or exchange. |

"Allowed" means this control did not stop this event. For a file-transfer event, that means the file was not blocked at that point. It does not, on its own, tell you the file executed, or that any later network connection completed — those are separate events with their own records.

Analysts routinely forget to state the Device Action in the write-up. It is one of the first things an incident responder looks for, because an allowed transfer of malicious content shifts the opening move from "verify and document" toward "treat as a live delivery and investigate accordingly."

**Related field: quarantine status.** In this case the file was recorded as **not quarantined** — the case data contains no record of an endpoint control isolating it. Combined with the allowed transfer, that supports urgent containment and a review of the relevant controls. What it does *not* establish is which endpoint controls inspected the file, whether any did, or why no quarantine occurred. "Two controls failed" sounds decisive, but it assumes two controls looked. Raise it with security engineering as a coverage question, not a conclusion.

---

## 8. MITRE ATT&CK — using it rather than citing it

**What happened:** The alert maps to `T1112 – Modify Registry`.

**Why it matters:**

MITRE ATT&CK is a catalog of observed adversary behaviors, organized by tactic (the goal) and technique (the method). Its value is that it converts a vague statement like "the malware does bad things" into a specific, checkable claim.

`T1112 – Modify Registry` says the alert associated the sample with registry modification. It does not tell you which key changed, or that the change occurred on either host — the mapping came from the alert, not from host telemetry. For macro-based Office malware the usual candidates, all *hunting hypotheses* rather than observations, are:

- **Disabling macro security** — setting `VBAWarnings` under the Office Trust Center keys so future documents run macros without prompting.
- **Establishing persistence** — writing to `Run` / `RunOnce` keys so the payload restarts after reboot.
- **Storing configuration** — some families keep addresses or campaign IDs in obscure registry values.

That converts into a defensible instruction for Tier 2: *review registry telemetry on the affected hosts for these key types.* A technique ID pasted into a report with no interpretation gives the next analyst nothing; the interpretation is the value you add — as long as it points to a check rather than asserting the behavior happened.

### One alert, several techniques

The alert supplied only T1112, but the sample's characteristics support a fuller mapping. Building one is normal analyst work — provided you record how confident each row is:

| Technique | Basis | Confidence |
| --- | --- | --- |
| **T1112** – Modify Registry | Supplied by the alert mapping | Given by the alert |
| **T1566.001** – Phishing: Spearphishing Attachment | Business-themed filename delivered as an attachment | Assessed from delivery pattern |
| **T1204.002** – User Execution: Malicious File | `auto-open` / `macros` tags | Assessed from VirusTotal tags; underlying behavior not independently examined |
| **T1203** – Exploitation for Client Execution | `cve-2017-11882` tag | Assessed from VirusTotal tags; underlying behavior not independently examined |
| **T1218.011** – Rundll32 | `run-dll` tag | Suggested only — needs process telemetry |
| **T1047** – Windows Management Instrumentation | `calls-wmi` tag | Suggested only — needs process telemetry |
| **T1622** – Debugger Evasion | `detect-debug-environment` tag | Assessed from VirusTotal tags; not independently examined |
| **T1497.003** – Virtualization/Sandbox Evasion: Time Based Checks | `long-sleeps` tag | Assessed from VirusTotal tags; not independently examined |
| **T1071.001** – Application Layer Protocol: Web | Outbound traffic on port 80 from HOST-B | **Withdrawn** — the supporting record cannot be correlated to this incident (Section 6.2) |

The confidence column is the part that matters. A tag like `run-dll` tells you the sandbox saw DLL-related execution behavior; it does not tell you `rundll32.exe` ran on your host, and it cannot distinguish that from another loader mechanism. Mapping it as an established technique overstates what you know. Mapping it as a lead is accurate and still useful — it tells Tier 2 exactly which process telemetry to pull.

Laid out this way, the mapping is no longer decoration — it is a coverage check. Each row is a place your detections either fire or do not, and a gap is a detection-engineering ticket.

---

## 9. Severity — when to raise it

**What happened:** Alert severity was Medium. The investigation supports High.

**Why it matters:**

Severity should reflect what you found. Relate the recommendation to your organization's severity criteria — asset importance, exposure, and how strong the execution evidence is — rather than asserting a number on its own. Here, the findings that survive validation support raising it toward High:

1. The file transfer was **allowed** — not a blocked attempt.
2. **No quarantine action** is recorded — nothing in the case data shows the file was isolated at the endpoint.
3. The sample has a **potential non-macro execution path** (CVE-2017-11882 tagged), so user caution alone would not necessarily have prevented compromise. Note "potential": execution is unconfirmed.
4. The sample is detected by **45 of 64 engines**, with tagging that suggests secondary-payload delivery and anti-analysis behavior.

How much each point moves the dial depends on the asset and the environment, which is a judgment your severity matrix should anchor, not the analyst alone.

**What was removed from this list, and why.** An earlier draft cited a fifth point: outbound traffic from HOST-B to associated infrastructure, showing that infrastructure was reachable from inside. That record is dated two years outside the incident window (Section 6.2). It was withdrawn from the severity argument, and the report says so explicitly. Severity can be raised on credible suspicion, but only on evidence that belongs to the incident. Once a record is excluded, every argument that rested on it has to be rebuilt without it — and it is better to state that openly than to hope no one traces the dependency.

**The discipline:** if you change severity, state the reason in the same section. An unexplained "Severity: High" in a report whose ticket says "Medium" looks like an error rather than a judgment. Show the reasoning and it becomes analysis.

---

## 10. Containment — scope and limits

**What happened:** Both hosts were network-isolated. The incident was escalated to Tier 2.

**Why it matters:**

### 10.1 Why isolation, and why not more

Network isolation restricts the host's connectivity while leaving it powered on and available for forensic collection. When enforced correctly it can interrupt C2, data exfiltration, and lateral movement. It is not the same as preserving evidence: the running system keeps changing while isolated, so isolation does not replace acquiring and preserving memory and disk. Treat them as two separate steps.

Unless your incident response plan or an authorized responder directs otherwise, avoid the following at Tier 1:

- **Powering the machine off without coordination.** Volatile memory holds running processes, injected code, cryptographic material, and network state, and shutting down destroys all of it. This is a default, not an absolute: active destructive behavior such as ransomware encryption in progress, or a safety consideration, can justify pulling power. That call is made with a responder, not alone.
- **Reimaging.** That deletes the evidence needed to understand what happened and whether it spread.
- **Deleting the file.** It is evidence, and Tier 2 may want to detonate it in a controlled environment.

Containment is a holding action. Eradication and recovery come after investigation. Where your organization's plan differs from any of the above, the plan wins — knowing it is part of the job.

### 10.2 Containing on suspicion is correct

HOST-B was reportedly isolated during triage based on the initial proxy correlation. That record was later excluded. The action and its stated rationale remain documented; whether the original decision was justified depends on the information, authority, and operational impact at the time — which this write-up does not fully capture, so it does not pronounce on it.

What is clear is what happens next: continued isolation has to be reassessed under the response process. After Tier 2 checks whether a correctly dated record exists, and if no incident-related evidence is found, the host is released through the approved process. The general principle still holds — you may contain on credible suspicion, because waiting for certainty is how incidents spread — but containment that outlives its supporting evidence has to be revisited, not left to stand by inertia.

Two points to carry from this. First, containment and reporting run on different standards. You contain on credible suspicion, because waiting for certainty is how incidents spread. You write on evidence, because a report that overstates gets acted on wrongly. Second, an action taken on evidence that later fails validation stays in the record with its reasoning. You do not erase it; you document what was done, why, and what changed.

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

**Label your confidence.** The strongest habit you can build is separating what you verified from what you assessed from what someone reported to you. A short provenance table at the top of a report — source, what it gave you, whether it is confirmed — costs five minutes and tells a reviewer exactly how far to trust each finding. It also protects you: a claim marked "pending confirmation" that later proves wrong is a normal open item, while the same claim stated flatly is an error with your name on it.

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
Pull associated indicators from Relations tab (what should I hunt for?)
        ↓
Correlate against internal logs (did anyone touch it?)
        ↓
Validate every correlated record (does it belong to THIS incident?)
        │   timestamp in window? association confirmed? session evidence?
        │   ─── fails ───→ exclude it, and withdraw everything that rested on it
        ↓
Check Device Action + quarantine status (did controls stop it?)
        ↓
    Blocked ────────────→ True Positive, this stage prevented
        │                  (still check other stages, hosts, attempts)
        ↓
    Allowed
        ↓
Contain affected hosts on credible suspicion (reassess when evidence changes)
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

1. What does the `.xlsm` extension establish about a file, and what does it *not* establish?
2. Your alert gives a 32-character hash and your VirusTotal link uses a 64-character hash. What must you check, and what breaks if you skip it?
3. What does `Device Action: Allowed` change about your response?
4. Source port 49874 is not suspicious. Why is it still worth recording, and what has to be accounted for when using it to correlate records across systems?
5. Why is a connection over port 80 harder to spot than one over port 4444 — and what can an investigator examine if proxy content or packet capture was retained?
6. Why should a Tier 1 analyst generally avoid powering off a potentially compromised host without coordination, and what circumstances might change that?
7. Your evidence shows the file on Host A and outbound traffic from Host B to an associated address. Write the two findings without over-claiming.
8. The rule assigned Medium severity. Under what conditions should you raise it, and what must accompany the change?
9. A user insists they never clicked "Enable Content." Why is that not sufficient to rule out execution for this sample?
10. The sample is tagged `executes-dropped-file`. What does that add to your IOC list that you do not currently have?
11. A contained host has shown no suspicious activity for six hours. Which tag on this sample argues against releasing it?
12. A 2.79 MB (2.66 MiB) spreadsheet expands to 2.01 GB. What can that ratio indicate, what ordinary causes should you rule out, and what can you *not* conclude from it alone?
13. A proxy log shows a connection from an internal host to an address associated with a malicious sample. Separate the three questions hidden in "successful C2 communication," say what evidence each needs, and explain why an HTTP response in the log does not by itself prove the destination replied.
14. A colleague sees `Device Action: Allowed` on an alert and concludes the C2 connection also succeeded. What is wrong with that reasoning?
15. Why is an `.xlsm` attachment not, by itself, evidence of malice?
16. Your alert is dated 2021 and the proxy record you want to cite is dated 2023. What do you write in the report?
17. You are about to write "an address associated with the malicious sample." What should you check first, and what do you write if you cannot check it?
18. A record you cited in the severity argument is later excluded because it cannot be correlated with the incident. What has to change in the report, and how do you show that change?
19. A host was isolated on evidence that later failed validation. What information would you need to judge whether the original decision was justified, what happens to the host now, and what happens to the record of the action?

---

## References

Every factual claim in this document about the sample, the CVE, the file formats, or the ATT&CK techniques can be checked against these sources.

- [VirusTotal report for SHA-256 7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813](https://www.virustotal.com/gui/file/7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813)
- [CVE-2017-11882, Microsoft Office Memory Corruption Vulnerability (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2017-11882)
- [Microsoft: file formats supported in Excel](https://support.microsoft.com/en-us/office/file-formats-that-are-supported-in-excel-0943ff2c-6014-4e8d-aaea-b83d51d46247)
- [Microsoft: enable or disable macros in Office files](https://support.microsoft.com/en-us/office/enable-or-disable-macros-in-microsoft-365-files-12b036fd-d140-4e74-b45e-16fed1a7e5c6)
- [MITRE ATT&CK T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [MITRE ATT&CK T1203 — Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1218.011 — System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK T1622 — Debugger Evasion](https://attack.mitre.org/techniques/T1622/)
- [MITRE ATT&CK T1497.003 — Virtualization/Sandbox Evasion: Time Based Checks](https://attack.mitre.org/techniques/T1497/003/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK T1566.001 — Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
