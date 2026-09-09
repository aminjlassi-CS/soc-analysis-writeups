# Incident Investigation Report — SOC138

| Field | Value |
| --- | --- |
| Analyst | Amin Jlassi |
| Role | Security Analyst (Tier 1) |
| Event ID | 77 |
| Alert Rule | SOC138 – Detected Suspicious XLS File |
| Event Time | 2021-03-13 20:20:58 (UTC+03:00) |
| Alert Severity | Medium (escalation to High recommended — see Section 6) |
| Alert Type | Malware |
| Verdict | True Positive |

> **Training scenario.** This report documents a lab exercise, not production incident response. The malware sample is real and publicly documented; the alert, host names, and log records come from a training environment. Internal host names and private IP addresses have been generalized.
>
> **Evidence artifacts.** The VirusTotal figures were previously reported against a last-analysis timestamp of 2026-09-09 19:20:23 UTC; that timestamp is **not independently verified** from the evidence retained here, and the currently accessible page does not expose the field. Screenshots and raw exports were not retained; the alert, proxy, and VirusTotal values were observed by the analyst but the original artifacts are not attached. Where a field value was not captured (for example, the proxy record's action), it is recorded as unavailable rather than reconstructed.
>
> **ATT&CK techniques.** Supplied by the alert mapping: T1112. Assessed from sandbox behavioral tags and delivery method, pending endpoint confirmation: T1566.001, T1204.002, T1203, T1218.011, T1047, T1622, T1497.003. T1071.001 was initially assessed from the HOST-B proxy record and is withdrawn with that record (Section 4.2).

---

## 1. Evidence Provenance

Every finding below is labeled by how it was established. This section exists so a reviewer can tell at a glance what is verified and what is assessed.

| Source | What it provided | Status |
| --- | --- | --- |
| Alert record (Event 77) | Rule, timestamp, severity, file name, MD5, file size, ATT&CK T1112, Device Action, source host | Observed by analyst; original artifact not retained |
| VirusTotal report | 45/64 detection ratio, community score −10, all three hashes, file type, creation and submission dates, bundle metadata, behavioral tags, alternate filenames | Observed by analyst; original artifact not retained. Last-analysis timestamp (2026-09-09 19:20:23 UTC) previously reported, not independently verified |
| VirusTotal Relations tab | Contacted IP addresses for this sample | **Not independently verified in this write-up** — see Section 4.2 |
| Proxy log | One outbound connection record from HOST-B | **Cannot be correlated with this alert** — timestamp falls outside the incident window. See Section 4.2 |
| Analyst actions | Host isolation, escalation | Reported by the analyst |

---

## 2. Executive Summary

On 13 March 2021 at 20:20:58 (UTC+03:00), alert SOC138 triggered on a macro-enabled Excel workbook delivered to host **HOST-A (10.20.30.41)**. Previously reported VirusTotal results show **45 of 64 engines** detecting the file, with a community score of **−10**; the analysis timestamp behind those figures is not independently verified (see the note above).

The Device Action recorded on the alert event was **Allowed**, and the case data contains **no recorded quarantine action**. The available evidence does not establish which endpoint controls inspected the file.

VirusTotal tagging suggests two potential execution mechanisms: automatic macro execution and Equation Editor exploitation (CVE-2017-11882). Tags also suggest secondary-payload delivery and anti-analysis behavior. These are automated-analysis indicators, not activity confirmed on either host, and the underlying mechanisms were not directly examined for this report.

A proxy record showing outbound traffic from host **HOST-B (10.20.30.58)** to 209.197.3.8 was initially correlated to this alert. On review, that record is dated **2023-04-17**, two years outside the incident window. **It is therefore excluded from the findings of this incident** pending validation of the source data. Section 4.2 sets out what would be required to reinstate it.

Both hosts were network-isolated at the time of triage and the incident was escalated to Tier 2. HOST-B's isolation is not supported by validated evidence tied to this incident and should be reassessed promptly after the Tier 2 validation steps in Section 4.3.

**Scope of this incident as currently evidenced:** delivery to HOST-A of a file currently classified as malicious, through an allowed transfer, with no quarantine action recorded. Execution is unconfirmed. No validated internal network activity is associated with this alert.

---

## 3. File Analysis

### 3.1 Attributes

| Attribute | Value |
| --- | --- |
| File name | `ORDER SHEET & SPEC.xlsm` |
| File size | 2,793,487 bytes (2.66 MiB; displayed as "2.66 MB" by the alert and VirusTotal) |
| MD5 | `7ccf88c0bbe3b29bf19d877c4596a8d4` |
| SHA-1 | `23f0506d857d38c3cd5354b80afc725b5f034744` |
| SHA-256 | `7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813` |
| File type | Office Open XML spreadsheet, macro-enabled (.xlsm) |
| Bundle contents | 38 files, 2.01 GB uncompressed |
| File creation timestamp (metadata) | 2020-02-01 18:28:07 UTC |
| First seen on VirusTotal | 2021-01-28 14:07:33 UTC |
| VirusTotal results (previously reported) | 45/64 engines detect; community score −10. Analysis timestamp not independently verified |
| Device Action (alert event, HOST-A) | Allowed |
| Quarantine status | Not quarantined |

The alert MD5 was confirmed against the MD5 listed on the VirusTotal Details tab. The two match, establishing that the VirusTotal report describes the same file as the alert.

The `.xlsm` extension confirms the workbook can carry VBA macros. That capability is legitimate and common in business use. Its significance here comes from the combination: a macro-capable file with an unexpected business-themed name, automatic-execution and exploit tagging, and a malicious reputation verdict.

### 3.2 Execution paths

VirusTotal tags suggest two potential execution mechanisms. These are automated-analysis indicators; the VBA code and OLE contents were not examined directly for this report. Execution on either host is unconfirmed.

- **Tags:** `macros`, `auto-open`, `macro-run-file` — suggest potential automatic macro execution when the workbook is opened, if macros are permitted. In a default configuration that requires the user to enable content; Trusted Locations, Trusted Publishers, or policy settings can allow it without a prompt. The specific VBA procedure was not inspected.
- **Tags:** `cve-2017-11882`, `exploit` — suggest an exploit for the Microsoft Equation Editor stack-overflow vulnerability (`EQNEDT32.EXE`). This route would not depend on the user enabling macros. On a vulnerable and unprotected Office installation, opening the document may trigger exploitation on its own; whether it succeeds depends on patch level, the Office component in use, and protections such as Protected View.

**Observation:** the sample's alternate filenames include an `.emf` variant and the bundle contains EMF objects. This is recorded as a metadata observation only. It does not establish the exploit's delivery structure; determining how any exploit is carried would require examining the OLE contents directly.

**Operational consequence:** "the user did not enable macros" is not sufficient to rule out execution. Equation Editor patch status and Protected View configuration must be checked before execution can be excluded.

**Telemetry availability at Tier 1.** Where EDR is deployed, process ancestry for HOST-A around 2021-03-13 20:20:58 should be checked at Tier 1 before escalation — specifically whether `EXCEL.EXE` ran and whether it or `EQNEDT32.EXE` spawned any child process. **In this case, no endpoint process telemetry was available in the case data.** That check therefore could not be performed at triage and is escalated in Section 7. This is stated so the reader does not infer that the absence of a process finding means no process ran.

### 3.3 Behavioral tags

The tags below are reported by VirusTotal from its sandbox detonation and static analysis. This report did not independently examine the underlying traces, so each is a reported indicator and a lead for endpoint verification — not a finding about HOST-A or HOST-B.

| Tag | Assessed meaning |
| --- | --- |
| `write-file`, `executes-dropped-file` | Reported tags suggest the sample dropped and executed a second file; the underlying sandbox trace was not independently examined. Does not establish that a second file exists on HOST-A — an artifact type to hunt for |
| `run-dll`, `exe-pattern` | Reported tags suggest DLL-based execution. Consistent with T1218.011; the specific binary is not established without process telemetry |
| `calls-wmi` | Reported tag suggests WMI-related activity. Consistent with T1047; the purpose — execution, persistence, or reconnaissance — is not established |
| `detect-debug-environment` | Reported tag suggests a debugger check. Consistent with T1622 (Debugger Evasion); underlying trace not independently examined |
| `long-sleeps` | Reported tag suggests stalling past sandbox timeouts. Consistent with T1497.003 (Time Based Checks); underlying trace not independently examined |
| `checks-user-input` | May serve sandbox evasion (checking for a real user) or reconnaissance; not necessarily data theft |
| `clipboard` | Suggests possible clipboard data or credential collection; purpose not established from the tag |

Two consequences for Tier 2. First, `detect-debug-environment` means the sandbox report may be incomplete — the sample may have withheld behavior it would exhibit on a real host. Second, `long-sleeps` means an absence of observed activity on a contained host is not evidence that the host is clean.

### 3.4 File size

The workbook is 2,793,487 bytes (2.66 MiB) compressed and expands to 2.01 GB across 38 contained files. Decompression limits in a gateway or sandbox can prevent complete inspection of an archive this size. What happens next — blocked, quarantined, or delivered — depends on the product and its configuration, and is not determined by the size alone. An expansion ratio of this magnitude **may indicate decompression-based evasion**, but embedded images and legacy objects can inflate a workbook for ordinary reasons, so intent is not established by the ratio alone.

### 3.5 Distribution context

Alternate filenames recorded on VirusTotal include French-language variants (`Nouvelle version du cahier des charges.xlsm`) alongside the English `ORDER SHEET & SPEC.xlsm`. This **may indicate distribution across multiple language groups**, though the list reflects how submitters named the file rather than how it was distributed. Each variant is an additional string for the mail-gateway search.

VirusTotal records two dates worth separating. **First submission** was 2021-01-28, approximately six weeks before the incident date of 2021-03-13. The **file creation timestamp** in the document metadata is 2020-02-01 — roughly thirteen months before the incident. If that metadata is accurate, the document existed for over a year before it reached this environment, which would be consistent with a long-lived sample reused across campaigns; the multi-language filename variants in this section point the same way. Two caveats apply. File creation timestamps can be altered or inherited from a template, so the thirteen-month figure is weak evidence and is offered as context, not a finding. And first submission establishes only that the sample was known to the platform by that date — it does not establish what the detection ratio was at that time, or that the sample was classified malicious then. The 45/64 ratio cited in this report reflects a later analysis.

The defensible statement is that the sample existed in VirusTotal before the incident date. Establishing what any given control should have caught in March 2021 would require time-specific reputation data.

---

## 4. Findings

### 4.1 HOST-A (10.20.30.41) — initial delivery

HOST-A is the host named in the originating alert and is assessed as the point of initial delivery.

- Device Action on this event: **Allowed** — the control did not block the transfer.
- The case data contains **no recorded quarantine action**. It does not establish which endpoint controls inspected the file.
- Whether the document was opened or executed on this host is **not established** by available evidence. No endpoint process telemetry for HOST-A was available in the case data, so process ancestry could not be checked at Tier 1.

### 4.2 HOST-B (10.20.30.58) — excluded from findings

A proxy record showing outbound traffic from HOST-B was initially correlated to this alert. It is set out here in full, and then excluded, with reasons.

| Field | Value |
| --- | --- |
| Source | 10.20.30.58 (HOST-B) |
| Source port | 49874 (ephemeral) |
| Destination | 209.197.3.8 |
| Destination port | 80 |
| Log source | Proxy |
| Device Action | Field present in the log; value not captured in the evidence reviewed |
| Timestamp recorded | **2023-04-17 05:15:13** |

**Available evidence, stated plainly.** A proxy record dated 2023-04-17 lists HOST-B and destination 209.197.3.8:80. Its action value was not captured. The completed exchange, the sample association, and the record's relevance to the 2021 alert all remain unverified.

**Exclusion.** The recorded timestamp is 2023-04-17; the alert is dated 2021-03-13 — a gap of just over two years. The record therefore **cannot be correlated with this incident** and may belong to an unrelated event. It is excluded from the findings, the severity assessment, and the verdict. The question for Tier 2 is not how HOST-B was infected — that presumes a compromise the evidence does not establish — but whether the evidence establishes that HOST-B was compromised at all. As it stands, it does not.

**Three items would need resolving before it could be reinstated:**

1. **Timestamp.** Determine whether the discrepancy stems from the wrong log range being pulled, a timezone or clock normalization fault, an export defect, or a genuinely different event. Only a record falling within the incident window can corroborate the alert.
2. **Address association.** Confirm 209.197.3.8 against the sample's VirusTotal contacted-IP list. This linkage currently rests on the analyst's review and has not been independently re-verified here.
3. **Completion evidence.** Even a correctly dated record would show only a connection. Determine whether communication with the destination completed. Repeated attempts do not establish completion, and a proxy-generated response does not establish that the destination answered.

**Consequence for this report.** No validated internal network activity is currently associated with this alert. The incident is evidenced as a delivery event on HOST-A only.

### 4.3 Open question — HOST-B's status

HOST-B was isolated during triage on the basis of the correlation above. With that record excluded, HOST-B's status is unresolved rather than cleared. Tier 2 should determine, in this order:

1. Whether a correctly dated proxy record exists for HOST-B within the incident window.
2. Whether `ORDER SHEET & SPEC.xlsm` was delivered to HOST-B independently.
3. Whether any lateral movement from HOST-A occurred.

**Recommended disposition.** Continued isolation of a host on evidence known to be out-of-window carries real operational cost. The recommendation is that release be the *default outcome*: the response lead sets a bounded reassessment window on escalation, and unless Tier 2 surfaces a validated in-window artifact within it, HOST-B is released through the approved process. The burden sits with telemetry to justify continued containment, not with the host to prove it is clean. Absence of validated evidence is not proof the host is uncompromised, but it is not grounds for indefinite isolation either.

---

## 5. Containment Actions

- **Network isolation:** Both HOST-A (10.20.30.41) and HOST-B (10.20.30.58) were isolated from the local network and from internet egress during triage.
- **HOST-A basis:** Confirmed delivery of a file currently classified as malicious, through an allowed transfer, with no quarantine action recorded. Isolation is appropriate on this evidence.
- **HOST-B basis:** Reportedly isolated on the initial proxy correlation, which was subsequently excluded (Section 4.2). The action and its stated rationale remain documented. This report does not pronounce on whether the original decision was justified — that depends on the information, authority, and operational impact at the time — and does not claim validated evidence of compromise on HOST-B. Continued isolation requires reassessment under the response process within a window set by the response lead; release is the recommended default if the Tier 2 checks in Section 4.3 surface no validated in-window evidence (see Section 4.3, recommended disposition).
- **Scope and preservation:** Isolation restricts connectivity while leaving the host available for forensic collection. It is a holding measure, not evidence preservation: the running system keeps changing while isolated, so memory and disk still need to be acquired and preserved separately. No eradication, reimaging, or file deletion has been performed at Tier 1.

Documenting an action that later evidence does not support, rather than removing it from the record, is deliberate. The incident log should reflect what was done, on what basis, and what changed.

---

## 6. Severity Assessment

The alert was generated at **Medium**. Escalation to **High** is recommended, assessed against the organization's severity criteria — asset importance, exposure, and strength of execution evidence — on these grounds:

- Device Action was **Allowed** — the transfer was not blocked.
- The sample was recorded as **not quarantined** — no evidence in the case data shows the file was isolated at the endpoint.
- The sample has a **potential non-macro execution path** (CVE-2017-11882 tagged), so user caution alone would not necessarily have prevented compromise. Execution is unconfirmed.
- The sample is detected by 45 of 64 engines, with tagging that suggests secondary-payload delivery.

How far these move severity depends on the asset and environment, which the severity matrix should anchor. The recommendation is a reasoned one, not a mechanical output.

**What is deliberately not cited here.** The HOST-B proxy record is excluded (Section 4.2) and forms no part of this severity argument. Earlier drafts used it to argue that external infrastructure was reachable from inside the environment. That argument is withdrawn.

**Control observation.** The sample was present in VirusTotal before the incident date and was permitted by the control that generated this alert, with no quarantine action recorded. This is worth raising with security engineering as a coverage question. Note the limits of what the case data shows: it does not establish which controls inspected the file, what reputation data was available to them in March 2021, or why no quarantine occurred. Those are questions for the review, not conclusions from this report.

---

## 7. Escalation to Tier 2

1. **Resolve the proxy record** (Section 4.2). Determine whether a correctly dated record exists for HOST-B inside the incident window, or whether the 2023 record belongs to an unrelated event. This governs whether HOST-B is part of this incident at all.
2. **Confirm the address association** — verify 209.197.3.8 against the sample's VirusTotal contacted-IP list, and pull the associated network indicators including contacted domains and URLs.
3. **Equation Editor patch status** on both hosts — confirm whether `EQNEDT32.EXE` is patched against CVE-2017-11882 and whether Protected View was in effect.
4. **Registry review** for T1112 artifacts. The specific keys modified are unknown. The following are hunting hypotheses, not observed behavior: Run/RunOnce persistence keys, Office Trust Center `VBAWarnings` values, obscure keys used for configuration storage.
5. **Process ancestry** — look for `EXCEL.EXE` or `EQNEDT32.EXE` spawning `rundll32.exe`, `wmiprvse.exe`, or other unexpected child processes.
6. **Process and memory analysis.** Note `long-sleeps`: a quiet host is not evidence of a clean host.
7. **Confirm execution** — determine whether automatic macro execution occurred, and whether a dropped file was written and executed. Obtain the dropped payload's hash.
8. **Determine whether HOST-B was involved at all** per Section 4.3. Only if compromise is established should the infection vector be investigated.
9. **Environment-wide sweep**, targeted by data source:
   - **Endpoint file events** (EDR or Sysmon Event ID 11 / file-creation telemetry): search for all three hashes and for the filename strings `ORDER SHEET & SPEC.xlsm`, `ORDER_SHEET_SPEC.xlsm`, and `Nouvelle version du cahier des charges.xlsm`.
   - **Process creation events** (Sysmon Event ID 1 / EDR process telemetry): command lines containing those filenames, and any `EXCEL.EXE` or `EQNEDT32.EXE` parent spawning `rundll32.exe`, `wmiprvse.exe`, `powershell.exe`, `cmd.exe`, or `mshta.exe`.
   - **AMSI and PowerShell script-block logs** (Event ID 4104): script content executed from an Office parent process in the incident window. These log script *content*, not filenames, so search here for macro-spawned commands rather than the document name.
   - **Proxy, firewall, and DNS logs**: the network indicators from the sample's VirusTotal Relations data, across the full incident window and both hosts.
   - **Mail gateway logs**: attachment name and hash matches, to find other recipients (see item 10).
10. **Mail gateway search** for other recipients, including the filename variants in Section 3.5.

---

## 8. Verdict

**True Positive.**

A file that VirusTotal results (previously reported) show detected by 45 of 64 engines was delivered to HOST-A. The Device Action on that event was Allowed rather than Blocked, and the case data contains no recorded quarantine action. A file currently classified as malicious therefore reached an internal host through an allowed transfer.

That is the whole of the evidenced case. Specifically **not** claimed:

- **Execution.** Not confirmed on any host. The sample has two plausible execution paths, but neither has been observed in this environment.
- **C2 communication.** No validated internal network activity is associated with this alert. The only proxy record available falls two years outside the incident window and is excluded.
- **A second affected host.** HOST-B's involvement is unresolved, not established.

The verdict is True Positive because an allowed transfer of content currently classified as malicious into the environment is sufficient on its own. It does not depend on any of the three items above.

---

## Indicators of Compromise

| Type | Indicator | Confidence |
| --- | --- | --- |
| MD5 | `7ccf88c0bbe3b29bf19d877c4596a8d4` | Confirmed |
| SHA-1 | `23f0506d857d38c3cd5354b80afc725b5f034744` | Confirmed |
| SHA-256 | `7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813` | Confirmed |
| File name | `ORDER SHEET & SPEC.xlsm` | Confirmed |
| File name (variant) | `ORDER_SHEET_SPEC.xlsm` | Reported on VirusTotal |
| File name (variant) | `Nouvelle version du cahier des charges.xlsm` | Reported on VirusTotal |
| CVE | CVE-2017-11882 | Tagged on VirusTotal |
| IP address | `209.197.3.8` (destination port 80) | Not correlated to this incident — see Section 4.2 |

**Not held:** the hash of the secondary file that the `executes-dropped-file` tag indicates was written and executed *in the analysis environment*. Whether a corresponding file exists on any host here is unknown. Obtaining that hash from Tier 2 or from a controlled detonation would add a searchable indicator.

### Asset classification

| Asset | Classification |
| --- | --- |
| HOST-A (10.20.30.41) | Confirmed delivery of malicious document; execution unconfirmed |
| HOST-B (10.20.30.58) | Status unresolved. Isolated during triage; the supporting record is excluded (Section 4.2). Neither implicated nor cleared |

---

## References

- [VirusTotal report for SHA-256 7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813](https://www.virustotal.com/gui/file/7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813)
- [CVE-2017-11882, Microsoft Office Memory Corruption Vulnerability (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2017-11882)
- [Microsoft: file formats that are supported in Excel](https://support.microsoft.com/en-us/office/file-formats-that-are-supported-in-excel-0943ff2c-6014-4e8d-aaea-b83d51d46247)
- [MITRE ATT&CK T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [MITRE ATT&CK T1203 — Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1218.011 — System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK T1622 — Debugger Evasion](https://attack.mitre.org/techniques/T1622/)
- [MITRE ATT&CK T1497.003 — Virtualization/Sandbox Evasion: Time Based Checks](https://attack.mitre.org/techniques/T1497/003/)
- [MITRE ATT&CK T1071.001 — Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) (initially assessed, withdrawn with the HOST-B record — see Section 4.2)
- [MITRE ATT&CK T1566.001 — Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
