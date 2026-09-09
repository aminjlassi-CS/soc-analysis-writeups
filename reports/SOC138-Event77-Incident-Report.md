# Incident Investigation Report — SOC138

**Analyst:** Amin Jlassi
**Role:** Security Analyst (Tier 1)
**Event ID:** 77
**Alert Rule:** SOC138 – Detected Suspicious XLS File
**Event Time:** 2021-03-13 20:20:58 (UTC+03:00)
**Alert Severity:** Medium (recommended escalation to High — see Section 5)
**Alert Type:** Malware
**MITRE ATT&CK:** T1112 (Modify Registry), T1203 (Exploitation for Client Execution), T1204.002 (User Execution: Malicious File), T1218.011 (Rundll32), T1047 (WMI), T1497 (Sandbox Evasion)
**Verdict:** True Positive

---

> **Note:** Internal host names and private IP addresses in this report have been generalized. The file hashes, CVE reference, and external C2 address are the real, publicly documented indicators for this sample.

## 1. Executive Summary

On 13 March 2021 at 20:20:58 (UTC+03:00), alert SOC138 triggered on a macro-enabled Excel workbook delivered to host **HOST-A (10.20.30.41)**. VirusTotal analysis confirmed the file as malicious (**45/64 engines**, community score −10) and identified it as a weaponised document combining an **AutoOpen VBA macro** with an embedded **CVE-2017-11882** exploit. The sample drops and executes a secondary payload, and employs anti-analysis techniques including debugger detection and extended sleep delays.

The proxy **allowed** the transfer and the file was **not quarantined** by endpoint controls, meaning the sample reached the host intact.

Command-and-control (C2) indicators extracted from the VirusTotal report were correlated against internal proxy logs. Host **HOST-B (10.20.30.58)** was observed making a successful outbound HTTP connection to **209.197.3.8:80**, an address listed in the sample's contacted-IP set.

Both hosts were network-isolated as a containment measure and the incident was escalated to Tier 2 for forensic analysis.

---

## 2. File Analysis

| Attribute | Value |
|---|---|
| File name | `ORDER SHEET & SPEC.xlsm` |
| File size | 2.66 MB |
| MD5 | `7ccf88c0bbe3b29bf19d877c4596a8d4` |
| SHA-1 | `23f0506d857d38c3cd5354b80afc725b5f034744` |
| SHA-256 | `7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813` |
| File type | Office Open XML spreadsheet, macro-enabled (.xlsm) |
| Uncompressed contents | 2.01 GB across 38 contained files |
| Created | 2020-02-01 18:28:07 UTC |
| First seen on VirusTotal | 2021-01-28 14:07:33 UTC |
| VirusTotal verdict | Malicious — **45/64 engines**, community score −10 |
| Device Action | **Allowed** |
| Quarantine status | **Not quarantined** |

The `.xlsm` extension is significant: unlike a standard `.xls`, this format carries embedded VBA macros, which is the delivery mechanism for the payload. Execution depends on the user enabling content.

### 2.1 Dual execution paths

VirusTotal behavioural tagging shows the sample carries **two independent routes to code execution**:

- **`auto-open` / `macros` / `macro-run-file`** — an AutoOpen VBA macro that executes as soon as the workbook is opened, provided the user enables content.
- **`cve-2017-11882` / `exploit`** — an embedded exploit for the Microsoft Equation Editor stack-overflow vulnerability (`EQNEDT32.EXE`). This path does **not** require the user to enable macros. On an unpatched host, opening the document is sufficient.

The presence of a `.emf` alternate filename and EMF objects among the contained files is consistent with the standard CVE-2017-11882 delivery pattern, in which the exploit is carried inside an embedded OLE object.

**Operational consequence:** "the user did not enable macros" cannot be used to rule out execution. Patch status of Equation Editor must be checked on both hosts.

### 2.2 Post-execution behaviour

| Tag | Interpretation |
|---|---|
| `write-file`, `executes-dropped-file` | Drops a secondary payload to disk and runs it |
| `run-dll`, `exe-pattern` | Embedded executable content; likely `rundll32` execution (T1218.011) |
| `calls-wmi` | WMI used for execution or persistence (T1047) |
| `detect-debug-environment`, `long-sleeps` | Anti-analysis — evades sandboxes by detecting debuggers and stalling past analysis timeouts (T1497) |
| `checks-user-input`, `clipboard` | Interacts with user input and clipboard contents; possible credential or data theft |
| T1112 (Modify Registry) | Writes to the registry — typically Office Trust Center macro settings or Run/RunOnce persistence keys |

### 2.3 Evasion through file size

The workbook is 2.66 MB compressed but expands to **2.01 GB** across 38 contained files. That ratio is not incidental. Many email gateways and sandboxes impose a maximum decompression size and will skip files that exceed it. The padding is a deliberate attempt to bypass automated inspection.

### 2.4 Campaign context

Alternate filenames recorded on VirusTotal include French-language variants (`Nouvelle version du cahier des charges.xlsm`) alongside the English `ORDER SHEET & SPEC.xlsm`, indicating a multi-language distribution campaign rather than targeted delivery.

The sample was created on 2020-02-01 and first submitted to VirusTotal on 2021-01-28 — approximately six weeks before this incident. It was publicly known malicious at the time of delivery, which is a relevant finding for the control-gap review in Section 5.

---

## 3. Findings

### 3.1 Host HOST-A — 10.20.30.41 (initial delivery)

HOST-A is the host named in the originating alert and is assessed as the point of initial delivery. The malicious workbook was transferred to this host and the proxy action was recorded as **Allowed**. Endpoint controls did **not** quarantine the file.

### 3.2 Host HOST-B — 10.20.30.58 (C2 communication)

Proxy logs show an outbound connection from HOST-B to a C2 address identified in the VirusTotal relations data:

| Field | Value |
|---|---|
| Source | 10.20.30.58 (HOST-B) |
| Source port | 49874 |
| Destination | 209.197.3.8 |
| Destination port | 80 (HTTP) |
| Log source | Proxy |
| Timestamp | [verify against alert window] |

### 3.3 Open question — HOST-B's infection vector

No delivery event for `ORDER SHEET & SPEC.xlsm` has been confirmed on HOST-B. HOST-B's C2 traffic is therefore not yet linked to a known infection path on that host. Three possibilities remain open for Tier 2:

1. HOST-B received the same attachment independently (same distribution wave, separate recipient).
2. The infection spread laterally from HOST-A.
3. HOST-B is compromised by unrelated activity that shares infrastructure with this sample.

This is stated as an open finding rather than an assumption.

---

## 4. Containment Actions

- **Network isolation:** Both HOST-A (10.20.30.41) and HOST-B (10.20.30.58) were isolated from the local network and from internet egress to halt any active C2 channel and prevent lateral movement.
- **Scope:** Isolation is a holding measure pending Tier 2 forensic review. No eradication or reimaging has been performed at Tier 1.

---

## 5. Severity Assessment

The alert was generated at **Medium**. Escalation to **High** is recommended on the following grounds:

- The proxy **allowed** the file transfer — this was not a blocked delivery attempt.
- The sample was **not quarantined** — it remained resident on the host.
- Successful outbound C2 communication was observed, confirming the infrastructure is live and reachable from inside the environment.
- The sample carries a **non-macro execution path** (CVE-2017-11882), so user caution alone would not have prevented compromise.

**Control gap:** the sample had been publicly classified as malicious on VirusTotal for approximately six weeks before delivery, and was flagged by 45 of 64 engines. Both the network control and the endpoint control permitted it. This should be raised with security engineering independently of the incident response.

---

## 6. Escalation to Tier 2

Escalated for in-depth forensic investigation. Recommended actions:

1. **Equation Editor patch status** on both hosts — confirm whether `EQNEDT32.EXE` is patched against CVE-2017-11882. If unpatched, assume execution occurred on open regardless of macro settings.
2. **Registry review** for T1112 artifacts — Run/RunOnce keys and Office Trust Center `VBAWarnings` values.
3. **Process ancestry** — look for `EXCEL.EXE` or `EQNEDT32.EXE` spawning `rundll32.exe`, `wmiprvse.exe`, or any unexpected child process.
4. **Process and memory analysis** to identify any running payload. Note the `long-sleeps` tag — the payload may delay execution, so a quiet host is not evidence of a clean host.
5. **Confirm execution** — determine whether the AutoOpen macro ran and whether a dropped file was written and executed.
6. **Establish HOST-B's infection vector** per Section 3.3.
7. **Environment-wide sweep** for all three file hashes and for connections to 209.197.3.8 and other C2 indicators from the VirusTotal relations set.
8. **Mail gateway search** for other recipients, including the French-language filename variants listed in Section 2.4.

---

## 7. Verdict

**True Positive.** A confirmed-malicious macro-enabled workbook was delivered to an internal host, was permitted by network controls, was not quarantined by endpoint controls, and a second internal host established successful outbound communication with C2 infrastructure associated with the sample.

---

## Indicators of Compromise

| Type | Indicator |
|---|---|
| MD5 | `7ccf88c0bbe3b29bf19d877c4596a8d4` |
| SHA-1 | `23f0506d857d38c3cd5354b80afc725b5f034744` |
| SHA-256 | `7bcd31bd41686c32663c7cabf42b18c50399e3b3b4533fc2ff002d9f2e058813` |
| File name | `ORDER SHEET & SPEC.xlsm` |
| File name (variant) | `ORDER_SHEET_SPEC.xlsm` |
| File name (variant) | `Nouvelle version du cahier des charges.xlsm` |
| CVE | CVE-2017-11882 (Equation Editor RCE) |
| C2 IP | `209.197.3.8` (port 80/HTTP) |
| Affected host | 10.20.30.41 (HOST-A) |
| Affected host | 10.20.30.58 (HOST-B) |
