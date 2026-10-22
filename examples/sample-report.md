# Case file: Account restriction, Oct 2026

- **Case ID:** demo
- **Institution:** Example Bank
- **Generated:** 2026-10-22T01:09:02+00:00
- **Ledger integrity:** VERIFIED

## Summary

8 events recorded, 7 adverse decisions, 7 flagged for audit. Findings: 20 high, 23 medium, 15 informational.

## Timeline

| ID | Timestamp | Type | Decision | Code | Gate |
|---|---|---|---|---|---|
| EVT-0003 | 2026-10-10T00:00:00 | letter | Restricted | — | AUDIT FLAG |
| EVT-0004 | 2026-10-10T00:00:00 | transaction | Declined | R16 | AUDIT FLAG |
| EVT-0008 | 2026-10-10T00:00:00 | letter | Restricted | — | AUDIT FLAG |
| EVT-0005 | 2026-10-11T00:00:00 | transaction | Declined | — | AUDIT FLAG |
| EVT-0002 | 2026-10-12T14:05:00 | transcript | Restricted | — | AUDIT FLAG |
| EVT-0001 | 2026-10-14T09:12:44+00:00 | email | Rejected \(undeliverable\) | 550 5.7.193 | AUDIT FLAG |
| EVT-0007 | 2026-10-21T21:38:40 | screenshot | Rejected \(undeliverable\) | 550 5.7.193 | AUDIT FLAG |
| EVT-0006 | — | screenshot | — | — | N/A |

## Audit findings

### Decision EVT-0003: Restricted

```text
Decision EVT-0003 (Restricted) on 2026-10-10T00:00:00.
The record does not show whether the decision was automated or made by a person.
No human review record has been provided.
The document cites "Section 12.3 of the Deposit Account Agreement"; the rule and its text are not confirmed.
No supporting evidence was provided for the decision.
No appeal path was disclosed.
Our own evidence that this event occurred is unverified.
```

| Finding | Question | Severity | Statement |
|---|---|---|---|
| AF-0001 | Was the decision automatic? | medium | The record does not show whether the decision was automated or made by a person. |
| AF-0002 | Was a human involved? | medium | No human review record has been provided. |
| AF-0003 | What rule triggered it? | medium | The document cites "Section 12.3 of the Deposit Account Agreement"; the rule and its text are not confirmed. |
| AF-0004 | What evidence supported the rule? | high | No supporting evidence was provided for the decision. |
| AF-0005 | Was notice provided? | info | Notice is inferred from the document itself \(unconfirmed\). |
| AF-0006 | Was an appeal path disclosed? | high | No appeal path was disclosed. |
| AF-0007 | Does policy or law permit the action? | info | No legal or contractual basis has been identified yet \(needs review\). |
| AF-0008 | Is the event itself documented? | medium | Our own evidence that this event occurred is unverified. |

### Decision EVT-0004: Declined

```text
Decision EVT-0004 (Declined, R16) on 2026-10-10T00:00:00.
The record does not show whether the decision was automated or made by a person.
No human review record has been provided.
Only a system code (R16) was given; no written policy was cited.
No supporting evidence was provided for the decision.
The record does not show that notice of the decision was provided.
No appeal path was disclosed.
Our own evidence that this event occurred is unverified.
```

| Finding | Question | Severity | Statement |
|---|---|---|---|
| AF-0009 | Was the decision automatic? | medium | The record does not show whether the decision was automated or made by a person. |
| AF-0010 | Was a human involved? | medium | No human review record has been provided. |
| AF-0011 | What rule triggered it? | medium | Only a system code \(R16\) was given; no written policy was cited. |
| AF-0012 | What evidence supported the rule? | high | No supporting evidence was provided for the decision. |
| AF-0013 | Was notice provided? | medium | The record does not show that notice of the decision was provided. |
| AF-0014 | Was an appeal path disclosed? | high | No appeal path was disclosed. |
| AF-0015 | Does policy or law permit the action? | info | No legal or contractual basis has been identified yet \(needs review\). |
| AF-0016 | Is the event itself documented? | medium | Our own evidence that this event occurred is unverified. |

### Decision EVT-0008: Restricted

```text
Decision EVT-0008 (Restricted) on 2026-10-10T00:00:00.
The document indicates the decision was made automatically (unconfirmed).
No human review record has been provided.
The document cites "Section 12.3 of the Deposit Account Agreement"; the rule and its text are not confirmed.
No supporting evidence was provided for the decision.
The document mentions "If you disagree, you may dispute this decision by writing to the address above"; it is not confirmed to be a usable appeal path.
Our own evidence that this event occurred is unverified.
```

| Finding | Question | Severity | Statement |
|---|---|---|---|
| AF-0017 | Was the decision automatic? | info | The document indicates the decision was made automatically \(unconfirmed\). |
| AF-0018 | Was a human involved? | high | No human review record has been provided. |
| AF-0019 | What rule triggered it? | medium | The document cites "Section 12.3 of the Deposit Account Agreement"; the rule and its text are not confirmed. |
| AF-0020 | What evidence supported the rule? | high | No supporting evidence was provided for the decision. |
| AF-0021 | Was notice provided? | info | Notice is inferred from the document itself \(unconfirmed\). |
| AF-0022 | Was an appeal path disclosed? | medium | The document mentions "If you disagree, you may dispute this decision by writing to the address above"; it is not confirmed to be a usable appeal path. |
| AF-0023 | Does policy or law permit the action? | info | No legal or contractual basis has been identified yet \(needs review\). |
| AF-0024 | Is the event itself documented? | medium | Our own evidence that this event occurred is unverified. |

### Decision EVT-0005: Declined

```text
Decision EVT-0005 (Declined) on 2026-10-11T00:00:00.
The record does not show whether the decision was automated or made by a person.
No human review record has been provided.
No rule, policy or code was cited for the decision.
No supporting evidence was provided for the decision.
The record does not show that notice of the decision was provided.
No appeal path was disclosed.
No reason was given, so the decision cannot be explained or reproduced.
Our own evidence that this event occurred is unverified.
```

| Finding | Question | Severity | Statement |
|---|---|---|---|
| AF-0025 | Was the decision automatic? | medium | The record does not show whether the decision was automated or made by a person. |
| AF-0026 | Was a human involved? | medium | No human review record has been provided. |
| AF-0027 | What rule triggered it? | high | No rule, policy or code was cited for the decision. |
| AF-0028 | What evidence supported the rule? | high | No supporting evidence was provided for the decision. |
| AF-0029 | Was notice provided? | medium | The record does not show that notice of the decision was provided. |
| AF-0030 | Was an appeal path disclosed? | high | No appeal path was disclosed. |
| AF-0031 | Is the decision reproducible? | high | No reason was given, so the decision cannot be explained or reproduced. |
| AF-0032 | Does policy or law permit the action? | info | No legal or contractual basis has been identified yet \(needs review\). |
| AF-0033 | Is the event itself documented? | medium | Our own evidence that this event occurred is unverified. |

### Decision EVT-0002: Restricted

```text
Decision EVT-0002 (Restricted) on 2026-10-12T14:05:00.
The document indicates the decision was made automatically (unconfirmed).
No human review record has been provided.
No rule, policy or code was cited for the decision.
No supporting evidence was provided for the decision.
The record does not show that notice of the decision was provided.
The document mentions "Agent: You can file a dispute through the online portal"; it is not confirmed to be a usable appeal path.
No reason was given, so the decision cannot be explained or reproduced.
Our own evidence that this event occurred is unverified.
```

| Finding | Question | Severity | Statement |
|---|---|---|---|
| AF-0034 | Was the decision automatic? | info | The document indicates the decision was made automatically \(unconfirmed\). |
| AF-0035 | Was a human involved? | high | No human review record has been provided. |
| AF-0036 | What rule triggered it? | high | No rule, policy or code was cited for the decision. |
| AF-0037 | What evidence supported the rule? | high | No supporting evidence was provided for the decision. |
| AF-0038 | Was notice provided? | medium | The record does not show that notice of the decision was provided. |
| AF-0039 | Was an appeal path disclosed? | medium | The document mentions "Agent: You can file a dispute through the online portal"; it is not confirmed to be a usable appeal path. |
| AF-0040 | Is the decision reproducible? | high | No reason was given, so the decision cannot be explained or reproduced. |
| AF-0041 | Does policy or law permit the action? | info | No legal or contractual basis has been identified yet \(needs review\). |
| AF-0042 | Is the event itself documented? | medium | Our own evidence that this event occurred is unverified. |

### Decision EVT-0001: Rejected \(undeliverable\)

```text
Decision EVT-0001 (Rejected (undeliverable), 550 5.7.193) on 2026-10-14T09:12:44+00:00.
The document indicates the decision was made automatically (unconfirmed).
No human review record has been provided.
Only a system code (550 5.7.193) was given; no written policy was cited.
No supporting evidence was provided for the decision.
No appeal path was disclosed.
Our own evidence that this event occurred is unverified.
```

| Finding | Question | Severity | Statement |
|---|---|---|---|
| AF-0043 | Was the decision automatic? | info | The document indicates the decision was made automatically \(unconfirmed\). |
| AF-0044 | Was a human involved? | high | No human review record has been provided. |
| AF-0045 | What rule triggered it? | medium | Only a system code \(550 5.7.193\) was given; no written policy was cited. |
| AF-0046 | What evidence supported the rule? | high | No supporting evidence was provided for the decision. |
| AF-0047 | Was notice provided? | info | Notice is inferred from the document itself \(unconfirmed\). |
| AF-0048 | Was an appeal path disclosed? | high | No appeal path was disclosed. |
| AF-0049 | Does policy or law permit the action? | info | No legal or contractual basis has been identified yet \(needs review\). |
| AF-0050 | Is the event itself documented? | medium | Our own evidence that this event occurred is unverified. |

### Decision EVT-0007: Rejected \(undeliverable\)

```text
Decision EVT-0007 (Rejected (undeliverable), 550 5.7.193) on 2026-10-21T21:38:40.
The document indicates the decision was made automatically (unconfirmed).
No human review record has been provided.
Only a system code (550 5.7.193) was given; no written policy was cited.
No supporting evidence was provided for the decision.
No appeal path was disclosed.
Our own evidence that this event occurred is unverified.
```

| Finding | Question | Severity | Statement |
|---|---|---|---|
| AF-0051 | Was the decision automatic? | info | The document indicates the decision was made automatically \(unconfirmed\). |
| AF-0052 | Was a human involved? | high | No human review record has been provided. |
| AF-0053 | What rule triggered it? | medium | Only a system code \(550 5.7.193\) was given; no written policy was cited. |
| AF-0054 | What evidence supported the rule? | high | No supporting evidence was provided for the decision. |
| AF-0055 | Was notice provided? | info | Notice is inferred from the document itself \(unconfirmed\). |
| AF-0056 | Was an appeal path disclosed? | high | No appeal path was disclosed. |
| AF-0057 | Does policy or law permit the action? | info | No legal or contractual basis has been identified yet \(needs review\). |
| AF-0058 | Is the event itself documented? | medium | Our own evidence that this event occurred is unverified. |

## Evidence ledger

### EVT-0003

```text
ID: EVT-0003
Type: letter *(extracted, unconfirmed)*
Timestamp: 2026-10-10T00:00:00 *(extracted, unconfirmed)*
Decision: Restricted *(extracted, unconfirmed)*
Reason: activity that does not meet our risk standards *(extracted, unconfirmed)*
Policy cited: Section 12.3 of the Deposit Account Agreement *(extracted, unconfirmed)*
Automated: unknown
Human involved: unknown
Notice provided: yes *(extracted, unconfirmed)*
Reproducible: unknown
Evidence status: unverified
```
- Artifact denial\_letter.txt (name as supplied) → evidence/11420d9f5a1d\_denial\_letter.txt, 257 bytes, SHA-256 11420d9f5a1d91d311f1caf77da84f4b64b71a3b126952cefcc61a5063c98bf4

### EVT-0004

```text
ID: EVT-0004
Type: transaction *(extracted, unconfirmed)*
Timestamp: 2026-10-10T00:00:00 *(extracted, unconfirmed)*
Request: Rent payment ACH -1200.00 *(extracted, unconfirmed)*
Decision: Declined *(extracted, unconfirmed)*
Code: R16 *(extracted, unconfirmed)*
Reason: Account frozen *(extracted, unconfirmed)*
Automated: unknown
Human involved: unknown
Notice provided: unknown
Reproducible: unknown
Evidence status: unverified
Notes: CSV row 3 *(extracted, unconfirmed)*
```
- Artifact transactions.csv (name as supplied) → evidence/8428b2cff159\_transactions.csv, 248 bytes, SHA-256 8428b2cff15967a1dfaddac980bd38da1c753e9b5040b685c56a8f9744887982

### EVT-0008

```text
ID: EVT-0008
Type: letter *(extracted, unconfirmed)*
Timestamp: 2026-10-10T00:00:00 *(extracted, unconfirmed)*
Decision: Restricted *(extracted, unconfirmed)*
Reason: activity that does not meet our risk standards *(extracted, unconfirmed)*
Policy cited: Section 12.3 of the Deposit Account Agreement *(extracted, unconfirmed)*
Automated: yes *(extracted, unconfirmed)*
Human involved: no *(extracted, unconfirmed)*
Notice provided: yes *(extracted, unconfirmed)*
Appeal path: If you disagree, you may dispute this decision by writing to the address above *(extracted, unconfirmed)*
Reproducible: unknown
Evidence status: unverified
Notes: Text extracted by pdf-text. Check it against the original.
```
- Artifact letter\_text.pdf (name as supplied) → evidence/95f44a532e61\_letter\_text.pdf, 1786 bytes, SHA-256 95f44a532e61c8a16b5a632a528a00e68ebb799076af71190ea8c8e95dd17395
- Artifact 95f44a532e61\_letter\_text.pdf.extracted.txt (name as supplied) → evidence/95f44a532e61\_letter\_text.pdf.extracted.txt, 436 bytes, SHA-256 19abff1259fd0b4ce9b72e3540b4196071cb89ff60b6345953ace91f99cb742c

### EVT-0005

```text
ID: EVT-0005
Type: transaction *(extracted, unconfirmed)*
Timestamp: 2026-10-11T00:00:00 *(extracted, unconfirmed)*
Request: Grocery store -84.12 *(extracted, unconfirmed)*
Decision: Declined *(extracted, unconfirmed)*
Automated: unknown
Human involved: unknown
Notice provided: unknown
Reproducible: unknown
Evidence status: unverified
Notes: CSV row 4 *(extracted, unconfirmed)*
```
- Artifact transactions.csv (name as supplied) → evidence/8428b2cff159\_transactions.csv, 248 bytes, SHA-256 8428b2cff15967a1dfaddac980bd38da1c753e9b5040b685c56a8f9744887982

### EVT-0002

```text
ID: EVT-0002
Type: transcript *(extracted, unconfirmed)*
Timestamp: 2026-10-12T14:05:00 *(extracted, unconfirmed)*
Decision: Restricted *(extracted, unconfirmed)*
Automated: yes *(extracted, unconfirmed)*
Human involved: no *(extracted, unconfirmed)*
Notice provided: unknown
Appeal path: Agent: You can file a dispute through the online portal *(extracted, unconfirmed)*
Reproducible: unknown
Evidence status: unverified
```
- Artifact call\_transcript.txt (name as supplied) → evidence/5d159f5b2115\_call\_transcript.txt, 279 bytes, SHA-256 5d159f5b21151f580c841d4cdaa02de8c415113357f347a30a964474c7e81ec8

### EVT-0001

```text
ID: EVT-0001
Source: Mail system (delivery status notification) *(extracted, unconfirmed)*
Type: email *(extracted, unconfirmed)*
Timestamp: 2026-10-14T09:12:44+00:00 *(extracted, unconfirmed)*
Sender: Microsoft Outlook <postmaster@outlook.com> *(extracted, unconfirmed)*
Recipient: customer@example.com *(extracted, unconfirmed)*
Request: Send email to customer@example.com *(extracted, unconfirmed)*
Decision: Rejected (undeliverable) *(extracted, unconfirmed)*
Code: 550 5.7.193 *(extracted, unconfirmed)*
Reason: External sender blocked by organization policy *(extracted, unconfirmed)*
Automated: yes *(extracted, unconfirmed)*
Human involved: no *(extracted, unconfirmed)*
Notice provided: yes *(extracted, unconfirmed)*
Reproducible: unknown
Evidence status: unverified
```
- Artifact bounce.eml (name as supplied) → evidence/b09468d94480\_bounce.eml, 423 bytes, SHA-256 b09468d944807e1294442a8175a0062feedca0203b1e6635fe56ee6dab1eedc4

### EVT-0007

```text
ID: EVT-0007
Source: Microsoft 365 (Exchange Online) *(extracted, unconfirmed)*
Type: screenshot *(extracted, unconfirmed)*
Timestamp: 2026-10-21T21:38:40 *(extracted, unconfirmed)*
Sender: sender@example.com *(extracted, unconfirmed)*
Recipient: group@agency.example.ca *(extracted, unconfirmed)*
Request: Send email to group@agency.example.ca: RE:RequestforAccountRecords and Reviewof the RestrictionNoticeDated October2,2026 *(extracted, unconfirmed)*
Decision: Rejected (undeliverable) *(extracted, unconfirmed)*
Code: 550 5.7.193 *(extracted, unconfirmed)*
Reason: The Microsoft 365 group, group@agency.example.ca, is configured to reject messages sent to it from outside its organization -- unless the sender is a guest group member. *(extracted, unconfirmed)*
Automated: yes *(extracted, unconfirmed)*
Human involved: no *(extracted, unconfirmed)*
Notice provided: yes *(extracted, unconfirmed)*
Reproducible: unknown
Evidence status: unverified
Notes: Text extracted by ocr:rapidocr, mean OCR confidence 0.99. Check it against the original.
```
- Artifact ndr\_screenshot.png (name as supplied) → evidence/686bf07ce5f1\_ndr\_screenshot.png, 148555 bytes, SHA-256 686bf07ce5f1da290ee9a9544f747e95437e965890a4cf337fc630d7e019c4bd
- Artifact 686bf07ce5f1\_ndr\_screenshot.png.extracted.txt (name as supplied) → evidence/686bf07ce5f1\_ndr\_screenshot.png.extracted.txt, 1139 bytes, SHA-256 055c75c7a8b907224556661e92a849ab481c2f1e4d5f14b9edd36375ae574216

### EVT-0006

```text
ID: EVT-0006
Type: screenshot
Automated: unknown
Human involved: unknown
Notice provided: unknown
Reproducible: unknown
Evidence status: unverified
Notes: Binary artifact preserved; no text could be extracted. Enter its facts with `audit edit`. (could not read file for text extraction: cannot identify image file 'examples\\app_banner.png') Ingest warnings: could not read file for text extraction: cannot identify image file 'examples\\app_banner.png'
```
- Artifact app\_banner.png (name as supplied) → evidence/7332b0057d6b\_app\_banner.png, 29 bytes, SHA-256 7332b0057d6b283cbabdf237022735f3aa65f7a465b9454d8466be0dedcd410d

## Integrity

All 19 ledger entries chain correctly, every evidence file matches its recorded SHA-256 hash, and the evidence folder holds no unrecorded files.

Ledger anchor at the time of this report: `19:030624f47d4e64f1c00a9d97f24c944bb5b65622addce9ffddac53cde64071b8`. Anyone holding it can confirm with `audit verify --expect <anchor> --exact` that the ledger is still exactly as it was when this report was made.

## Method and limitations

- Each finding describes what is **absent from the collected record**. It does not claim that something did not happen inside the institution.
- Fields marked *(extracted, unconfirmed)* were pulled out automatically and have not yet been checked by a person.
- Copies of the evidence are stored byte for byte and identified by SHA-256. The ledger is append-only and hash-chained, so editing or deleting a recorded entry is detected. Replacing the whole ledger with a new, consistent one is only detected against a head hash saved somewhere else beforehand.
- This report is not legal advice.
