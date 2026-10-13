# System Security Plan — Cybersecurity Home Lab (HL-01)

> **At a glance.** A system security plan for a single-operator security lab, developed with the NIST Risk Management Framework (SP 800-37 Rev 2) and structured to the SP 800-18 Rev 2 Security Plan Example Outline. Identifying values are replaced or redacted, as the outline provides: *"Redact sensitive system information as required."*
>
> - **System:** two components, Ubuntu Server (SIEM) and the Samba DC (§7); categorized HIGH for confidentiality, integrity and availability (§6.2).
> - **Controls:** 286 in the tailored baseline, from the 370 of the SP 800-53B HIGH baseline, less 85 tailored out (84 on scoping grounds, 1 with a compensating control), plus 1 added (§10.2).
> - **Plan status:** control selection complete; tailoring complete except organization-defined parameter values, most of which are assigned at implementation (§10.2); assessment of nine of the controls named by Findings 1–9 (AC-3, AC-7, CA-3, CM-7, SA-9, SA-22, SC-7, SI-2, SI-3) complete. Plan approval and authorization decision not issued (§4).
> - **Findings:** 1, 5, 9, 12 and 14 open; 2, 3, 4, 7, 8, 10, 11 and 13 closed; 6 withdrawn (§11).

---

## 1. System Name and Identifier

| Element | Value |
|---|---|
| System name | Cybersecurity Home Lab |
| System identifier | HL-01 |
| Historical names | None |

---

## 2. System Overview

**Purpose.** HL-01 supports three functions: **detection** (a Wazuh SIEM), **identity services** (a Samba Active Directory domain), and **evidence production** (command output, alert records, packet captures, and assessment and incident documentation).

| Characteristic | Value |
|---|---|
| Environment type | Testing and training |
| Implemented technology | On-premises: two virtual machines (VMware Fusion on a macOS host) |
| System exposure | Isolated for the lab segment; restricted for the home-network side |
| System criticality | Mission-critical to its own three functions |
| Ownership | Privately owned and operated by a single individual |
| Common control provider | None. No controls are inherited from the MacBook Air (macOS; hypervisor and administration host) outside the boundary. |

**Users.** One operator administers both components over SSH from the MacBook Air. The directory also holds test accounts used in exercises. No data about real individuals is processed.

**Factors presenting additional risk:**

- The Samba DC is dual-homed across the lab segment and the home network.
- Kali Linux (attack simulation) shares the lab segment with Ubuntu Server and the Samba DC by design.
- Neither server has malicious code protection meeting the approved values (Finding 12).
- The Samba DC accepts an anonymous file-sharing session and, over the network RPC transport, lists all 8 domain user accounts to anonymous requesters on the lab segment (Finding 14).

---

## 3. Laws, Regulations, and Policies

**Laws and regulations: none identified.** HL-01 is a privately owned, nonfederal system that processes no federal information and no data about individuals. SP 800-18 Rev 2 §1.1: *"Nonfederal organizations — including private and small businesses, academic institutions, and state, local, and tribal governments — may utilize the guidelines provided in this publication to support their risk management programs."*

**Policies: none issued.** Technical settings, such as the domain password and lockout policy and the host firewall defaults, are configured on the components but are not issued as organizational policy. No rules of behavior (PL-4) have been issued.

**Standards applied voluntarily:**

| Publication | Used for |
|---|---|
| NIST SP 800-37 Rev 2 | Risk Management Framework steps and tasks |
| FIPS 199 (February 2004); NIST SP 800-60 Vol 1 Rev 1 | Security categorization |
| NIST SP 800-53 Rev 5 (Release 5.2.0) | Control catalog |
| NIST SP 800-53B (Release 5.2.0) | Control baselines and tailoring |
| NIST SP 800-53A Rev 5 (Release 5.2.0) | Control assessment procedures (`security-assessment-plan.md`) |
| NIST SP 800-18 Rev 2 | System plan elements and structure |
| NIST SP 800-88 Rev 2 | Media sanitization (§10.2, MP-6 value) |

---

## 4. System Status

| Element | Status |
|---|---|
| System security plan approval | Not issued. Select step partly complete: controls selected (SP 800-37 Rev 2 Task S-1) and tailored (Task S-2) except organization-defined parameter values, most of which are assigned at implementation (§10.2); Tasks S-3 to S-5 not done. Plan approval (Task S-6) is pending Authorizing Official review (§5). |
| Authorization decision | Not issued |
| Operational status | In operation, not authorized. SP 800-18 Rev 2 defines "Operational" as *"The authorized system is operating in the operational environment"* and provides that *"Organizations may use other operational status indicators as needed …"* |

---

## 5. Roles

| Role | Assigned to |
|---|---|
| System owner; information owner; system security officer | Jason Mason |
| Authorizing Official | Not designated |
| Control assessor | System owner (self-assessment; security assessment plan §2) |

**Why no Authorizing Official is designated.** SP 800-37 Rev 2 Task P-1: *"authorizing officials cannot occupy the role of system owner … for systems … they are authorizing."* This single-operator system has no one else to fill the role. Every Authorizing Official decision is recorded as pending review or not issued, never as made. Four are named here: categorization approval, plan approval, acceptance of risk for tailored-out controls, and authorization. The decisions within each plan, such as the authorization boundary (§7) and the level of assessor independence (assessment plan §2), await Authorizing Official review with that plan (§4; assessment plan §7).

**Separation of duties.** One person holds every assigned role. The SP 800-18 Rev 2 supplement *System Plan-related Roles and Responsibilities*: *"When multiple roles are fulfilled by the same individual, additional considerations for the separation of duties may require compensating controls that are documented in the system plan."* This is addressed under AC-5 in tailoring (§10.2).

**Contact:** GitHub, `JSON-MSON`.

---

## 6. Security Categorization

### 6.1 Information types

Organization-identified (SP 800-60 Vol 1 Rev 1 §4.1.4); provisional impact levels from SP 800-60 Vol 2 Rev 1 were not used.

| Information type | Confidentiality | Integrity | Availability | Basis |
|---|---|---|---|---|
| 1. Identity and authentication data | HIGH | HIGH | HIGH | Disclosure of the key that signs Kerberos ticket-granting tickets lets an attacker forge authentication for any account in the domain (MITRE ATT&CK v19.2, T1558.001); identity services is a primary function. |
| 2. Security event and audit log data | LOW | MODERATE | MODERATE | A documented log truncation destroyed the live log for a bounded period; its content survived in the detection record, and detection was not disabled. |
| 3. Network traffic capture data | LOW | LOW | LOW | Completed exercise; the captured credential is a non-functioning test value. |
| 4. System configuration data | MODERATE | HIGH | MODERATE | Unauthorized change leaves a control that appears active while no longer functioning. |
| 5. Assessment and incident documentation | MODERATE | HIGH | MODERATE | Every downstream artifact inherits what this documentation records. |

Each rating uses FIPS 199 impact definitions, applied to degradation of mission capability.

### 6.2 System security category

Per the FIPS 199 high-water-mark rule (SP 800-60 Vol 1 Rev 1 §4.4.1), each objective takes the highest level rated for any information type. Type 1 sets HIGH on all three. The adjustment factors of SP 800-60 Vol 1 Rev 1 §4.4.2 were reviewed; none changes a result already at the ceiling of the scale.

```
SC Cybersecurity Home Lab = {(confidentiality, HIGH), (integrity, HIGH), (availability, HIGH)}
```

**Overall impact level: HIGH.** Categorization approval (Task C-3) is pending Authorizing Official review.

---

## 7. Authorization Boundary

Two components across two network segments. The boundary follows SP 800-37 Rev 2's definition: *"All components of an information system to be authorized for operation by an authorizing official. …"*

| Component | Type | Role | Network placement |
|---|---|---|---|
| Ubuntu Server | Virtual machine, Ubuntu Server LTS | Wazuh manager, indexer, and dashboard; domain member | Lab segment only; no route off it |
| Samba DC | Virtual machine, Ubuntu Server LTS | Samba Active Directory: directory, Kerberos, DNS | Dual-homed: lab segment and home network; the home-network adapter is bridged to the MacBook Air's Wi-Fi |

| Excluded | Reason |
|---|---|
| Kali Linux | Generates test traffic against the system; holds none of its information types |
| MacBook Air | Hosting infrastructure for the two virtual machines; the operator administers every component from it over SSH |
| The rest of the home network | The Samba DC connects to it; the network itself is outside the boundary |

```mermaid
flowchart TB
    subgraph BOUNDARY["HL-01 authorization boundary"]
        subgraph SEG["Isolated lab segment"]
            SIEM["Ubuntu Server<br/>Wazuh SIEM"]
        end
        DC["Samba DC<br/>Active Directory, dual-homed"]
    end
    ATK["Kali Linux<br/>attack simulation, outside the boundary"]
    HOME["Home network<br/>outside the boundary"]
    HV["MacBook Air<br/>hypervisor and administration host, outside the boundary"]
    NET["Internet"]
    SIEM <-->|"domain membership"| DC
    ATK -->|"test traffic"| SIEM
    ATK -->|"test traffic"| DC
    DC --- HOME
    HOME --- NET
    HV -.->|"hosts"| SIEM
    HV -.->|"hosts"| DC
```

---

## 8. Information Exchanges

No information exchange agreements exist; none of the connected systems is separately authorized. No remote-management service is connected to the system; the Action1 account closure is tracked in `poam.md` P-06.

| Counterpart | Components | What crosses the boundary | Security consideration |
|---|---|---|---|
| Home network | Samba DC | Inbound: SSH from the MacBook Air only (assessment report §13.1) | Host firewall, default deny inbound (`poam.md` P-01) |
| Internet | Samba DC | Outbound paths exist through the home gateway; the Samba DC uses one to reach its time server ([evidence appendix §16](evidence-appendix.md#16-time-synchronization-on-ubuntu-server)); inbound reachability from the internet was not examined. | The Samba DC's host firewall allows all outgoing connections (assessment report §13.1) |
| MacBook Air | Both components | Administration over SSH; evidence copied out for publication | Published evidence is redacted |
| Kali Linux | Ubuntu Server; Samba DC (lab-segment interface) | Hostile test traffic, by design | A host-specific firewall rule denies it SSH to Ubuntu Server; the Samba DC's firewall admits only directory services from it |

---

## 9. System Component Inventory

Captured live from each component and from the virtual machine configuration files. Exact versions are held in the operator's working records.

| Component | Hardware | Operating system and support status | Key software |
|---|---|---|---|
| Ubuntu Server | VMware virtual machine, arm64, 2 vCPU, 6 GB; virtual EFI supplied by the MacBook Air (outside the boundary), Secure Boot not enabled | Ubuntu Server 26.04 LTS; supported | Wazuh 4.14, OpenSSH, Samba winbind, ufw, chrony |
| Samba DC | VMware virtual machine, arm64, 2 vCPU, 4 GB; virtual EFI supplied by the MacBook Air (outside the boundary), Secure Boot not enabled | Ubuntu Server 26.04 LTS; supported | Samba Active Directory domain controller, MIT Kerberos tools, OpenSSH, ufw, chrony |

---

## 10. Control Selection and Tailoring

### 10.1 Control selection (SP 800-37 Rev 2 Task S-1)

**Baseline: SP 800-53B HIGH.** SP 800-53B §2.2 defines *"a high-impact system"* as *"a system in which at least one security objective is high"*, and *"The organization selects one of three security control baselines from Chapter Three corresponding to the low-impact, moderate-impact, or high-impact categorization of the system."* HL-01 is HIGH on all three objectives (§6.2).

**370 controls and control enhancements are selected** — 188 base controls and 182 enhancements across 18 families. The Program Management and Personally Identifiable Information Processing and Transparency families have no HIGH-baseline entries. The privacy baseline is not selected: the system processes no data about individuals. The SP 800-53 Rev 5 (Release 5.2.0) Summary of Changes records that SP 800-53B (Release 5.2.0) *"has no changes"*, and that the three controls and enhancements the release adds, and the one enhancement whose requirement it revises, are each *"not included in any SP 800-53B baseline."*

| Family | Selected | Family | Selected |
|---|---|---|---|
| Access Control | 46 | Media Protection | 10 |
| Awareness and Training | 6 | Physical and Environmental Protection | 25 |
| Audit and Accountability | 25 | Planning | 7 |
| Assessment, Authorization, and Monitoring | 14 | Personnel Security | 10 |
| Configuration Management | 32 | Risk Assessment | 11 |
| Contingency Planning | 35 | System and Services Acquisition | 21 |
| Identification and Authentication | 26 | System and Communications Protection | 30 |
| Incident Response | 18 | System and Information Integrity | 28 |
| Maintenance | 12 | Supply Chain Risk Management | 14 |
| | | **Total** | **370** |

**Baseline assumptions (SP 800-53B §2.3)**, checked against this system. SP 800-53B: *"If any of the above assumptions are not valid, then some of the security controls allocated to the control baselines in Chapter Three may not be applicable—a situation that can be addressed by applying the tailoring guidance in Section 2.4 and the results of organization- and system-level risk assessments."*

| Assumption | Holds? | Evidence |
|---|---|---|
| Information is relatively persistent (*"utility for a relatively long duration (e.g., days, weeks)"*) | Yes | Directory and alert records are ongoing; exercise captures are retained. |
| Systems are multi-user, serially or concurrently | By account, not by person | One operator; several administrative accounts and directory test accounts. |
| Some information is not shareable with other authorized users | Yes | Administrative accounts are separate from test accounts; file permissions enforce the split (one set of file modes is broader than the captures', Finding 5). |
| Systems are networked and general purpose | Yes | Two components on two segments; general-purpose operating systems. |
| The organization has the structure, resources, and infrastructure to implement the controls | No | One individual holds every assigned role and no policy is issued. SP 800-53B footnote 22 names this case for small nonfederal entities, which *"may not be large enough or sufficiently resourced to have elements dedicated to providing the range of security or privacy capabilities that are assumed by the baselines."* |

| Assumption not addressed by the baselines | Applies? | Evidence |
|---|---|---|
| Insider threats exist within the organization | No | No personnel other than the system owner. |
| Classified information is processed | No | Nonfederal; no federal information. |
| Advanced persistent threats exist within the organization | Not established | No system risk assessment has been developed. |
| Information requires specialized protection under legislation, directives, regulations, or policies | No | None identified (§3). |
| Systems communicate across different security domains | Yes | A security domain is *"a domain that implements a security policy and is administered by a single authority"* (SP 800-53 Rev 5 glossary). The Samba DC reaches the internet through the home gateway. |

SP 800-53B: where these apply, *"additional controls from [SP 800-53] are likely needed to ensure adequate protection—a situation that can also be effectively addressed by applying the tailoring guidance in Section 2.4 (specifically, security control supplementation) and the results of organization- and system-level assessments of risk."*

### 10.2 Tailoring (SP 800-37 Rev 2 Task S-2)

**Result: 286 controls in the tailored baseline** — 370 selected, 85 tailored out, 1 added. SP 800-53B §2.4 requires that *"Every control from the selected control baseline is accounted for by the organization. If certain controls are tailored out, the rationale is recorded in the system security and privacy plans …"* Every control's disposition is listed at the end of this section.

| Family | Selected | Tailored out | Added | Tailored baseline | Basis for tailoring |
|---|---|---|---|---|---|
| Access Control | 46 | 8 | — | 38 | Single operator; no mobile devices; no wireless equipment in the system; no public content; separation of duties compensated |
| Awareness and Training | 6 | 6 | — | 0 | Single operator — no workforce for awareness or role-based training programs; contingency and incident response training (CP-3, IR-2) is retained for the operator |
| Audit and Accountability | 25 | 1 | — | 24 | No automated physical access monitoring records to correlate with |
| Assessment, Authorization, and Monitoring | 14 | 3 | — | 11 | No independent assessor available |
| Configuration Management | 32 | 1 | — | 31 | No separate security representatives |
| Contingency Planning | 35 | 16 | — | 19 | No alternate site or telecommunications provider |
| Identification and Authentication | 26 | 10 | 1 | 17 | No PIV credentials, external users, or identity proofing; IA-5(13) added |
| Incident Response | 18 | 1 | — | 17 | No incident response team |
| Maintenance | 12 | 2 | — | 10 | No maintenance personnel other than the operator |
| Media Protection | 10 | — | — | 10 | None |
| Physical and Environmental Protection | 25 | 12 | — | 13 | Residence without facility infrastructure |
| Planning | 7 | — | — | 7 | None |
| Personnel Security | 10 | 10 | — | 0 | Single operator — no personnel |
| Risk Assessment | 11 | — | — | 11 | None |
| System and Services Acquisition | 21 | 8 | — | 13 | Off-the-shelf components; no external developer builds or maintains software for this system; no PIV products |
| System and Communications Protection | 30 | 1 | — | 29 | No remote devices |
| System and Information Integrity | 28 | 3 | — | 25 | No mail service across the boundary; no wireless equipment in the system |
| Supply Chain Risk Management | 14 | 3 | — | 11 | No team to establish; off-the-shelf supply chain, no notification agreement exists; no training audience |
| **Total** | **370** | **85** | **1** | **286** | |

**Scoping considerations (SP 800-53B §2.4).** 84 controls are tailored out on scoping grounds:

- **Single operator (31).** §2.4 names *"single-user systems and operations"* among the operational factors that justify tailoring, and the baseline assumption that the organization has the structure and resources to implement the controls does not hold (§10.1). Personnel security, awareness and training, identity proofing, and controls requiring an independent assessor or a separate team have no one to apply to.
- **No facility infrastructure (13).** The system operates in a residence: no alarm or surveillance equipment, system-level physical access monitoring, or visitor records; no emergency shutoff or lighting, long-term alternate power, automatic fire detection or suppression, automated water-damage protection, or controlled delivery area; no alternate work site; and no automated physical access records to correlate with audit records (AU-6(6)).
- **No alternate site or provider (16).** Alternate storage and processing sites and alternate telecommunications services do not exist. Availability is rated HIGH (§6.2), so this is an availability risk submitted for acceptance (pending Authorizing Official review), not a downgrade.
- **Technology not present (16).** §2.4: controls referring to specific technologies *"are applicable only if those technologies are implemented or required for use within organizational systems."* The system has no PIV credentials, no users from outside the organization, no mobile devices, no remote devices, no wireless equipment of its own, and no mail service operating across the system boundary (spam protection, SI-8, acts on messaging the system does not run; web- and file-borne malicious code is covered by SI-3, which is retained), and it hosts no publicly accessible content (AC-22). Each server's kernel shows no wireless interface, wireless radio or Bluetooth controller (checked October 10, 2026). The Samba DC's home-network adapter is bridged to the MacBook Air's Wi-Fi, outside the boundary, so wireless access to the system exists: AC-18 and AC-18(1) are retained. AC-18(3) is tailored out because no radio is embedded in either component; AC-18(4) and AC-18(5) because the wireless equipment, the MacBook Air's radio and the home network's access point, with their configuration, antennas and transmission power, is outside the boundary; and SI-4(14) because no wireless equipment is inside the boundary to monitor; tailoring it out also gives up its scan for unauthorized wireless access points. Publishing this portfolio's lab evidence to external public repositories is not publicly accessible content hosted on the system; that activity falls under PL-4(1) (Social Media and External Site/Application Usage Restrictions), which is retained, and whose rules of behavior are not yet issued (§3).
- **No external developer or supply-chain relationship (8).** Every component is off-the-shelf (§9). No external developer builds or maintains software for this system. No supply-chain notification agreement (SR-8) exists with any supplier.

**Compensating control.** AC-5 (Separation of Duties) is tailored out: one person holds every assigned role (§5). More frequent audit record review under AU-6 is designated to compensate (its frequency is assigned at implementation; AU-6 is not yet assessed), as SP 800-53B §2.4, footnote 33 provides: *"In a small organization, more frequent auditing, targeted role-based training, or stronger personnel screening may be implemented in lieu of separation of duties."*

**Supplementation.** IA-5(13) (Expiration of Cached Authenticators) is added. It is in no SP 800-53B baseline and addresses Finding 7 (closed October 12, 2026): cached domain logons, which could be accepted while the domain connection was flagged offline.

**Parameter values.** Organization-defined parameter values for the controls in the assessment scope are assigned in `security-assessment-plan.md`. The values below are assigned for the Windows client's disposal (`poam.md` P-17). All others are assigned at implementation.

| Control | Parameter | Value |
|---|---|---|
| MP-6 | System media to be sanitized prior to release for reuse | The Windows client's internal storage drive |
| MP-6 | Sanitization techniques and procedures to be used for sanitization prior to release for reuse | Purge, the method SP 800-88 Rev 2 (Figure 1) gives for media that will be reused, hold HIGH-confidentiality information and stay under organizational control; carried out with the drive's ATA Enhanced Security Erase command, as decided by the system owner; verified by reading the whole drive; validated; certificate of sanitization completed |
| SR-12 | Data, documentation, tools, or system components to be disposed of | The Windows client and its storage media |
| SR-12 | Techniques and methods for disposing of data, documentation, tools, or system components | The `poam.md` P-17 tasks: the computer account deleted from the domain; the storage media sanitized as assigned under MP-6; the inventory, boundary and plans updated |

**Common controls.** None; no common control provider exists (§2).

**Risk acceptance.** Acceptance of the risk from controls tailored out is an Authorizing Official decision and is pending review (§5).

<details>
<summary>Disposition of every control (371 rows)</summary>

| Control | Name | Disposition |
|---|---|---|
| AC-1 | Policy and Procedures | Retained |
| AC-2 | Account Management | Retained |
| AC-2(1) | AUTOMATED SYSTEM ACCOUNT MANAGEMENT | Retained |
| AC-2(2) | AUTOMATED TEMPORARY AND EMERGENCY ACCOUNT MANAGEMENT | Retained |
| AC-2(3) | DISABLE ACCOUNTS | Retained |
| AC-2(4) | AUTOMATED AUDIT ACTIONS | Retained |
| AC-2(5) | INACTIVITY LOGOUT | Retained |
| AC-2(11) | USAGE CONDITIONS | Retained |
| AC-2(12) | ACCOUNT MONITORING FOR ATYPICAL USAGE | Retained |
| AC-2(13) | DISABLE ACCOUNTS FOR HIGH-RISK INDIVIDUALS | Tailored out — single operator (scoping) |
| AC-3 | Access Enforcement | Retained |
| AC-4 | Information Flow Enforcement | Retained |
| AC-4(4) | FLOW CONTROL OF ENCRYPTED INFORMATION | Retained |
| AC-5 | Separation of Duties | Tailored out — compensated by AU-6 |
| AC-6 | Least Privilege | Retained |
| AC-6(1) | AUTHORIZE ACCESS TO SECURITY FUNCTIONS | Retained |
| AC-6(2) | NON-PRIVILEGED ACCESS FOR NONSECURITY FUNCTIONS | Retained |
| AC-6(3) | NETWORK ACCESS TO PRIVILEGED COMMANDS | Retained |
| AC-6(5) | PRIVILEGED ACCOUNTS | Retained |
| AC-6(7) | REVIEW OF USER PRIVILEGES | Retained |
| AC-6(9) | LOG USE OF PRIVILEGED FUNCTIONS | Retained |
| AC-6(10) | PROHIBIT NON-PRIVILEGED USERS FROM EXECUTING PRIVILEGED FUNCTIONS | Retained |
| AC-7 | Unsuccessful Logon Attempts | Retained |
| AC-8 | System Use Notification | Retained |
| AC-10 | Concurrent Session Control | Retained |
| AC-11 | Device Lock | Retained |
| AC-11(1) | PATTERN-HIDING DISPLAYS | Retained |
| AC-12 | Session Termination | Retained |
| AC-14 | Permitted Actions without Identification or Authentication | Retained |
| AC-17 | Remote Access | Retained |
| AC-17(1) | MONITORING AND CONTROL | Retained |
| AC-17(2) | PROTECTION OF CONFIDENTIALITY AND INTEGRITY USING ENCRYPTION | Retained |
| AC-17(3) | MANAGED ACCESS CONTROL POINTS | Retained |
| AC-17(4) | PRIVILEGED COMMANDS AND ACCESS | Retained |
| AC-18 | Wireless Access | Retained |
| AC-18(1) | AUTHENTICATION AND ENCRYPTION | Retained |
| AC-18(3) | DISABLE WIRELESS NETWORKING | Tailored out — technology not present (scoping) |
| AC-18(4) | RESTRICT CONFIGURATIONS BY USERS | Tailored out — technology not present (scoping) |
| AC-18(5) | ANTENNAS AND TRANSMISSION POWER LEVELS | Tailored out — technology not present (scoping) |
| AC-19 | Access Control for Mobile Devices | Tailored out — technology not present (scoping) |
| AC-19(5) | FULL DEVICE OR CONTAINER-BASED ENCRYPTION | Tailored out — technology not present (scoping) |
| AC-20 | Use of External Systems | Retained |
| AC-20(1) | LIMITS ON AUTHORIZED USE | Retained |
| AC-20(2) | PORTABLE STORAGE DEVICES — RESTRICTED USE | Retained |
| AC-21 | Information Sharing | Retained |
| AC-22 | Publicly Accessible Content | Tailored out — technology not present (scoping) |
| AT-1 | Policy and Procedures | Tailored out — single operator (scoping) |
| AT-2 | Literacy Training and Awareness | Tailored out — single operator (scoping) |
| AT-2(2) | INSIDER THREAT | Tailored out — single operator (scoping) |
| AT-2(3) | SOCIAL ENGINEERING AND MINING | Tailored out — single operator (scoping) |
| AT-3 | Role-Based Training | Tailored out — single operator (scoping) |
| AT-4 | Training Records | Tailored out — single operator (scoping) |
| AU-1 | Policy and Procedures | Retained |
| AU-2 | Event Logging | Retained |
| AU-3 | Content of Audit Records | Retained |
| AU-3(1) | ADDITIONAL AUDIT INFORMATION | Retained |
| AU-4 | Audit Log Storage Capacity | Retained |
| AU-5 | Response to Audit Logging Process Failures | Retained |
| AU-5(1) | STORAGE CAPACITY WARNING | Retained |
| AU-5(2) | REAL-TIME ALERTS | Retained |
| AU-6 | Audit Record Review, Analysis, and Reporting | Retained |
| AU-6(1) | AUTOMATED PROCESS INTEGRATION | Retained |
| AU-6(3) | CORRELATE AUDIT RECORD REPOSITORIES | Retained |
| AU-6(5) | INTEGRATED ANALYSIS OF AUDIT RECORDS | Retained |
| AU-6(6) | CORRELATION WITH PHYSICAL MONITORING | Tailored out — no facility infrastructure (scoping) |
| AU-7 | Audit Record Reduction and Report Generation | Retained |
| AU-7(1) | AUTOMATIC PROCESSING | Retained |
| AU-8 | Time Stamps | Retained |
| AU-9 | Protection of Audit Information | Retained |
| AU-9(2) | STORE ON SEPARATE PHYSICAL SYSTEMS OR COMPONENTS | Retained |
| AU-9(3) | CRYPTOGRAPHIC PROTECTION | Retained |
| AU-9(4) | ACCESS BY SUBSET OF PRIVILEGED USERS | Retained |
| AU-10 | Non-repudiation | Retained |
| AU-11 | Audit Record Retention | Retained |
| AU-12 | Audit Record Generation | Retained |
| AU-12(1) | SYSTEM-WIDE AND TIME-CORRELATED AUDIT TRAIL | Retained |
| AU-12(3) | CHANGES BY AUTHORIZED INDIVIDUALS | Retained |
| CA-1 | Policy and Procedures | Retained |
| CA-2 | Control Assessments | Retained |
| CA-2(1) | INDEPENDENT ASSESSORS | Tailored out — single operator (scoping) |
| CA-2(2) | SPECIALIZED ASSESSMENTS | Retained |
| CA-3 | Information Exchange | Retained |
| CA-3(6) | TRANSFER AUTHORIZATIONS | Retained |
| CA-5 | Plan of Action and Milestones | Retained |
| CA-6 | Authorization | Retained |
| CA-7 | Continuous Monitoring | Retained |
| CA-7(1) | INDEPENDENT ASSESSMENT | Tailored out — single operator (scoping) |
| CA-7(4) | RISK MONITORING | Retained |
| CA-8 | Penetration Testing | Retained |
| CA-8(1) | INDEPENDENT PENETRATION TESTING AGENT OR TEAM | Tailored out — single operator (scoping) |
| CA-9 | Internal System Connections | Retained |
| CM-1 | Policy and Procedures | Retained |
| CM-2 | Baseline Configuration | Retained |
| CM-2(2) | AUTOMATION SUPPORT FOR ACCURACY AND CURRENCY | Retained |
| CM-2(3) | RETENTION OF PREVIOUS CONFIGURATIONS | Retained |
| CM-2(7) | CONFIGURE SYSTEMS AND COMPONENTS FOR HIGH-RISK AREAS | Retained |
| CM-3 | Configuration Change Control | Retained |
| CM-3(1) | AUTOMATED DOCUMENTATION, NOTIFICATION, AND PROHIBITION OF CHANGES | Retained |
| CM-3(2) | TESTING, VALIDATION, AND DOCUMENTATION OF CHANGES | Retained |
| CM-3(4) | SECURITY AND PRIVACY REPRESENTATIVES | Tailored out — single operator (scoping) |
| CM-3(6) | CRYPTOGRAPHY MANAGEMENT | Retained |
| CM-4 | Impact Analyses | Retained |
| CM-4(1) | SEPARATE TEST ENVIRONMENTS | Retained |
| CM-4(2) | VERIFICATION OF CONTROLS | Retained |
| CM-5 | Access Restrictions for Change | Retained |
| CM-5(1) | AUTOMATED ACCESS ENFORCEMENT AND AUDIT RECORDS | Retained |
| CM-6 | Configuration Settings | Retained |
| CM-6(1) | AUTOMATED MANAGEMENT, APPLICATION, AND VERIFICATION | Retained |
| CM-6(2) | RESPOND TO UNAUTHORIZED CHANGES | Retained |
| CM-7 | Least Functionality | Retained |
| CM-7(1) | PERIODIC REVIEW | Retained |
| CM-7(2) | PREVENT PROGRAM EXECUTION | Retained |
| CM-7(5) | AUTHORIZED SOFTWARE — ALLOW-BY-EXCEPTION | Retained |
| CM-8 | System Component Inventory | Retained |
| CM-8(1) | UPDATES DURING INSTALLATION AND REMOVAL | Retained |
| CM-8(2) | AUTOMATED MAINTENANCE | Retained |
| CM-8(3) | AUTOMATED UNAUTHORIZED COMPONENT DETECTION | Retained |
| CM-8(4) | ACCOUNTABILITY INFORMATION | Retained |
| CM-9 | Configuration Management Plan | Retained |
| CM-10 | Software Usage Restrictions | Retained |
| CM-11 | User-Installed Software | Retained |
| CM-12 | Information Location | Retained |
| CM-12(1) | AUTOMATED TOOLS TO SUPPORT INFORMATION LOCATION | Retained |
| CP-1 | Policy and Procedures | Retained |
| CP-2 | Contingency Plan | Retained |
| CP-2(1) | COORDINATE WITH RELATED PLANS | Retained |
| CP-2(2) | CAPACITY PLANNING | Retained |
| CP-2(3) | RESUME MISSION AND BUSINESS FUNCTIONS | Retained |
| CP-2(5) | CONTINUE MISSION AND BUSINESS FUNCTIONS | Retained |
| CP-2(8) | IDENTIFY CRITICAL ASSETS | Retained |
| CP-3 | Contingency Training | Retained |
| CP-3(1) | SIMULATED EVENTS | Retained |
| CP-4 | Contingency Plan Testing | Retained |
| CP-4(1) | COORDINATE WITH RELATED PLANS | Retained |
| CP-4(2) | ALTERNATE PROCESSING SITE | Tailored out — no alternate site or provider (scoping) |
| CP-6 | Alternate Storage Site | Tailored out — no alternate site or provider (scoping) |
| CP-6(1) | SEPARATION FROM PRIMARY SITE | Tailored out — no alternate site or provider (scoping) |
| CP-6(2) | RECOVERY TIME AND RECOVERY POINT OBJECTIVES | Tailored out — no alternate site or provider (scoping) |
| CP-6(3) | ACCESSIBILITY | Tailored out — no alternate site or provider (scoping) |
| CP-7 | Alternate Processing Site | Tailored out — no alternate site or provider (scoping) |
| CP-7(1) | SEPARATION FROM PRIMARY SITE | Tailored out — no alternate site or provider (scoping) |
| CP-7(2) | ACCESSIBILITY | Tailored out — no alternate site or provider (scoping) |
| CP-7(3) | PRIORITY OF SERVICE | Tailored out — no alternate site or provider (scoping) |
| CP-7(4) | PREPARATION FOR USE | Tailored out — no alternate site or provider (scoping) |
| CP-8 | Telecommunications Services | Tailored out — no alternate site or provider (scoping) |
| CP-8(1) | PRIORITY OF SERVICE PROVISIONS | Tailored out — no alternate site or provider (scoping) |
| CP-8(2) | SINGLE POINTS OF FAILURE | Tailored out — no alternate site or provider (scoping) |
| CP-8(3) | SEPARATION OF PRIMARY AND ALTERNATE PROVIDERS | Tailored out — no alternate site or provider (scoping) |
| CP-8(4) | PROVIDER CONTINGENCY PLAN | Tailored out — no alternate site or provider (scoping) |
| CP-9 | System Backup | Retained |
| CP-9(1) | TESTING FOR RELIABILITY AND INTEGRITY | Retained |
| CP-9(2) | TEST RESTORATION USING SAMPLING | Retained |
| CP-9(3) | SEPARATE STORAGE FOR CRITICAL INFORMATION | Retained |
| CP-9(5) | TRANSFER TO ALTERNATE STORAGE SITE | Tailored out — no alternate site or provider (scoping) |
| CP-9(8) | CRYPTOGRAPHIC PROTECTION | Retained |
| CP-10 | System Recovery and Reconstitution | Retained |
| CP-10(2) | TRANSACTION RECOVERY | Retained |
| CP-10(4) | RESTORE WITHIN TIME PERIOD | Retained |
| IA-1 | Policy and Procedures | Retained |
| IA-2 | Identification and Authentication (Organizational Users) | Retained |
| IA-2(1) | MULTI-FACTOR AUTHENTICATION TO PRIVILEGED ACCOUNTS | Retained |
| IA-2(2) | MULTI-FACTOR AUTHENTICATION TO NON-PRIVILEGED ACCOUNTS | Retained |
| IA-2(5) | INDIVIDUAL AUTHENTICATION WITH GROUP AUTHENTICATION | Retained |
| IA-2(8) | ACCESS TO ACCOUNTS — REPLAY RESISTANT | Retained |
| IA-2(12) | ACCEPTANCE OF PIV CREDENTIALS | Tailored out — technology not present (scoping) |
| IA-3 | Device Identification and Authentication | Retained |
| IA-4 | Identifier Management | Retained |
| IA-4(4) | IDENTIFY USER STATUS | Retained |
| IA-5 | Authenticator Management | Retained |
| IA-5(1) | PASSWORD-BASED AUTHENTICATION | Retained |
| IA-5(2) | PUBLIC KEY-BASED AUTHENTICATION | Retained |
| IA-5(6) | PROTECTION OF AUTHENTICATORS | Retained |
| IA-5(13) | EXPIRATION OF CACHED AUTHENTICATORS | Added — supplementation (Finding 7) |
| IA-6 | Authentication Feedback | Retained |
| IA-7 | Cryptographic Module Authentication | Retained |
| IA-8 | Identification and Authentication (Non-Organizational Users) | Tailored out — technology not present (scoping) |
| IA-8(1) | ACCEPTANCE OF PIV CREDENTIALS FROM OTHER AGENCIES | Tailored out — technology not present (scoping) |
| IA-8(2) | ACCEPTANCE OF EXTERNAL AUTHENTICATORS | Tailored out — technology not present (scoping) |
| IA-8(4) | USE OF DEFINED PROFILES | Tailored out — technology not present (scoping) |
| IA-11 | Re-authentication | Retained |
| IA-12 | Identity Proofing | Tailored out — single operator (scoping) |
| IA-12(2) | IDENTITY EVIDENCE | Tailored out — single operator (scoping) |
| IA-12(3) | IDENTITY EVIDENCE VALIDATION AND VERIFICATION | Tailored out — single operator (scoping) |
| IA-12(4) | IN-PERSON VALIDATION AND VERIFICATION | Tailored out — single operator (scoping) |
| IA-12(5) | ADDRESS CONFIRMATION | Tailored out — single operator (scoping) |
| IR-1 | Policy and Procedures | Retained |
| IR-2 | Incident Response Training | Retained |
| IR-2(1) | SIMULATED EVENTS | Retained |
| IR-2(2) | AUTOMATED TRAINING ENVIRONMENTS | Retained |
| IR-3 | Incident Response Testing | Retained |
| IR-3(2) | COORDINATION WITH RELATED PLANS | Retained |
| IR-4 | Incident Handling | Retained |
| IR-4(1) | AUTOMATED INCIDENT HANDLING PROCESSES | Retained |
| IR-4(4) | INFORMATION CORRELATION | Retained |
| IR-4(11) | INTEGRATED INCIDENT RESPONSE TEAM | Tailored out — single operator (scoping) |
| IR-5 | Incident Monitoring | Retained |
| IR-5(1) | AUTOMATED TRACKING, DATA COLLECTION, AND ANALYSIS | Retained |
| IR-6 | Incident Reporting | Retained |
| IR-6(1) | AUTOMATED REPORTING | Retained |
| IR-6(3) | SUPPLY CHAIN COORDINATION | Retained |
| IR-7 | Incident Response Assistance | Retained |
| IR-7(1) | AUTOMATION SUPPORT FOR AVAILABILITY OF INFORMATION AND SUPPORT | Retained |
| IR-8 | Incident Response Plan | Retained |
| MA-1 | Policy and Procedures | Retained |
| MA-2 | Controlled Maintenance | Retained |
| MA-2(2) | AUTOMATED MAINTENANCE ACTIVITIES | Retained |
| MA-3 | Maintenance Tools | Retained |
| MA-3(1) | INSPECT TOOLS | Retained |
| MA-3(2) | INSPECT MEDIA | Retained |
| MA-3(3) | PREVENT UNAUTHORIZED REMOVAL | Retained |
| MA-4 | Nonlocal Maintenance | Retained |
| MA-4(3) | COMPARABLE SECURITY AND SANITIZATION | Retained |
| MA-5 | Maintenance Personnel | Tailored out — single operator (scoping) |
| MA-5(1) | INDIVIDUALS WITHOUT APPROPRIATE ACCESS | Tailored out — single operator (scoping) |
| MA-6 | Timely Maintenance | Retained |
| MP-1 | Policy and Procedures | Retained |
| MP-2 | Media Access | Retained |
| MP-3 | Media Marking | Retained |
| MP-4 | Media Storage | Retained |
| MP-5 | Media Transport | Retained |
| MP-6 | Media Sanitization | Retained |
| MP-6(1) | REVIEW, APPROVE, TRACK, DOCUMENT, AND VERIFY | Retained |
| MP-6(2) | EQUIPMENT TESTING | Retained |
| MP-6(3) | NONDESTRUCTIVE TECHNIQUES | Retained |
| MP-7 | Media Use | Retained |
| PE-1 | Policy and Procedures | Retained |
| PE-2 | Physical Access Authorizations | Retained |
| PE-3 | Physical Access Control | Retained |
| PE-3(1) | SYSTEM ACCESS | Retained |
| PE-4 | Access Control for Transmission | Retained |
| PE-5 | Access Control for Output Devices | Retained |
| PE-6 | Monitoring Physical Access | Retained |
| PE-6(1) | INTRUSION ALARMS AND SURVEILLANCE EQUIPMENT | Tailored out — no facility infrastructure (scoping) |
| PE-6(4) | MONITORING PHYSICAL ACCESS TO SYSTEMS | Tailored out — no facility infrastructure (scoping) |
| PE-8 | Visitor Access Records | Tailored out — no facility infrastructure (scoping) |
| PE-8(1) | AUTOMATED RECORDS MAINTENANCE AND REVIEW | Tailored out — no facility infrastructure (scoping) |
| PE-9 | Power Equipment and Cabling | Retained |
| PE-10 | Emergency Shutoff | Tailored out — no facility infrastructure (scoping) |
| PE-11 | Emergency Power | Retained |
| PE-11(1) | ALTERNATE POWER SUPPLY — MINIMAL OPERATIONAL CAPABILITY | Tailored out — no facility infrastructure (scoping) |
| PE-12 | Emergency Lighting | Tailored out — no facility infrastructure (scoping) |
| PE-13 | Fire Protection | Retained |
| PE-13(1) | DETECTION SYSTEMS — AUTOMATIC ACTIVATION AND NOTIFICATION | Tailored out — no facility infrastructure (scoping) |
| PE-13(2) | SUPPRESSION SYSTEMS — AUTOMATIC ACTIVATION AND NOTIFICATION | Tailored out — no facility infrastructure (scoping) |
| PE-14 | Environmental Controls | Retained |
| PE-15 | Water Damage Protection | Retained |
| PE-15(1) | AUTOMATION SUPPORT | Tailored out — no facility infrastructure (scoping) |
| PE-16 | Delivery and Removal | Tailored out — no facility infrastructure (scoping) |
| PE-17 | Alternate Work Site | Tailored out — no facility infrastructure (scoping) |
| PE-18 | Location of System Components | Retained |
| PL-1 | Policy and Procedures | Retained |
| PL-2 | System Security and Privacy Plans | Retained |
| PL-4 | Rules of Behavior | Retained |
| PL-4(1) | SOCIAL MEDIA AND EXTERNAL SITE/APPLICATION USAGE RESTRICTIONS | Retained |
| PL-8 | Security and Privacy Architectures | Retained |
| PL-10 | Baseline Selection | Retained |
| PL-11 | Baseline Tailoring | Retained |
| PS-1 | Policy and Procedures | Tailored out — single operator (scoping) |
| PS-2 | Position Risk Designation | Tailored out — single operator (scoping) |
| PS-3 | Personnel Screening | Tailored out — single operator (scoping) |
| PS-4 | Personnel Termination | Tailored out — single operator (scoping) |
| PS-4(2) | AUTOMATED ACTIONS | Tailored out — single operator (scoping) |
| PS-5 | Personnel Transfer | Tailored out — single operator (scoping) |
| PS-6 | Access Agreements | Tailored out — single operator (scoping) |
| PS-7 | External Personnel Security | Tailored out — single operator (scoping) |
| PS-8 | Personnel Sanctions | Tailored out — single operator (scoping) |
| PS-9 | Position Descriptions | Tailored out — single operator (scoping) |
| RA-1 | Policy and Procedures | Retained |
| RA-2 | Security Categorization | Retained |
| RA-3 | Risk Assessment | Retained |
| RA-3(1) | SUPPLY CHAIN RISK ASSESSMENT | Retained |
| RA-5 | Vulnerability Monitoring and Scanning | Retained |
| RA-5(2) | UPDATE VULNERABILITIES TO BE SCANNED | Retained |
| RA-5(4) | DISCOVERABLE INFORMATION | Retained |
| RA-5(5) | PRIVILEGED ACCESS | Retained |
| RA-5(11) | PUBLIC DISCLOSURE PROGRAM | Retained |
| RA-7 | Risk Response | Retained |
| RA-9 | Criticality Analysis | Retained |
| SA-1 | Policy and Procedures | Retained |
| SA-2 | Allocation of Resources | Retained |
| SA-3 | System Development Life Cycle | Retained |
| SA-4 | Acquisition Process | Retained |
| SA-4(1) | FUNCTIONAL PROPERTIES OF CONTROLS | Retained |
| SA-4(2) | DESIGN AND IMPLEMENTATION INFORMATION FOR CONTROLS | Retained |
| SA-4(5) | SYSTEM, COMPONENT, AND SERVICE CONFIGURATIONS | Retained |
| SA-4(9) | FUNCTIONS, PORTS, PROTOCOLS, AND SERVICES IN USE | Retained |
| SA-4(10) | USE OF APPROVED PIV PRODUCTS | Tailored out — technology not present (scoping) |
| SA-5 | System Documentation | Retained |
| SA-8 | Security and Privacy Engineering Principles | Retained |
| SA-9 | External System Services | Retained |
| SA-9(2) | IDENTIFICATION OF FUNCTIONS, PORTS, PROTOCOLS, AND SERVICES | Retained |
| SA-10 | Developer Configuration Management | Tailored out — no developer relationship (scoping) |
| SA-11 | Developer Testing and Evaluation | Tailored out — no developer relationship (scoping) |
| SA-15 | Development Process, Standards, and Tools | Tailored out — no developer relationship (scoping) |
| SA-15(3) | CRITICALITY ANALYSIS | Tailored out — no developer relationship (scoping) |
| SA-16 | Developer-Provided Training | Tailored out — no developer relationship (scoping) |
| SA-17 | Developer Security and Privacy Architecture and Design | Tailored out — no developer relationship (scoping) |
| SA-21 | Developer Screening | Tailored out — no developer relationship (scoping) |
| SA-22 | Unsupported System Components | Retained |
| SC-1 | Policy and Procedures | Retained |
| SC-2 | Separation of System and User Functionality | Retained |
| SC-3 | Security Function Isolation | Retained |
| SC-4 | Information in Shared System Resources | Retained |
| SC-5 | Denial-of-Service Protection | Retained |
| SC-7 | Boundary Protection | Retained |
| SC-7(3) | ACCESS POINTS | Retained |
| SC-7(4) | EXTERNAL TELECOMMUNICATIONS SERVICES | Retained |
| SC-7(5) | DENY BY DEFAULT — ALLOW BY EXCEPTION | Retained |
| SC-7(7) | SPLIT TUNNELING FOR REMOTE DEVICES | Tailored out — technology not present (scoping) |
| SC-7(8) | ROUTE TRAFFIC TO AUTHENTICATED PROXY SERVERS | Retained |
| SC-7(18) | FAIL SECURE | Retained |
| SC-7(21) | ISOLATION OF SYSTEM COMPONENTS | Retained |
| SC-8 | Transmission Confidentiality and Integrity | Retained |
| SC-8(1) | CRYPTOGRAPHIC PROTECTION | Retained |
| SC-10 | Network Disconnect | Retained |
| SC-12 | Cryptographic Key Establishment and Management | Retained |
| SC-12(1) | AVAILABILITY | Retained |
| SC-13 | Cryptographic Protection | Retained |
| SC-15 | Collaborative Computing Devices and Applications | Retained |
| SC-17 | Public Key Infrastructure Certificates | Retained |
| SC-18 | Mobile Code | Retained |
| SC-20 | Secure Name/Address Resolution Service (Authoritative Source) | Retained |
| SC-21 | Secure Name/Address Resolution Service (Recursive or Caching Resolver) | Retained |
| SC-22 | Architecture and Provisioning for Name/Address Resolution Service | Retained |
| SC-23 | Session Authenticity | Retained |
| SC-24 | Fail in Known State | Retained |
| SC-28 | Protection of Information at Rest | Retained |
| SC-28(1) | CRYPTOGRAPHIC PROTECTION | Retained |
| SC-39 | Process Isolation | Retained |
| SI-1 | Policy and Procedures | Retained |
| SI-2 | Flaw Remediation | Retained |
| SI-2(2) | AUTOMATED FLAW REMEDIATION STATUS | Retained |
| SI-3 | Malicious Code Protection | Retained |
| SI-4 | System Monitoring | Retained |
| SI-4(2) | AUTOMATED TOOLS AND MECHANISMS FOR REAL-TIME ANALYSIS | Retained |
| SI-4(4) | INBOUND AND OUTBOUND COMMUNICATIONS TRAFFIC | Retained |
| SI-4(5) | SYSTEM-GENERATED ALERTS | Retained |
| SI-4(10) | VISIBILITY OF ENCRYPTED COMMUNICATIONS | Retained |
| SI-4(12) | AUTOMATED ORGANIZATION-GENERATED ALERTS | Retained |
| SI-4(14) | WIRELESS INTRUSION DETECTION | Tailored out — technology not present (scoping) |
| SI-4(20) | PRIVILEGED USERS | Retained |
| SI-4(22) | UNAUTHORIZED NETWORK SERVICES | Retained |
| SI-5 | Security Alerts, Advisories, and Directives | Retained |
| SI-5(1) | AUTOMATED ALERTS AND ADVISORIES | Retained |
| SI-6 | Security and Privacy Function Verification | Retained |
| SI-7 | Software, Firmware, and Information Integrity | Retained |
| SI-7(1) | INTEGRITY CHECKS | Retained |
| SI-7(2) | AUTOMATED NOTIFICATIONS OF INTEGRITY VIOLATIONS | Retained |
| SI-7(5) | AUTOMATED RESPONSE TO INTEGRITY VIOLATIONS | Retained |
| SI-7(7) | INTEGRATION OF DETECTION AND RESPONSE | Retained |
| SI-7(15) | CODE AUTHENTICATION | Retained |
| SI-8 | Spam Protection | Tailored out — technology not present (scoping) |
| SI-8(2) | AUTOMATIC UPDATES | Tailored out — technology not present (scoping) |
| SI-10 | Information Input Validation | Retained |
| SI-11 | Error Handling | Retained |
| SI-12 | Information Management and Retention | Retained |
| SI-16 | Memory Protection | Retained |
| SR-1 | Policy and Procedures | Retained |
| SR-2 | Supply Chain Risk Management Plan | Retained |
| SR-2(1) | ESTABLISH SCRM TEAM | Tailored out — single operator (scoping) |
| SR-3 | Supply Chain Controls and Processes | Retained |
| SR-5 | Acquisition Strategies, Tools, and Methods | Retained |
| SR-6 | Supplier Assessments and Reviews | Retained |
| SR-8 | Notification Agreements | Tailored out — no supply-chain notification agreement exists (scoping) |
| SR-9 | Tamper Resistance and Detection | Retained |
| SR-9(1) | MULTIPLE STAGES OF SYSTEM DEVELOPMENT LIFE CYCLE | Retained |
| SR-10 | Inspection of Systems or Components | Retained |
| SR-11 | Component Authenticity | Retained |
| SR-11(1) | ANTI-COUNTERFEIT TRAINING | Tailored out — single operator (scoping) |
| SR-11(2) | CONFIGURATION CONTROL FOR COMPONENT SERVICE AND REPAIR | Retained |
| SR-12 | Component Disposal | Retained |

</details>

### 10.3 Implementation and assessment status

Nine of the controls named by Findings 1–9 (AC-3, AC-7, CA-3, CM-7, SA-9, SA-22, SC-7, SI-2, SI-3) have been assessed; results are in `security-assessment-report.md`. AC-14 (Findings 13 and 14), IA-5(13) (Finding 7), and the remaining controls of the tailored baseline are not yet assessed. The records below are implementation records; the time-synchronization record also holds the P-19 re-test result (`poam.md` §1). None is a control assessment result.

**AC-14 (Permitted Actions without Identification or Authentication)** (`poam.md` P-02 task 2). Without identification or authentication, the Samba DC permits name resolution, the directory's connectionless lookup, and the start of the Kerberos exchange. No other action is to be permitted. Rationale: a domain member uses these to find the domain controller and to begin a logon, before it holds any credential. Microsoft describes the first two: *"Clients query DNS for the appropriate SRV records and then ping those servers by using UDP-based LDAP pings"* ([Locating domain controllers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/dc-locator), checked October 12, 2026). The Kerberos specification describes the third: the Authentication Service exchange *"is initiated by a client when it wishes to obtain authentication credentials for a given server but currently holds no credentials"* (RFC 4120 §3.1, checked October 12, 2026). Exceptions, found by the P-02 re-test on October 12, 2026 (assessment report §13.1) and carried by Finding 14 (`poam.md` P-29): the Samba DC accepts an anonymous file-sharing session, although the share listing and the account listing over file sharing are refused on it; and an anonymous account listing over the network RPC transport (`ncacn_ip_tcp`) returns all 8 domain user accounts.

**IA-5(13) (Expiration of Cached Authenticators)** (`poam.md` P-05). Cached logons are turned off on Ubuntu Server (`winbind offline logon = no`); with the Samba DC's directory service stopped, a domain logon on Ubuntu Server failed (assessment report §13.2). IA-5(13)'s time period is not defined (§10.2).

**Time synchronization** (`poam.md` P-19). Ubuntu Server's time service, chrony, takes time only from the Samba DC, and VMware Tools periodic time synchronization is off; the Samba DC serves time to Ubuntu Server only and takes its own from a public Canonical time server. The re-test passed on October 12, 2026 (system owner's determination): chrony on Ubuntu Server showed the Samba DC as its selected source at 21:15 and 21:40 UTC, and reported synchronized (`Leap status     : Normal`) at 21:40 ([evidence appendix §16](evidence-appendix.md#16-time-synchronization-on-ubuntu-server)). The matching control is SC-45(1) (Synchronization with Authoritative Time Source), which is in no SP 800-53B baseline and is not added; AU-8 (Time Stamps) stays in the tailored baseline, not yet assessed.

---

## 11. Findings

Deficiencies in the system. Findings 1–9 were identified while describing and categorizing it; Findings 10–13 during control assessment; Finding 14 during a re-test (assessment report §13.1). Each finding's candidate controls are carried into the plan of action and milestones; all but AC-14 and IA-5(13) were assessed (§10.3).

| # | Finding | Status | Candidate controls |
|---|---|---|---|
| 1 | Wazuh services on Ubuntu Server bound to all interfaces; their unreachability rests entirely on the host firewall | Open | CM-7, SC-7 |
| 2 | Samba DC has no host firewall; every directory service is reachable from the home network | Closed — host firewall enabled (P-01), October 12, 2026 | SC-7, CM-7, AC-3 |
| 3 | Services outside the approved inbound set answer on the Windows client from the home network: seven TCP ports besides SSH are reachable through enabled firewall allow rules, despite a default-deny inbound policy | Closed — Windows client retired (P-17), October 10, 2026 | CM-7, SC-7 |
| 4 | Antivirus signatures out of date: every update attempt since early August has failed, most often on name resolution (Finding 10; [evidence appendix §4](evidence-appendix.md#4-windows-client-antivirus-update-failures-by-error-code)) | Closed — Windows client retired (P-17), October 10, 2026 | SI-3 |
| 5 | Files derived from packet captures carry world-readable permissions, while the captures themselves are owner-only; other accounts are currently blocked only by the home folder's permissions ([evidence appendix §7](evidence-appendix.md#7-exercise-file-permissions-and-the-unprivileged-read)) | Open | AC-3 |
| 6 | Withdrawn — not a system deficiency | — | — |
| 7 | Cached domain logons enabled; while the domain connection is flagged offline, domain logons may be validated against the local cache without reaching the domain lockout counter (not tested; settings: [evidence appendix §10](evidence-appendix.md#10-cached-logon-settings-on-ubuntu-server)) | Closed — cached logons turned off (P-05), October 12, 2026 | AC-7; IA-5(13) (in no SP 800-53B baseline; added, §10.2) |
| 8 | Windows client operating system past end of support, with no cumulative update installed since May 2023 ([evidence appendix §2](evidence-appendix.md#2-windows-client-model-firmware-date-and-hotfix-list)) | Closed — Windows client retired (P-17), October 10, 2026 | SA-22, SI-2 |
| 9 | External remote-management agent able to deploy software to a domain member, with no agreement in place ([evidence appendix §5](evidence-appendix.md#5-remote-management-agent-on-the-windows-client)) | Open — Windows client retired (P-17), retirement re-test passed October 10, 2026; closes when the Action1 account closure (P-06) is confirmed | CA-3, SA-9, CM-7 |
| 10 | The Windows client's internet isolation is not in effect: a manually configured default route leaves an open path to the internet while name resolution is disabled, so security updates cannot be retrieved. An earlier disconnect was verified only within its session and did not persist ([evidence appendix §13](evidence-appendix.md#13-the-august-7-disconnect-and-the-september-25-default-route)) | Closed — Windows client retired (P-17), October 10, 2026 | SC-7, SI-3 |
| 11 | An application Microsoft classifies as adware is installed and running on the Windows client. Malicious code protection has not detected it, and protection against potentially unwanted applications is off. It was installed on July 22, 2026: a paid Bing search ad led to a third-party download site; eight seconds later an ad-tagged PC App Store page opened, and the installer it offered was run four times. A remote-access tool (AnyDesk) ran from the store's download folder and left four inbound firewall allow rules; about twelve minutes later, AnyDesk was installed as a service, which left four more. The store's download manager records one completed download of AnyDesk from AnyDesk's official download address, with the same install path as the service. All eight inbound AnyDesk allow rules remain enabled; AnyDesk's program file is absent from its install path (evidence appendix [§11](evidence-appendix.md#11-adware-delivery-the-browser-record), [§12](evidence-appendix.md#12-adware-delivery-installer-runs-service-installs-and-firewall-rules), [§6](evidence-appendix.md#6-anydesk-download-record-remaining-firewall-rules-and-the-store-folder)) | Closed — Windows client retired (P-17), October 10, 2026 | CM-7, SI-3 |
| 12 | Neither server has malicious code protection meeting the approved values: the Samba DC has none, and Ubuntu Server has only a scheduled rootkit check that raises alerts but does not scan in real time, quarantine, or remove malicious code | Open | SI-3 |
| 13 | The Samba DC lists its file shares and every domain user account to anonymous requesters on the lab segment; the anonymous-access restriction is left at its default ([evidence appendix §8](evidence-appendix.md#8-anonymous-account-and-share-listing-from-the-lab-segment)) | Closed — anonymous share and account listings over file sharing refused (P-02), October 12, 2026; the remaining anonymous access is Finding 14 | AC-3, AC-14 |
| 14 | After P-02, the Samba DC still answers anonymous requests on the lab segment: it accepts an anonymous file-sharing session, although the share listing and the account listing over file sharing are refused on it; and an anonymous account listing over the network RPC transport (`ncacn_ip_tcp`) returns all 8 domain user accounts (assessment report §13.1) | Open | AC-3, AC-14 |

---

## 12. Referenced Artifacts

| Artifact | Location |
|---|---|
| Security assessment plan | `security-assessment-plan.md` |
| Security assessment report | `security-assessment-report.md` |
| Plan of action and milestones | `poam.md` |
| Evidence appendix | `evidence-appendix.md` |
| Earlier owner decision not to extend SIEM monitoring to the Windows client | [`iam-ad-lab`](https://github.com/JSON-MSON/iam-ad-lab), Risk response (predates this plan; not an Authorizing Official risk acceptance) |
| Incident records | [`incident-reports`](https://github.com/JSON-MSON/incident-reports) |
| Supporting lab evidence | [`iam-ad-lab`](https://github.com/JSON-MSON/iam-ad-lab), [`packet-analysis-lab`](https://github.com/JSON-MSON/packet-analysis-lab), [`siem-home-lab`](https://github.com/JSON-MSON/siem-home-lab), [`linux-audit-lab`](https://github.com/JSON-MSON/linux-audit-lab), [`dashboards`](https://github.com/JSON-MSON/dashboards) |

---

## 13. Review and Change Records

### 13.1 Review record

| Date | Reviewer | Notes |
|---|---|---|
| 2026-09-27 | System owner | Assessment of nine of the controls named by Findings 1–9 completed, with read-only follow-up checks on September 28 — 174 results of 73 determination statements, each rated per component; 73 satisfied, 101 other than satisfied (totals as updated September 28, 2026). |
| 2026-09-28 | System owner | Whole-plan review. Findings 11–13 added as risk factors (§2); policy statement confirmed and clarified (§3); internet exchange row reworded to what the evidence shows (§8). |
| 2026-10-10 | System owner | Security categorization reviewed after the Windows client's retirement (SP 800-60 Vol 1 Rev 1: categorization should be revisited *"when significant change occurs to the system"*). No information type was held only on the Windows client, each rating's basis (§6.1) still holds, and identity and authentication data (type 1), which sets HIGH on all three objectives, stays on the Samba DC. Ratings unchanged; the system stays HIGH for confidentiality, integrity and availability. |
| 2026-10-10 | System owner | Disposal review for the Windows client (SP 800-37 Rev 2, Task M-7). Notification: none needed; the system owner is the only user. Control inheritance: reviewed against this plan; no control is inherited from the client or provided by it to another component (no common controls exist, §10.2). Dispositions and values that depended on the client's presence were also updated: the wireless controls (§10.2) and the SSH and directory-service inbound values (assessment plan §4). Security posture reports: not produced; no Authorizing Official is designated (§5) and no continuous monitoring strategy exists. |

### 13.2 Change record

| Date | Sections | Description |
|---|---|---|
| 2026-09-24 | All | Initial issue: system description, security categorization (HIGH), authorization boundary, information exchanges, component inventory, control selection (370) and tailoring (81 tailored out, IA-5(13) added, 290), Findings 1–9. |
| 2026-09-27 | Header, §2, §7, §8, §9, §10.3, §11, §13 (new) | Control assessment. Findings 10–13 recorded; Finding 4 revised (most frequent failure: name resolution, Finding 10); Windows-client internet isolation described as intended but not in effect; server firmware noted as supplied by the MacBook Air; §11 introduction reworded; §13 added. |
| 2026-09-28 | Header, §2, §3, §4, §5, §7, §8, §9, §10.1, §10.2, §10.3, §11, §12, §13 | Corrections from a review. Control assessor recorded as the system owner; Findings 3, 5, 7, and 10 revised to match the assessment evidence; the remote-management service named (Action1); Kali Linux's test traffic to the Samba DC recorded; two tailoring rationales reworded (dispositions and counts unchanged); redaction statement and citations made exact; referenced artifacts relabeled; the availability risk restated as submitted for acceptance; isolation wording made verbatim; the assessed-controls wording made exact, with AC-14 and IA-5(13) noted as not assessed; adware added to the inventory; cached-logon and file-mode wording aligned to Findings 7 and 5; assessment totals updated. |
| 2026-09-28 | §2, §3, §8, §13 | Whole-plan review by the system owner. §2 adds Findings 11–13 (adware on the Windows client, server malicious code protection, anonymous directory access) to the factors presenting additional risk; §3 states that configured technical settings are not issued policy; §8 internet row states that outbound paths exist and that inbound reachability was not examined; §13.1 review row added and the September 27 row's totals dated. |
| 2026-09-28 | §12 | Plan of action and milestones issued; reference updated. |
| 2026-09-29 | §2, §7, §8, §10.2, §13 | Windows client design change recorded by the system owner: internet isolation is no longer intended; the client keeps outbound internet access until it is retired after remediation (Finding 10 stays open until the P-07 re-test). §10.2 technology-not-present rationale reworded: AC-22 remains tailored out because the system hosts no publicly accessible content, and publishing lab evidence to external repositories falls under PL-4(1) (retained; rules of behavior not yet issued). Dispositions and counts unchanged. |
| 2026-10-01 | §2, §8, §9, §11, §13 | Windows client retirement decided by the system owner: the client is to be retired early, without remediation, and stays in the boundary and the component inventory, powered off, until its disposal is verified (`poam.md` P-17). §2 and §8 no longer state that it is retired after remediation; §2 and §9 record its status; Finding 11 adds the delivery chain shown by the October 1, 2026 evidence collection (the finding stays open; the assessment report is unchanged). |
| 2026-10-02 | §6, §10.1, §10.2, §11, §12, §13; assessment report §1, §6.1, §7.3, §9.2 | Corrections from the final review before publication. Finding 11's delivery chain worded to the sequences the records show: the search ad led to the download site, and the PC App Store page opened eight seconds later; AnyDesk ran from the store's download folder and was installed as a service about twelve minutes later, and the download manager's record is described without placing its download in that order. §6 cites MITRE ATT&CK T1558.001 for the identity information type's basis. §10.1 uses the approved Finding 5 wording ("broader than the captures'"). §11's introduction states that AC-14 and IA-5(13) were not assessed. §12 names the iam-ad-lab section as Risk response, its new heading. §10.2's Awareness and Training basis states that contingency and incident response training (CP-3, IR-2) is retained for the operator; dispositions and counts are unchanged. Assessment report wording corrected, with no assessment result changed (SP 800-37 Rev 2, Task A-5): §1 states that the scans test the boundary from outside it; §6.1 cites both Microsoft Extended Security Updates pages and the Defender schedule page as checked October 2, 2026; §7.3 adds that the manager's alert archives hold rootcheck alerts; §9.2 states that P-05 removes the cached-logon path instead of re-testing it. |
| 2026-10-03 | §2, §3, §8, §9, §10.2, §10.3, §11, §12, §13; assessment report At a glance, §1, §3.2, §4.1, §5.1, §5.3, §6, §6.1, §6.2, §8.1, §8.2, §8.3, §9.1, §9.2, §9.3 | Evidence appendix added (`evidence-appendix.md`): the command output and log records behind statements in this plan, the assessment report and the plan of action and milestones, linked from those statements. §2 names the MacBook Air's operating system (macOS). Assessment report §9.2 states that Ubuntu Server's winbind offline flag was observed set while the Samba DC was reachable (September 23 and October 2, 2026), instead of describing the flag as stale and citing September 26. Wording in this plan and the assessment report edited for brevity, grammar and readability. No disposition, finding or assessment result changed (SP 800-37 Rev 2, Task A-5). |
| 2026-10-04 | Header, §2, §4, §6.1, §6.2, §7, §8, §9, §10.2, §11, §13.2; assessment plan §1, §3, §4, §5, §7; assessment report At a glance, §1–§10; evidence appendix How the records were produced, §1, §3, §4, §6, §7–§10, §12, §13, §15 | Redaction scope revised by the system owner. Components are named by product — Ubuntu Server (SIEM), Samba DC, Windows client, Kali Linux (attack simulation) and MacBook Air (macOS; hypervisor and administration host) — with the role given at first mention; host names in quoted output are shown as recorded; quoted values that were descriptive placeholders use the same replacement values as the other documents; the redaction statement reads "identifying values are replaced or redacted". Earlier change-record rows use the new names. Publication editions are cited in full (SP 800-60 Vol 1 Rev 1 and Vol 2 Rev 1; ATT&CK v19.2). Evidence appendix §6 places the store folder's creation time against the §12 records. Wording in this plan, the assessment plan, the assessment report, the plan of action and milestones and the evidence appendix edited for brevity and readability. No finding, disposition, count or assessment result changed. |
| 2026-10-10 | §13.1, §13.2 | Security categorization reviewed after the Windows client's retirement and recorded in §13.1. No rating or category changed. |
| 2026-10-10 | §2, §7, §8, §9, §10.1, §11, §13.1, §13.2; assessment plan §1, §4, §7; evidence appendix §14, §15; README | Windows client removed from the boundary, inventory and plans (`poam.md` P-17 task 3), after P-17 tasks 1 and 2 were completed and ahead of the retirement re-test: computer account deleted October 7, 2026; internal drive sanitized by Purge, verified, validated and certified October 8, 2026. §2 drops the client from the implemented technology and the risk factors, and states that the operator administers both components over SSH from the MacBook Air (the evidence appendix §15 link is removed); §7 states two components, drops the client from the boundary table and the client and the remote-management console from the diagram, records that the Samba DC's home-network adapter is bridged to the MacBook Air's Wi-Fi, and names the Samba DC as the only component connected to the excluded home network; §8 drops the Action1 exchange, stating that no remote-management service is connected and that the account closure is tracked in `poam.md` P-06, drops the client from the home-network and internet rows (the internet row's consideration now cites Finding 2 only), and names both components in the MacBook Air row; §9 drops the client and its retirement sentence ([evidence appendix §14](evidence-appendix.md#14-boot-camp-on-the-windows-client) keeps the record of its hardware); §10.1 updates the component count and the security-domains evidence; §11 records Findings 3, 4, 8, 9, 10 and 11 as open, Windows client retired, closing when the retirement re-test passes (Finding 9 also on confirmation of the Action1 closure), with each finding's description unchanged. The Task M-7 disposal review is recorded in §13.1. Assessment plan §4: directory services on the Samba DC are approved from the lab segment only (`poam.md` P-01), and the SSH value names the two servers instead of all three components; §1 states that its scope and counts are as assessed in September 2026; §4 notes that the CM-07 row is the value as amended for re-tests; §7 records its approval on October 10, 2026 and keeps, verbatim, the value it replaced. Evidence appendix §14's lead-in now supports the assessment report §6.1 and describes the client in the past tense; §15's no longer cites the system security plan §2. README: two components. |
| 2026-10-10 | §10.2, §13.2 | Re-tailoring after the Windows client's retirement, control by control: AC-18(3), AC-18(4), AC-18(5) and SI-4(14) tailored out — technology not present (scoping); neither remaining component has a wireless device of its own (checked October 10, 2026). AC-18 and AC-18(1) stay retained: the Samba DC's home-network adapter is bridged to the MacBook Air's Wi-Fi. 85 tailored out; 286 in the tailored baseline. Acceptance of the risk from tailored-out controls remains pending Authorizing Official review. |
| 2026-10-10 | §3, §10.2, §13.2 | Parameter values for MP-6 (Media Sanitization) and SR-12 (Component Disposal) assigned for the Windows client's disposal; §3 adds SP 800-88 Rev 2, which the MP-6 value cites. |
| 2026-10-10 | §11, §13.2; assessment report At a glance, §5.3, §6.2, §10, §10.1, §11.1, §12 | Windows client retirement re-test passed (`poam.md` P-17; assessment report §12, recorded beside the original results, which SP 800-37 Rev 2, Task A-5 keeps unchanged). Findings 3, 4, 8, 10 and 11 closed, each finding's description unchanged; Finding 9 stays open with `poam.md` P-06. Assessment report: §12 records the re-test and At a glance notes it. §5.3 and §6.2 now cite the assessment plan §4 values as assessed (plan §7 quotes the inbound value the assessment applied); §10, §10.1 and §11.1 now cite this plan's §8 records as assessed, since its §8 changed earlier on October 10, 2026; §10.1's description of those records is in the past tense. No original assessment result changed. |
| 2026-10-12 | At a glance (replacing the header), §2, §4, §5, §10.1, §10.2, §10.3, §11, §13.1, §13.2; assessment plan At a glance, §1, §5; assessment report At a glance, §1, §6.1, §6.2, §7.2; evidence appendix §1–§4, §6, §12, §14; README | Wording corrected against the sources. No finding status, disposition, count or assessment result changed. The plan opens with an At a glance: the description and the plan status as before, the two components, the security category, the control counts and the findings by status; §2 no longer repeats Ubuntu Server's role, now given at its first mention. §4 records the Select step as partly complete: controls selected (Task S-1) and tailored (Task S-2) except organization-defined parameter values, most of which are assigned at implementation; Tasks S-3 to S-5 not done. §5 states that the decisions within each plan, such as the authorization boundary and the level of assessor independence, await Authorizing Official review with that plan; §5, §10.1 and §10.2 say that one person holds every assigned role, since the Authorizing Official role is not held. The plan's opening, §10.3, §13.1 and the assessment plan's At a glance and §1 name the assessed controls as nine of the controls named by the findings (Finding 7 also names IA-5(13), not assessed). §10.2: the SR-8 reason states that no supply-chain notification agreement exists with any supplier, instead of that none can be established, and the scripts clause is removed (family table and SR-8 row aligned); the MP-6 value's grammar and the SI-4(14) sentence are corrected. §11: Finding 9's status no longer waits on the retirement re-test, which passed on October 10, 2026; Finding 11 states that AnyDesk's program file is absent from its install path, and evidence appendix §6 that it was, as the record shows. §13.1 and the At a glance of the assessment report and the README give 174 as results of 73 determination statements, each rated per component. §13.2: the first 2026-09-28 row's corrections came from a review, not an independent one (assessment plan §2). Assessment plan §1 states that IA-5(13) was not implemented at the time of the assessment; §5's CA-3 row refers to the §8 exchange records as assessed (five exchanges). Assessment report §1 states that evidence was gathered September 17–28, names the reads made before September 24, and adds the September 28 domain-membership read; §6.1 dates two evidence appendix citations, gives the firmware release date as October 7, 2023, links the Boot Camp record (evidence appendix §14) and notes that evidence appendix §6 shows the September 25 firewall rows as listed on October 1; §6.2 says it is the signature updates behind Finding 4 that fail on name resolution; §7.2 describes the component inventory as assessed. Evidence appendix: §1 and §3 name every statement they support; §2 gives the conversion of the firmware date as Windows displayed it; §4 marks the nine events not shown; §6's introduction is in the past tense and its excerpt adds the remote desktop rule's row from the enabled-rule listing; §12 cites Microsoft's archived page for event 2006; §14 cites the autostart entries' lines in full. README: the Authorizing Official, evidence-source, re-test and results wording matches these documents. |
| 2026-10-12 | §2, §8, §9, §10.2, §10.3, §11, §13.2; assessment plan §4, §7; assessment report At a glance, §13 (new); evidence appendix How the records were produced, §16 (new) | Remediation re-tests of October 12, 2026 (`poam.md` P-01, P-02, P-05, P-19). Findings 2, 7 and 13 closed, each finding's description unchanged; Finding 14 added (the Samba DC still accepts an anonymous file-sharing session and lists all 8 domain user accounts over the network RPC transport; `poam.md` P-29); §11's introduction names the re-test that found it. §2 no longer lists the Samba DC's lack of a host firewall or Ubuntu Server's cached logons as risk factors, and replaces Finding 13 with Finding 14. §8 records the Samba DC's firewall in the home-network, internet and Kali Linux rows, and its time server in the internet row. §9 adds chrony on both components and drops "(inactive)" from the Samba DC's ufw. §10.2's supplementation note records Finding 7 as closed. §10.3 names Finding 14 beside AC-14, states that the records that follow are implementation records (the time-synchronization record also holding the P-19 re-test result), and adds three: AC-14 (the actions permitted without identification or authentication, their rationale, and the two exceptions under Finding 14), IA-5(13) (cached logons turned off; its time period not defined), and time synchronization (the P-19 result, naming SC-45(1), which is in no SP 800-53B baseline and is not added; AU-8 stays in the baseline). No control disposition or baseline count changed. Assessment plan §4: the CM-07_ODP[02]–[06] inbound value adds the time service on the Samba DC, from Ubuntu Server only, approved by the system owner on October 12, 2026; §7 records the approval and keeps the October 10, 2026 value verbatim. Assessment report: §13 records the re-tests of P-01, P-02 and P-05, the scan of the four other UDP ports on October 13, 2026 (UTC), and the October 12 attempt at the Finding 7 test, beside the original results (SP 800-37 Rev 2, Task A-5); At a glance notes them. No original assessment result changed. Evidence appendix §16 holds the P-19 records and the 21:40 re-check; How the records were produced describes the recorded sessions. |
