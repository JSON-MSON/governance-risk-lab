# Security Assessment Plan — Cybersecurity Home Lab (HL-01)

> **At a glance.** A targeted assessment of the nine controls named by the findings in the [system security plan](system-security-plan.md), using NIST SP 800-53A Rev 5 (Release 5.2.0) procedures, which are unchanged from the base edition for these controls. Each determination statement is rated *satisfied* or *other than satisfied*. Controls fixed during the assessment are re-tested before the report is final.

---

## 1. Purpose and Scope

**Type: partial assessment.** SP 800-53A §3.2.1 provides for *"a partial assessment of the controls in a system"*, where *"The determination of the controls to be assessed depends on the purpose of the assessment."* The purpose here is to test the deficiencies identified while describing and categorizing the system, against the controls those findings name.

| Control | Name | Findings | Components |
|---|---|---|---|
| AC-3 | Access Enforcement | 2, 5 | Ubuntu Server (SIEM); Samba DC |
| AC-7 | Unsuccessful Logon Attempts | 7 | Samba DC; Ubuntu Server |
| CA-3 | Information Exchange | 9 | All information exchanges (system security plan §8) |
| CM-7 | Least Functionality | 1, 2, 3, 9 | All three components |
| SA-9 | External System Services | 9 | Windows client; remote-management service |
| SA-22 | Unsupported System Components | 8 | All three components |
| SC-7 | Boundary Protection | 1, 2, 3 | All three components |
| SI-2 | Flaw Remediation | 8 | All three components |
| SI-3 | Malicious Code Protection | 4 | All three components |

**Out of scope:** the other 281 controls of the tailored baseline. IA-5(13), added for Finding 7, is not yet implemented and is not assessed: its time period is not defined (system security plan §10.2), and the installed Samba release documents no setting that limits how long cached logon credentials can be used.

---

## 2. Assessor and Independence

The assessor is the system owner. This is a self-assessment: CA-2(1) (Independent Assessors) is tailored out because no independent party exists (system security plan §10.2), and the report states this limitation. Interview methods are not used, since the only person to interview is the assessor.

---

## 3. Method

Each control is assessed with its SP 800-53A Rev 5 (Release 5.2.0) procedure, which is unchanged from the base edition. Assessment methods are **examine** (configuration settings and documentation) and **test** (exercising the mechanism live).

| Attribute | Method | Value | SP 800-53A Appendix C definition |
|---|---|---|---|
| Depth | Examine | Focused | *"Focused examination: Examination that consists of high-level reviews, checks, observations, or inspections and more in-depth studies/analyses of the assessment object …"* |
| Depth | Test | Focused | *"Focused testing: Test methodology that assumes some knowledge of the internal structure and implementation detail of the assessment object."* |
| Coverage | Examine | Comprehensive | *"Comprehensive examination: Examination that uses a sufficiently large sample of assessment objects (by type and number within type) and other specific assessment objects deemed particularly important to achieving the assessment objective …"* |
| Coverage | Test | Comprehensive | *"Comprehensive testing: Testing that uses a sufficiently large sample of assessment objects (by type and number within type) and other specific assessment objects deemed particularly important to achieving the assessment objective …"* |

Applied here as: every component §1 names for a control is examined; controls with a test in §5 are also tested on those components.

**Findings.** Per SP 800-53A §3.3, each determination statement produces *satisfied* or *other than satisfied*. Other than satisfied *"may also indicate that the assessor was unable to obtain sufficient information to make the determination …"*

**Remediation and re-test.** SP 800-53A §3.3: *"Security or privacy controls that are modified, enhanced, or added during this process are reassessed by the assessor prior to the production of the final assessment reports."* Any control fixed during the assessment is re-tested, and the report records both results.

**Evidence.** Command output is gathered live from each component, quoted in the report with identifying values replaced or redacted.

---

## 4. Organization-Defined Parameter Values

SP 800-53A procedures first determine whether each organization-defined parameter is defined. The values below are assigned for this assessment, as the system security plan provides (§10.2).

| Parameter | Value |
|---|---|
| AC-07_ODP[01] — consecutive invalid logon attempts allowed | 5 |
| AC-07_ODP[02] — time period | 15 minutes |
| AC-07_ODP[03] — action when exceeded | Lock the account for a time period |
| AC-07_ODP[04] — lock period | 15 minutes |
| CA-03_ODP[01] — agreement types | Service level agreements or user agreements for external services; an information exchange record in the system security plan for every other exchange |
| CA-03_ODP[02] — organization-defined agreement type | An information exchange record in the system security plan |
| CA-03_ODP[03] — agreement review frequency | Annually |
| CM-07_ODP[01] — mission-essential capabilities | Detection, identity services, and evidence production (system security plan §2) |
| CM-07_ODP[02]–[06] — functions, ports, protocols, software, and services to restrict | Any not required by a mission-essential capability. Required inbound: SSH from the MacBook Air (macOS; hypervisor and administration host) on all three components; the SIEM dashboard on Ubuntu Server; directory services on the Samba DC, from the lab segment and the Windows client only. Remote-management software restricted to approved, documented tools. |
| SA-09_ODP[01] — controls employed by external service providers | The provider's published security commitments |
| SA-09_ODP[02] — monitoring of provider compliance | Annual review of the provider's security documentation |
| SA-22_ODP[01] — alternative support source | Support from external providers |
| SA-22_ODP[02] — support from external providers | Vendor extended security updates |
| SC-07_ODP — separation of publicly accessible components | Logically (the system has no publicly accessible components) |
| SI-02_ODP — time to install security-relevant updates | 30 days from release |
| SI-03_ODP[01] — mechanism type | Signature-based |
| SI-03_ODP[02] — periodic scan frequency | Weekly |
| SI-03_ODP[03] — real-time scanning points | Endpoint |
| SI-03_ODP[04] — response to detection | Quarantine malicious code |
| SI-03_ODP[06] — alert recipient | System owner |

---

## 5. Assessment Procedures

Determination statement identifiers are SP 800-53A Rev 5's.

| Control | Determination statements | Examine | Test |
|---|---|---|---|
| AC-3 | AC-03 | File permissions on exercise evidence files (Ubuntu Server); directory access settings (Samba DC) | Read the evidence files as a non-administrative account; query the directory without credentials |
| AC-7 | ODP[01]–[04]; AC-07a, AC-07b | Domain lockout policy; cached-logon configuration (Ubuntu Server) | Reach the attempt limit against a test account through the Samba DC and through Ubuntu Server; check whether the account locks |
| CA-3 | ODP[01]–[03]; CA-03a, b.[01]–[06], c | Agreements and exchange records for each exchange in system security plan §8 | — |
| CM-7 | ODP[01]–[06]; CM-07a, b.[01]–[05] | Listening services, installed services, and remote-management software on each component, against the required set in §4 | Port scans of each component from the lab segment and from the home network |
| SA-9 | ODP[01]–[02]; SA-09a.[01]–[03], b.[01]–[02], c | Service agreement, oversight roles, and monitoring records for the remote-management service | — |
| SA-22 | ODP[01]–[02]; SA-22a, b | Support status of each operating system and major software component; approvals for continued use | — |
| SC-7 | ODP; SC-07a.[01]–[04], b, c | Firewall configuration and interface placement on each component | Reachability of each component's services from the home network and from the lab segment |
| SI-2 | ODP; SI-02a.[01]–[03], b.[01]–[04], c.[01]–[02], d | Installed updates and pending security updates on each component, against release dates | — |
| SI-3 | ODP[01]–[04], [06]; SI-03a.[01]–[02], b, c.01[01]–[02], c.02[01]–[02], d | Malicious code protection on each component: presence, signature age, scan schedule, response and alert settings | — |

**Sequence.** SP 800-53A §3.2.5 lists sequence as an area for consideration: assessing controls that describe the system early *"may provide a basic understanding of the system …"*. SA-22 and SI-2 establish the component inventory and patch state, so they are assessed first. Order: SA-22 and SI-2 (component inventory and patch state), CM-7 and SC-7 (services and boundary, one scan set serving both), AC-3, AC-7, SI-3, then CA-3 and SA-9 (documentation only).

---

## 6. Schedule

| Activity | Timing |
|---|---|
| Evidence gathering and testing, all nine controls | First day of the assessment |
| Remediation of selected findings and re-test | Second day |
| Security assessment report and plan of action and milestones | Second day |

---

## 7. Approval

SP 800-53A §3.2.6 calls for the plan to be *"reviewed and approved by appropriate organizational officials …"* Parameter values (§4) were approved by the system owner on September 24, 2026. The plan as a whole was reviewed and approved by the system owner on September 28, 2026, after the assessment was performed. Authorizing Official review is pending (system security plan §5).
