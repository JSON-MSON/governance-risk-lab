# governance-risk-lab

The NIST Risk Management Framework (SP 800-37 Rev 2) applied to a working security lab, the Cybersecurity Home Lab (HL-01). The lab has three components: Ubuntu Server (SIEM), running Wazuh; Samba DC, an Active Directory domain controller; and the Windows client, a domain member. Identifying values are replaced or redacted.

## At a glance

Figures are from the September 2026 assessment cycle.

| Step | Result |
|---|---|
| **Categorize** | HIGH for confidentiality, integrity, and availability (FIPS 199; SP 800-60 Vol 1 Rev 1) |
| **Select and tailor** | 370 controls in the SP 800-53B (Release 5.2.0) HIGH baseline; 81 tailored out with recorded rationale, 1 added; 290 in the tailored baseline |
| **Assess** | 9 controls assessed with SP 800-53A Rev 5 (Release 5.2.0) procedures: **174 determination statements, 73 satisfied, 101 other than satisfied** |
| **Plan remediation** | 28 plan of action and milestones entries covering all 101 other-than-satisfied results and the 12 open findings; current status, target date and risk acceptance proposals in [`poam.md`](poam.md) |

## Documents

| Document | What it holds |
|---|---|
| [`system-security-plan.md`](system-security-plan.md) | System description, authorization boundary, security categorization, control selection and tailoring (every control's disposition), findings |
| [`security-assessment-plan.md`](security-assessment-plan.md) | Scope, method, organization-defined parameter values, and procedures for the nine assessed controls |
| [`security-assessment-report.md`](security-assessment-report.md) | Evidence and a determination for each statement, by component |
| [`poam.md`](poam.md) | The hardening plan: for each weakness, the fix, how it is re-tested, and when; every other-than-satisfied statement traced to an entry |
| [`evidence-appendix.md`](evidence-appendix.md) | Command output and log records behind statements in the system security plan, the assessment report and the plan of action and milestones, each with its source and date |

## How it was done

- **Evidence first.** Every assessment result rests on command output from the lab, on the system's own records (the assessment plan's parameter values and the two documentation-only controls), or on the vendors' published support dates.
- **Self-assessment, stated plainly.** The system owner is the assessor. No independent assessor or Authorizing Official exists, so every Authorizing Official decision is recorded as pending review or not issued, never as made.
- **Current publications only.** Every NIST publication cited was checked against its live publication page before use.
- **A loop, not a snapshot.** Each fix in `poam.md` is to be re-tested, with the result added to the assessment report (or, for the three entries that trace to no assessed statement, to the system security plan) and a change record added to the system security plan.
