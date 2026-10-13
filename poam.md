# Plan of Action and Milestones — Cybersecurity Home Lab (HL-01)

> **At a glance.** This is the lab's hardening plan. The [security assessment](security-assessment-report.md) of nine controls produced 174 results of 73 determination statements, each rated per component: 73 satisfied and 101 other than satisfied. Every other-than-satisfied result maps to at least one of the 29 entries below (traceability, §6). The entries cover the findings in the [system security plan](system-security-plan.md) (§11 gives each one's status), the deficiencies that carry no finding, and three items the system owner raised in review rather than from a determination statement. Each entry names the fix and how it will be re-tested; an entry superseded by another closes with the superseding entry's re-test. The Windows client has been retired without remediation, and its retirement was verified on October 10, 2026: P-17 and the six entries it superseded are closed. The system owner proposes retirement as risk avoidance, pending Authorizing Official review. On October 12, 2026, P-01, P-02 (for the share and account listings over file sharing), P-05 and P-19 passed their re-tests and closed; the P-02 re-test raised Finding 14, carried by P-29. On October 13, 2026, P-29 passed its re-test from Kali Linux; it stays open for the account listing over the network RPC transport, still reachable from Ubuntu Server; task 4 applies a Samba setting if a release adds one. Three residual gaps are proposed for risk acceptance, pending Authorizing Official review. The target date for all open entries is October 18, 2026.

---

## 1. Scope and Method

**Task.** SP 800-37 Rev 2, Task A-6: *"Prepare the plan of action and milestones based on the findings and recommendations of the assessment reports."* Its discussion lists what each plan contains: *"tasks to be accomplished with a recommendation for completion before or after system authorization; resources required to accomplish the tasks; milestones established to meet the tasks; and the scheduled completion dates for the milestones and tasks."*

**Sources.** The [security assessment report](security-assessment-report.md) (SP 800-53A Rev 5 (Release 5.2.0) procedures) and the findings in the [system security plan](system-security-plan.md) §11. P-19, P-27 and P-28 come from the system owner's review rather than from a determination statement. Their source line says so.

**Authorizing Official.** None is designated (system security plan §5). Task A-6 provides that *"Plan of action and milestones entries are not necessary when deficiencies are accepted by the authorizing official as residual risk."* No deficiency has been accepted, so every other-than-satisfied result has an entry. Where a gap is expected to remain after remediation, the entry proposes it for acceptance, recorded as *pending Authorizing Official review*. No organizational risk tolerance has been stated yet (SP 800-37 Rev 2, Task P-2), so these proposals cannot be decided until one is: SP 800-39 provides that *"A decision to accept risk must be consistent with the stated organizational tolerance for risk."*

**Prioritization.** Task A-6: *"A risk assessment guides the prioritization process for items included in the plan of action and milestones."* No SP 800-30 Rev 1 risk assessment has been developed yet. SP 800-53A Rev 5 (Release 5.2.0), §3.3, footnote 46, provides that *"organizations may decide without prejudice that waiting for the risk assessment to prioritize remediation efforts is the better course of action."* Entries are therefore **not ranked by risk**. Scheduled dates are a work schedule. Where one entry depends on another, the entry says so.

**Common to every entry.**
- *Resources:* the system owner's time; no cost.
- *Recommended completion:* before authorization.
- *Status at issue:* open unless the entry states otherwise; status and date changes are recorded in the change record (§7).
- *Re-test:* each fix is re-tested with the method the entry names. The reassessment result is added to the assessment report and the original result is kept, as SP 800-37 Rev 2 Task A-5 provides: *"The assessors update the assessment reports with the findings from the reassessment, but do not change the original assessment results."* For P-19, P-27 and P-28, which trace to no assessed statement, the result is recorded in the system security plan. Each re-test is also recorded in the system security plan's change record.

**Schedule.** Target date for all open entries: **October 18, 2026**. An entry closes when its re-test passes, or, if superseded, when the superseding entry's re-test passes; a change to the target date is recorded in the change record (§7).

---

## 2. Summary

| # | Weakness | Component | Controls | Source |
|---|---|---|---|---|
| P-01 | No host firewall on the Samba DC | Samba DC | SC-7, CM-7, AC-3 | Finding 2 |
| P-02 | Samba DC answers anonymous requests | Samba DC | AC-3, AC-14 | Finding 13 |
| P-03 | Windows client answers on services outside the approved set | Windows client | CM-7, SC-7 | Finding 3 |
| P-04 | Exercise files readable more broadly than their sources | Ubuntu Server (SIEM) | AC-3 | Finding 5 |
| P-05 | Cached domain logons leave a lockout path untested | Ubuntu Server | AC-7, IA-5(13) | Finding 7 |
| P-06 | External remote-management agent with no agreement | Windows client | CA-3, SA-9, CM-7 | Finding 9 |
| P-07 | Windows client's internet isolation not in effect; design since changed | Windows client | SC-7, SI-3 | Finding 10 |
| P-08 | Adware installed and running | Windows client | CM-7, SI-3 | Finding 11 |
| P-09 | Ubuntu Server SSH rule broader than approved; allowed traffic not logged | Ubuntu Server | CM-7, SC-7 | Report §5.1, §5.3, §5.4 |
| P-10 | Services beyond the mission run | Both servers | CM-7 | Report §5.1, §5.2, §5.3 |
| P-29 | Samba DC accepts an anonymous file-sharing session and lists accounts over the network RPC transport | Samba DC | AC-3, AC-14 | Finding 14 |
| P-11 | No agent enrolled in the SIEM; Samba DC flaws not reported | Samba DC; Ubuntu Server | SI-2, SC-7, SI-3 | Report §4.2, §5.3, §5.4, §7.3 |
| P-12 | Wazuh services listen on every interface | Ubuntu Server | CM-7, SC-7 | Finding 1 |
| P-13 | Ubuntu Server security updates overdue; vulnerability data not updating | Ubuntu Server | SI-2 | Report §3 |
| P-14 | Updates not tested before installation; general updates not installed | Both servers | SI-2 | Report §3.2, §4.2 |
| P-15 | Servers lack malicious code protection meeting the approved values | Both servers | SI-3 | Finding 12 |
| P-16 | Windows antivirus signatures out of date | Windows client | SI-3 | Finding 4 |
| P-17 | Windows client operating system past end of support | Windows client | SA-22, SI-2 | Finding 8 |
| P-18 | Windows detections not set to quarantine | Windows client | SI-3 | Report §6.2 |
| P-19 | Ubuntu Server clock not synchronized | Ubuntu Server | AU-8; SC-45(1) (in no SP 800-53B baseline) | System owner review |
| P-20 | No configuration management plan | Both servers | SI-2, CM-9 | Report §3.2, §4.2 |
| P-21 | No software-restriction policy or list | Both servers | CM-7 | Report §5.3 |
| P-22 | No security architecture document | Both servers | SC-7, PL-8 | Report §5.4 |
| P-23 | No access control policy or list of approved authorizations | Both servers | AC-3, AC-1 | Report §8 |
| P-24 | No procedure for false positives | Both servers | SI-3 | Report §7.3 |
| P-25 | Information exchanges have no agreements | All exchanges | CA-3 | Report §10 |
| P-26 | Windows client has no flaw reporting or detection alert path | Windows client | SI-2, SI-3, SC-7 | Report §6.2 |
| P-27 | Inbound reachability from the internet not examined | Home gateway | SC-7 | System owner review |
| P-28 | Ubuntu Server isolation has no recorded risk acceptance | Ubuntu Server | SI-2 | System owner review |

For entries from a finding, the Controls column lists the finding's candidate controls (system security plan §11); §6 maps each other-than-satisfied result to its entries. Entries are listed in section order (§3–§5), so P-29 follows P-10. P-03, P-07, P-08, P-16, P-18 and P-26 are superseded by P-17, which retires the Windows client; each is kept below under its status line.

---

## 3. Entries — Configuration Changes

### P-01 — No host firewall on the Samba DC (Finding 2)

| | |
|---|---|
| Status | Closed October 12, 2026: re-test passed (report §13.1). |
| Statements | CM-07b.[02]–[03]; SC-07a.[01], [03]; SC-07a.[02], [04]; SC-07c — Samba DC |
| Evidence | The host firewall was inactive and the packet filter accepted everything; every directory service and SSH answered from the lab segment and from the home network (report §5.2). |
| Tasks | 1. Add the SSH allow rule for the home-network address of the MacBook Air (macOS; hypervisor and administration host) before enabling the firewall; the `ufw` manual warns that enabling it may drop existing connections such as SSH. 2. Default deny inbound. 3. Allow the directory service ports the host listens on (TCP 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269 and the dynamic RPC range 49152–65535; UDP 53, 88, 137, 138, 389, 464) from the lab segment only, the value approved on October 10, 2026 (assessment plan §7). 4. Carried by P-13, P-15 and P-19, each of which allows its own service in the Samba DC's firewall from Ubuntu Server only when that service is set up (done for P-19). 5. Set firewall logging to `medium`, which adds new connections, allowed packets not matching the policy, and invalid packets to the firewall log (still rate-limited). 6. Enable the firewall. |
| Re-test | Repeat the assessment plan §5 scans. From the MacBook Air on the home network, only SSH answers. From Kali Linux (attack simulation) on the lab segment, only the directory ports answer. The log records connections. |
| Dependency | Remediated together with P-02 (system owner decision, September 26, 2026). P-11, P-13, P-15 and P-19 depend on this entry. |

### P-02 — Samba DC answers anonymous requests (Finding 13)

| | |
|---|---|
| Status | Closed October 12, 2026: re-test passed for the share and account listings over file sharing (report §13.1); the anonymous file-sharing session and the account listing over `ncacn_ip_tcp` are carried by P-29 (Finding 14). Task 2 is recorded in the system security plan §10.3. |
| Statements | AC-03 — Samba DC; AC-14 (not yet assessed) |
| Evidence | With no credentials, a host on the lab segment, outside the boundary, obtained all 8 domain user accounts and the share list; the anonymous-access restriction was at its default (report §8.2). |
| Tasks | 1. Set `restrict anonymous = 2`. Samba documents that this disables anonymous account-database access and *"disallow[s] anonymous connections to the IPC$ share in general"*. Confirm no share sets `guest ok = yes`, which Samba says removes the benefit. 2. After the re-test, record in the system security plan the actions permitted without identification or authentication (name resolution, the directory's connectionless lookup, and the start of the Kerberos exchange), and that no other action is permitted (AC-14); if the account listing over `ncacn_ip_tcp` still answers, record it as an exception under the new finding. |
| Re-test | From both segments, with no credentials, repeat the anonymous share listing and account listing over the file-sharing transport. Then repeat the account listing directly over the network RPC transport (`ncacn_ip_tcp`). On a domain controller, that service runs in a separate server component whose source does not read `restrict anonymous`, so this second test decides whether the fix is complete. If it still answers, a new finding is raised. |
| Dependency | Remediated together with P-01. |

### P-03 — Windows client answers on services outside the approved set (Finding 3)

| | |
|---|---|
| Status | Closed October 10, 2026: superseded by P-17 (October 1, 2026); the Windows client's retirement was verified (report §12). |
| Statements | CM-07a (print spooler); CM-07b.[02]–[03]; SC-07a.[01], [03] (firewall logging); SC-07a.[02], [04] (inbound) — Windows client |
| Evidence | Eight TCP ports answered from the home network, seven outside the approved set; the SSH rule accepted any remote address; firewall logging was off (report §6.1). |
| Tasks | 1. Restrict the SSH rule's remote address to the MacBook Air (`Set-NetFirewallRule -RemoteAddress`). 2. Disable the File and Printer Sharing and Network Discovery rule groups, and the Delivery Optimization and Connected Devices Platform allow rules (`Disable-NetFirewallRule`). 3. Remove the unused remote-desktop and AnyDesk allow rules. 4. Stop and disable the print spooler, per Microsoft's published workaround; printing is not a mission capability. 5. Log blocked and allowed connections on all three profiles (`Set-NetFirewallProfile -LogBlocked True -LogAllowed True`). |
| Re-test | Repeat the assessment plan §5 home-network scan: only SSH answers. The SSH rule's address filter shows the MacBook Air. The firewall log records connections. |

### P-04 — Exercise files readable more broadly than their sources (Finding 5)

| | |
|---|---|
| Statements | AC-03 — Ubuntu Server (file modes; the policy part is P-23) |
| Evidence | Three files derived from packet captures, one holding a captured test credential, are world-readable, while the two captures are owner-only (report §8.1). |
| Tasks | Set the three files to owner read and write only (mode 600), matching the captures. |
| Re-test | The listing shows `-rw-------` on all five files. The unprivileged read, which the home folder already blocked, is repeated and still fails. |

### P-05 — Cached domain logons leave a lockout path untested (Finding 7)

| | |
|---|---|
| Status | Closed October 12, 2026: re-test passed (report §13.2). The system security plan §10.3 records that cached logons are turned off, rather than that no cached authenticators exist (system owner decision, October 12, 2026). |
| Statements | AC-07a, AC-07b — Ubuntu Server |
| Evidence | Cached domain logons were enabled; the lockout was enforced through the online path; the cached-logon path was not tested; the installed Samba release documents no setting that limits how long a cached logon is accepted (report §9.2; assessment plan §1). |
| Tasks | Set `winbind offline logon = no` and restart winbind. Samba documents that the authentication module's cached-logon option works only *"when winbind offline logon is enabled"*, so domain logons then always go to the Samba DC. Record in the system security plan that no cached authenticators exist, for the assessment of IA-5(13). |
| Re-test | The setting reads `No`. With the Samba DC shut down, a domain logon on Ubuntu Server fails. With it running, the assessment plan §5 lockout test through Ubuntu Server is repeated, and the account locks at the fifth attempt. |

### P-06 — External remote-management agent with no agreement (Finding 9)

| | |
|---|---|
| Statements | SA-09a.[01]–[03], b.[01]–[02], c; this exchange's part of CA-03a–c; CM-07a and CM-07b.[04] (agent) — Windows client |
| Evidence | The Action1 agent ran with automatic start and could receive software deployments from the vendor's console; no agreement covered the connection (report §6.1, §11.1). |
| Tasks | 1. Remove the endpoint from the Action1 console with its option to uninstall agents and remove endpoints, then close the account. Action1 documents that a connected agent is uninstalled at once, and an unconnected one when it next connects; the client is not reconnected before its retirement (P-17). 2. The agent itself is removed when the client's storage media are sanitized (P-17). 3. With P-17 task 3, remove the exchange from the system security plan §8 and the agent from §9. |
| Re-test | The console lists no endpoint and the account is closed; the agent is gone with the sanitized media (P-17); SA-9 and this exchange's CA-3 statements are re-assessed. |
| Dependency | With P-17. |

### P-07 — Windows client's internet isolation not in effect; design since changed (Finding 10)

| | |
|---|---|
| Status | Closed October 10, 2026: superseded by P-17 (October 1, 2026); the Windows client's retirement was verified (report §12). |
| Statements | SC-07a.[02], [04] (outbound); SC-07c — Windows client |
| Evidence | A manually configured default route reached the internet by address; name resolution was disabled (report §6.1); an earlier disconnect did not persist (system security plan §11; [evidence appendix §13](evidence-appendix.md#13-the-august-7-disconnect-and-the-september-25-default-route)). |
| Design change | The system owner changed the design on September 29, 2026: the client keeps outbound internet access until it is retired, and isolation is no longer intended. The system owner's reasons: the attempts to isolate the client did not hold (Finding 10), and the client is retired after remediation. |
| Tasks | 1. Restore name resolution on the Wi-Fi adapter (`Set-DnsClientServerAddress`). 2. Record the new design in the system security plan: outbound internet access by design until retirement, with inbound connections restricted (P-03). |
| Re-test | Name resolution succeeds, and Defender records a successful signature update. The system security plan records the new design, and the SC-7 outbound statements are re-assessed against it. Finding 10 then closes, with the design change recorded as the reason. |
| Dependency | Before P-06 and P-16. |

### P-08 — Adware installed and running (Finding 11)

| | |
|---|---|
| Status | Closed October 10, 2026: superseded by P-17 (October 1, 2026); the Windows client's retirement was verified (report §12). |
| Statements | CM-07a and CM-07b.[04] (adware); SI-03a.[01]; SI-03a.[02] — Windows client |
| Evidence | An application Microsoft classifies as adware ran as three processes; antivirus had not detected it, and protection against potentially unwanted applications was off (report §6.1). |
| Tasks | 1. Uninstall the application and confirm its processes and folder are gone. 2. Turn on blocking of potentially unwanted applications (`Set-MpPreference -PUAProtection Enabled`). 3. Run a full scan once signatures are current (P-16). |
| Re-test | No adware processes or folder; the preference reads `1`; the scan reports no threats. |

### P-09 — Ubuntu Server SSH rule broader than approved; allowed traffic not logged

| | |
|---|---|
| Statements | CM-07b.[02]–[03]; SC-07a.[01], [03]; SC-07a.[02], [04] — Ubuntu Server |
| Evidence | SSH is allowed from any address except one; only blocked traffic is logged, with rate limiting (report §5.1). |
| Tasks | 1. Replace the SSH allow rules (IPv4 and IPv6) with one rule allowing SSH from the MacBook Air's lab-segment address. 2. Set firewall logging to `medium`. |
| Re-test | The firewall status lists SSH from the MacBook Air only; the log records new connections. |

### P-10 — Services beyond the mission run

| | |
|---|---|
| Statements | CM-07a; CM-07b.[01], [05] — both servers |
| Evidence | Modem, multipath and disk-management services run on both servers (report §5.1, §5.2). |
| Tasks | Stop and disable ModemManager, multipathd and udisks2 on both servers. |
| Re-test | The running-services list on each server matches the approved set. |

### P-29 — Samba DC accepts an anonymous file-sharing session and lists accounts over the network RPC transport (Finding 14)

| | |
|---|---|
| Status | Open: tasks 1–3 completed and re-test passed from Kali Linux, October 13, 2026 (system owner's determination; report §14). The Samba DC requires encrypted file sharing and admits the RPC ports from Ubuntu Server only. Kept open by the system owner for the account listing over `ncacn_ip_tcp`, still reachable from Ubuntu Server, where it was not run (`rpcclient` is not installed); task 4 is tracked instead of a proposal for acceptance. |
| Statements | AC-03 — Samba DC; AC-14 (not yet assessed) |
| Evidence | After P-02, from Kali Linux on the lab segment with no credentials: the Samba DC accepted an anonymous file-sharing session, although the share listing and the account listing over file sharing were refused; the account listing over the network RPC transport (`ncacn_ip_tcp`) returned all 8 domain user accounts (report §13.1). |
| Tasks | 1. Research how the Samba DC can refuse the anonymous account listing over `ncacn_ip_tcp` and the anonymous file-sharing session, and record each method with its source. 2. Apply them. 3. Update the AC-14 record in the system security plan §10.3. 4. If a Samba release adds a setting that refuses anonymous requesters on the account listing over `ncacn_ip_tcp` (proposed in [Samba bug 12775](https://bugzilla.samba.org/show_bug.cgi?id=12775)), apply it, then repeat the re-test, including from Ubuntu Server (system owner decision, October 13, 2026). |
| Re-test | From the lab segment, with no credentials, repeat the share listing, the account listing over the file-sharing transport and the account listing over `ncacn_ip_tcp`: the anonymous file-sharing session is refused and no account is listed. |

---

## 4. Entries — Update and Monitoring Infrastructure

### P-11 — No agent enrolled in the SIEM; Samba DC flaws not reported

| | |
|---|---|
| Statements | SI-02a.[01]–[02]; SC-07a.[01], [03] (monitoring part); SI-03c.02[02] (alert path, with P-15) — Samba DC |
| Evidence | The manager's agent list shows only the manager (report §5.3; [evidence appendix §1](evidence-appendix.md#1-wazuh-agent-list-and-server-clocks)). No vulnerability scanning covers the Samba DC, and nothing reports its flaws (report §4.2). |
| Tasks | 1. Install the Wazuh agent on the Samba DC at the manager's version, or upgrade the manager first in a maintenance window (P-14); Wazuh guarantees compatibility when the manager's version is the same as or later than the agent's. 2. Enroll it to Ubuntu Server's manager (`WAZUH_MANAGER`). Its package inventory then feeds vulnerability detection, and its logs, including ClamAV's (P-15), reach the dashboard. |
| Re-test | The agent list shows the Samba DC active. Its vulnerabilities appear on the dashboard. |
| Dependency | After P-01, P-12 and P-13. |

### P-12 — Wazuh services listen on every interface (Finding 1)

| | |
|---|---|
| Statements | CM-07a (agent ports) — Ubuntu Server |
| Evidence | Agent ports 1514 and 1515 and the API on 55000 listen on all interfaces; only the host firewall keeps them unreachable (report §5.1). |
| Tasks | 1. Confirm the dashboard reaches the Wazuh API over the loopback address. Then set the API's `host` value to the loopback address only, and restart the manager. 2. Allow 1514 and 1515 in the host firewall from the Samba DC's lab-segment address only, for P-11. The assessment plan §4 inbound value is to be amended to include them when this entry is remediated. |
| Re-test | Listening sockets show the API on loopback only. A full TCP scan from Kali Linux still shows 1514, 1515 and 55000 filtered, as at assessment. |

### P-13 — Ubuntu Server security updates overdue; vulnerability data not updating

| | |
|---|---|
| Statements | SI-02a.[01]–[03]; SI-02c.[01] — Ubuntu Server |
| Evidence | When assessed, 11 security fixes had not been installed at least 51 days after release, against a 30-day limit. The vulnerability module's data updates failed: 25 failures were logged from September 13 to the assessment, and no success appeared in the entries read (report §3.1, §3.2). |
| Tasks | 1. Run a package caching proxy (`apt-cacher-ng`) on the Samba DC, reachable from Ubuntu Server only, and point Ubuntu Server's package manager at it (`Acquire::http::Proxy`). Confirm each package source's scheme; for any `https://` source, such as the Wazuh repository, configure the proxy to pass it through or remap it. 2. Install the pending security updates in the first maintenance window (P-14). 3. On the Samba DC, download the current Wazuh vulnerability-data snapshot and serve it to Ubuntu Server. Set the manager's `offline-url` to it, which Wazuh documents for servers without internet access. 4. In the Samba DC's host firewall, allow the proxy and the snapshot from Ubuntu Server only (from P-01 task 4). The approved inbound set in the assessment plan §4 is to be amended to include them when this entry is remediated. |
| Re-test | No security update is pending; the manager log records a successful vulnerability-data update; the dashboard lists vulnerabilities. |
| Dependency | After P-01. |

### P-14 — Updates not tested before installation; general updates not installed

| | |
|---|---|
| Statements | SI-02b.[01]–[04] — both servers; SI-02a.[03] — Samba DC |
| Evidence | Neither server tests updates before installation. When assessed, the Samba DC had 65 general updates not installed (report §3.2, §4.1, §4.2). |
| Tasks | 1. Turn off automatic installation on both servers, keeping the daily package-list refresh. 2. Hold a weekly maintenance window per server: take a VMware snapshot, install all pending updates, check the services, then keep the change or revert to the snapshot. |
| Re-test | Each window is recorded (date, updates installed, services checked, kept or reverted); no update is pending after a window. |

### P-15 — Servers lack malicious code protection meeting the approved values (Finding 12)

| | |
|---|---|
| Statements | Ubuntu Server: SI-03a.[01]–[02], b, c.01[02], c.02[01]. Samba DC: SI-03a.[01]–[02], b, c.01[01]–[02], c.02[01]–[02]. |
| Evidence | No antivirus was found on either server; Ubuntu Server's only mechanism is a rootkit check every 12 hours that raises alerts but does not scan in real time or quarantine (report §7). |
| Tasks | 1. Install ClamAV (`clamav`, `clamav-daemon`, `clamav-freshclam`) on both servers; on Ubuntu Server, through the proxy (P-13). 2. On the Samba DC, run a private signature mirror (`cvdupdate`) reachable from Ubuntu Server only. Point Ubuntu Server's `freshclam` at it (`PrivateMirror`, `DNSDatabaseInfo no`). 3. Turn on on-access scanning (`clamd` with `clamonacc`) after confirming the kernel supports fanotify access permissions, with quarantine (`--move`). 4. Schedule a weekly full scan with quarantine. 5. Send ClamAV events to syslog (`LogSyslog true`). Confirm each server writes the system log that Wazuh's ClamAV decoders read, and that the events reach the dashboard. 6. In the Samba DC's host firewall, allow the signature mirror from Ubuntu Server only (from P-01 task 4). The approved inbound set in the assessment plan §4 is to be amended to include it when this entry is remediated. |
| Re-test | ClamAV's documented test: an EICAR test file in a watched path is blocked and quarantined, and an alert appears on the dashboard, on both servers. Ubuntu Server's signatures update from the mirror. |
| Dependency | After P-01, P-11 and P-13. |

### P-16 — Windows antivirus signatures out of date (Finding 4)

| | |
|---|---|
| Status | Closed October 10, 2026: superseded by P-17 (October 1, 2026); the Windows client's retirement was verified (report §12). |
| Statements | SI-03a.[01] (signature part); SI-03b — Windows client |
| Evidence | Signatures were dated August 6, 2026. Defender's log recorded its last successful update on August 7 and only failed attempts after that, most often on name resolution, which was disabled. `SignatureScheduleDay` was at Microsoft's default (8), and `SignatureUpdateInterval` read 0; with 8, Microsoft documents that Defender checks for definition updates at a default frequency (report §6.1). |
| Tasks | After P-07 restores name resolution, set an explicit daily signature check (`Set-MpPreference -SignatureScheduleDay 0`). |
| Re-test | The signature date is within the past day, and the Defender log records a successful update that ran on its own schedule. |
| Dependency | After P-07. |

### P-17 — Windows client operating system past end of support (Finding 8)

| | |
|---|---|
| Status | Closed October 10, 2026: re-test passed (report §12). |
| Statements | SA-22a; SA-22b; SI-02a.[03]; SI-02c.[01]; SI-02c.[02] — Windows client. Every other Windows client result that is other than satisfied also maps here, as do the remote-management exchange's CA-03a–c and SA-09 results (with P-06; §6). |
| Evidence | Windows 10 left support October 14, 2025; no security update since May 2023 was installed; whether newer firmware existed could not be established (report §6.1). |
| Constraint | Microsoft provides Windows 10 security updates after October 14, 2025 only through Extended Security Updates. Its consumer program excludes *"Devices joined to an Active Directory domain …"* Its program for organizations is sold per device; it is not used, because remediation is limited to no-cost actions (§1). |
| Risk response | Risk avoidance: the system owner decided on October 1, 2026, to retire the client early, without remediating it. SP 800-39 describes risk avoidance as *"taking specific actions to eliminate the activities or technologies that are the basis for the risk"*. This is the system owner's proposed risk response, pending Authorizing Official review (§1). |
| Tasks | Dispose of the client as a system element removed from operation (SP 800-37 Rev 2, Task M-7): 1. Delete the client's computer account from the domain. 2. Sanitize its storage media with the Purge method of SP 800-88 Rev 2, since the system is categorized HIGH for confidentiality and the media will be reused and stay under the system owner's control; validate the result and complete a certificate of sanitization. 3. Update the component inventory, the authorization boundary and the plans. The Action1 endpoint and account are handled in P-06. |
| Re-test | Retirement is verified: the domain no longer lists the computer account; the Action1 console lists no endpoint (P-06); the client is absent from the network; the certificate of sanitization is on file; the component inventory, boundary and plans record the retirement. |
| Milestones | Retirement decided by the system owner (October 1, 2026). Computer account deleted (October 7, 2026). Media sanitized by Purge (ATA Enhanced Security Erase), verified with a full read of the drive, and validated; certificate of sanitization completed (October 8, 2026). Inventory, boundary and plans updated (October 10, 2026). Retirement re-test passed (October 10, 2026). |

### P-18 — Windows detections not set to quarantine

| | |
|---|---|
| Status | Closed October 10, 2026: superseded by P-17 (October 1, 2026); the Windows client's retirement was verified (report §12). |
| Statements | SI-03c.02[01] — Windows client |
| Evidence | The four default threat actions were left at Microsoft's default, which applies the action Microsoft's threat data recommends; quarantine was not configured (report §6.1, §6.2). |
| Tasks | Set the low, moderate, high and severe default threat actions to `Quarantine` (`Set-MpPreference`). |
| Re-test | All four preferences read `2` (Quarantine). |

### P-19 — Ubuntu Server clock not synchronized

| | |
|---|---|
| Status | Closed October 12, 2026: re-test passed; result recorded in the system security plan §10.3. |
| Source | System owner review; AU-8 was not assessed. |
| Evidence | On September 28, 2026, Ubuntu Server reported its clock as not synchronized; the Samba DC's was synchronized ([evidence appendix §1](evidence-appendix.md#1-wazuh-agent-list-and-server-clocks)). On October 12, 2026, before the change, Ubuntu Server reported `System clock synchronized: yes`, but its time service, chrony, had no source in use (`Leap status     : Not synchronised`), and VMware Tools periodic time synchronization was on (`Enabled`); the Samba DC's `chrony.conf` had no `allow` line ([evidence appendix §16](evidence-appendix.md#16-time-synchronization-on-ubuntu-server)). |
| Tasks | 1. On the Samba DC, serve time with `chrony`, keeping its current upstream source. Allow Ubuntu Server only (`allow`); chrony serves no clients unless `allow` names them. In the host firewall, allow the time service (UDP 123) from Ubuntu Server only (from P-01 task 4); the assessment plan §4 inbound value was amended to include it (October 12, 2026). 2. On Ubuntu Server, set the Samba DC as chrony's only time source (`server` directive) and remove the other sources. 3. On Ubuntu Server, turn off VMware Tools periodic time synchronization, so that chrony alone keeps the clock (system owner decision, October 12, 2026). |
| Re-test | chrony on Ubuntu Server shows the Samba DC as its selected source and reports synchronized (matching control: SC-45(1), in no SP 800-53B baseline; system security plan §10.3). |
| Dependency | After P-01. |

---

## 5. Entries — Documents and Procedures

### P-20 — No configuration management plan

| | |
|---|---|
| Statements | SI-02d — both servers |
| Evidence | No configuration management plan exists (report §3.2, §4.2). |
| Tasks | Write a configuration management plan covering each server's baseline configuration, the weekly maintenance window (P-14) as the change procedure with flaw remediation built in, and the approved-software list (P-21). |
| Re-test | SI-02d is re-assessed against the plan. |

### P-21 — No software-restriction policy or list

| | |
|---|---|
| Statements | CM-07b.[04] — both servers |
| Evidence | No software-restriction policy or approved-software list is documented (report §5.3). |
| Tasks | Record an approved-software list in the configuration management plan (P-20) and check each server's installed packages against it monthly. |
| Re-test | The monthly check is recorded. |
| Proposed for acceptance | Servers: software is restricted by list and review, not by technical enforcement (pending Authorizing Official review). |

### P-22 — No security architecture document

| | |
|---|---|
| Statements | SC-07c — both servers |
| Evidence | No security architecture document exists (report §5.4). |
| Tasks | Write a security architecture document: the segments, each boundary device and its rules, the permitted flows after P-01, P-09, P-12 and P-29, and the update and time services on the Samba DC. |
| Re-test | SC-07c is re-assessed. |

### P-23 — No access control policy or list of approved authorizations

| | |
|---|---|
| Statements | AC-03 (policy part) — both servers |
| Evidence | No access control policy is issued and no list of approved authorizations exists (report §8.1, §8.2). |
| Tasks | Issue an access control policy with a list of approved authorizations for each account and path in the boundary. |
| Re-test | AC-3 is re-assessed on both servers against the policy. |

### P-24 — No procedure for false positives

| | |
|---|---|
| Statements | SI-03d — both servers |
| Evidence | No procedure addresses false positives (report §7.3). |
| Tasks | Write a procedure: how a detection is confirmed or dismissed, how a quarantined file is restored, and how an exclusion is approved and recorded. |
| Re-test | SI-03d is re-assessed. |

### P-25 — Information exchanges have no agreements

| | |
|---|---|
| Statements | CA-03_ODP[02]; CA-03a; CA-03b.[01]–[06]; CA-03c — all exchanges |
| Evidence | No exchange agreement exists; the defined agreement type, a record in the system security plan, is a one-party record (report §10). |
| Tasks | Expand each exchange record in the system security plan §8 to hold what CA-3 requires: approval and management of the exchange, interface characteristics, security and privacy requirements, controls, responsibilities for each system, the impact level of the information communicated, and a review date. The remote-management exchange and the Windows client's part of the home-network and internet exchanges ended with the client's retirement (P-06, P-17) and are not expanded. |
| Re-test | CA-3 is re-assessed. |
| Proposed for acceptance | The records remain one-party. The system owner is both parties to every internal exchange, and no information exchange agreement with the internet provider exists (pending Authorizing Official review). |

### P-26 — Windows client has no flaw reporting or detection alert path

| | |
|---|---|
| Status | Closed October 10, 2026: superseded by P-17 (October 1, 2026), and this entry's acceptance proposal is withdrawn; the Windows client's retirement was verified (report §12). |
| Statements | SI-02a.[01]–[02]; SI-03c.02[02]; SC-07a.[01], [03] (monitoring part) — Windows client |
| Evidence | No scanner or SIEM agent covered the client, and nothing alerted the system owner beyond the device itself (report §6.2). The client and Ubuntu Server shared no route (report §3.1, §6.1). |
| Tasks | Review Defender's detection events (IDs 1116 and 1117 in its operational log) weekly until retirement. |
| Re-test | The weekly review is recorded. |
| Proposed for acceptance (withdrawn) | No flaw scanning, no automated alert, and no interface monitoring beyond the firewall log, until retirement (pending Authorizing Official review). The system owner's earlier decision not to extend SIEM monitoring to this client stands. |

### P-27 — Inbound reachability from the internet not examined

| | |
|---|---|
| Source | System owner review. |
| Evidence | Outbound paths to the internet exist through the home gateway; inbound reachability was not examined (system security plan §8). |
| Tasks | Examine the home gateway's port forwarding, DMZ host and UPnP settings, and record them. Remove any forwarding or DMZ entry that points at a boundary component, and turn off UPnP unless something requires it. |
| Re-test | The settings are re-read and recorded; the system security plan §8 states the result. |

### P-28 — Ubuntu Server isolation has no recorded risk acceptance

| | |
|---|---|
| Source | System owner review (report §3.2, SI-02c.[01] basis). |
| Evidence | Ubuntu Server sits on an isolated segment by design; the effect of that isolation on patching was not assessed or accepted (report §3.2). |
| Tasks | Record the isolation as a design decision. With the proxy (P-13), mirror (P-15), vulnerability-data snapshot (P-13) and time service (P-19) in place, the isolation is intended to no longer block updates; the P-13 and P-15 re-tests are to confirm it (the P-19 time service passed its re-test on October 12, 2026). |
| Re-test | The design decision is recorded in the system security plan, and the acceptance proposal is filed, pending Authorizing Official review. |
| Proposed for acceptance | Isolation of Ubuntu Server by design (pending Authorizing Official review). |

---

## 6. Traceability — Every Other-Than-Satisfied Result

All 101 other-than-satisfied results from the assessment report, by component and by exchange. "S" marks a satisfied result; "—" marks a control not assessed on that component. Every other-than-satisfied Windows client result maps to P-17, which retires the client.

<details>
<summary>Statement-to-entry map (101 results)</summary>

| Statement | Ubuntu Server | Samba DC | Windows client |
|---|---|---|---|
| SA-22a | S | S | P-17 |
| SA-22b | S | S | P-17 |
| SI-02a.[01] | P-13 | P-11 | P-17 |
| SI-02a.[02] | P-13 | P-11 | P-17 |
| SI-02a.[03] | P-13 | P-14 | P-17 |
| SI-02b.[01]–[04] (4 each) | P-14 | P-14 | P-17 |
| SI-02c.[01] | P-13 | S | P-17 |
| SI-02c.[02] | S | S | P-17 |
| SI-02d | P-20 | P-20 | P-17 |
| CM-07a | P-10, P-12 | P-10 | P-06, P-17 |
| CM-07b.[01], [05] (2 each) | P-10 | P-10 | P-17 |
| CM-07b.[02]–[03] (2 each) | P-09 | P-01 | P-17 |
| CM-07b.[04] | P-21 | P-21 | P-06, P-17 |
| SC-07a.[01], [03] (2 each) | P-09 | P-01, P-11 | P-17 |
| SC-07a.[02], [04] (2 each) | P-09 | P-01 | P-17 |
| SC-07c | P-22 | P-01, P-22 | P-17 |
| SI-03a.[01] | P-15 | P-15 | P-17 |
| SI-03a.[02] | P-15 | P-15 | P-17 |
| SI-03b | P-15 | P-15 | P-17 |
| SI-03c.01[01] | S | P-15 | S |
| SI-03c.01[02] | P-15 | P-15 | S |
| SI-03c.02[01] | P-15 | P-15 | P-17 |
| SI-03c.02[02] | S | P-11, P-15 | P-17 |
| SI-03d | P-24 | P-24 | P-17 |
| AC-03 | P-04, P-23 | P-02, P-23, P-29 | — |
| AC-07a | P-05 | S | — |
| AC-07b | P-05 | S | — |
| **Other than satisfied** | **29** | **28** | **29** |

| Statement | Exchanges | Entry |
|---|---|---|
| CA-03_ODP[02] | All | P-25 |
| CA-03a, CA-03b.[01]–[06], CA-03c (8) | All | P-25; P-06 and P-17 for the remote-management exchange |
| SA-09a.[01]–[03], b.[01]–[02], c (6) | Remote-management service | P-06, P-17 |
| **Other than satisfied** | | **15** |

Total: 29 + 28 + 29 + 15 = **101**.

</details>

---

## 7. Change Record

| Date | Sections | Description |
|---|---|---|
| 2026-10-01 | At a glance, §1, §2, §3, §4, §5, §6 | Windows client retirement recorded. The system owner decided to retire the client early, without remediation; P-17 is rewritten as risk avoidance through disposal (SP 800-37 Rev 2 Task M-7), pending Authorizing Official review. P-03, P-07, P-08, P-16, P-18 and P-26 are superseded by P-17 and kept as written under a status line. P-06 no longer depends on P-07. The Windows parts of P-10, P-14, P-20, P-21, P-22 and P-24 are removed, P-01 task 3 and P-25 are tied to the retirement, and §6 maps every Windows client statement to P-17 (totals unchanged). Acceptance proposals for the Windows client in P-14, P-17 and P-26 are withdrawn: six proposals become three. |
| 2026-10-01 | At a glance, §1, §2, §7 (new) | Target date for all open entries moved from October 1, 2026, which passed with every entry open, to October 18, 2026. Re-test wording aligned with SP 800-37 Rev 2 Task A-5: reassessment results are added and original results kept. Report section references for P-10 and P-11 corrected. Change record added. |
| 2026-10-02 | §4 (P-11, P-16, P-17, P-25), §6 | Corrections from the final review before publication. P-11's evidence line says no vulnerability scanning covers the Samba DC, matching report §4.2. P-16's evidence line no longer calls `SignatureUpdateInterval 0` a Microsoft default; only `SignatureScheduleDay 8` is documented as the default. P-17's statements line, and §6's introduction, say every other-than-satisfied Windows client statement maps to it, as the §6 table shows, without attributing that to the superseded entries; P-17's constraint states that remediation is limited to no-cost actions. P-25's proposal no longer says an agreement with the internet provider is unobtainable. P-16 is otherwise kept as written. |
| 2026-10-03 | At a glance, §1, §3 (P-02, P-07), §4 (P-11, P-17, P-19), §7 | The evidence lines of P-07, P-11 and P-19 link to the records behind them in the new evidence appendix (`evidence-appendix.md`). Wording edited for brevity and grammar in the At a glance, §1, P-02 and P-17. No entry, status or date changed. |
| 2026-10-04 | At a glance, §2, §3 (P-01–P-05, P-09), §4 (P-11–P-15, P-19), §5 (P-22, P-26, P-28), §6, §7 | Components named by product (Ubuntu Server (SIEM), Samba DC, Windows client, Kali Linux (attack simulation), MacBook Air), with the role given at first mention; earlier change-record rows use the new names. Wording edited for readability. No entry, status or date changed. |
| 2026-10-07 | §1, §4 (P-17), §7 | P-17 task 1 completed: the Windows client's computer account was deleted from the domain on October 7, 2026; the domain no longer lists it. P-17 stays open until the client's retirement is verified. §1 states that no organizational risk tolerance has been stated and that the acceptance proposals cannot be decided until one is. No other entry, status or date changed. |
| 2026-10-08 | §4 (P-17), §7 | P-17 task 2 completed: on October 8, 2026, the Windows client's internal drive was sanitized by Purge, using the drive's ATA Enhanced Security Erase command. Verification confirmed that the command completed, and a read of the whole drive found every addressable byte to be zero. The result was validated and a certificate of sanitization completed. P-17 stays open until the client's retirement is verified. No other entry, status or date changed. |
| 2026-10-10 | At a glance, §3 (P-01, P-06), §4 (P-17), §7 | P-17 task 3 completed on October 10, 2026: the component inventory, the authorization boundary and the plans were updated for the Windows client's retirement (system security plan §2, §7–§11, §13; assessment plan §1, §4, §7; evidence appendix §14, §15; README), ahead of the retirement re-test. Carried out with it: P-06 task 3 (the Action1 exchange removed from the system security plan §8 and the agent from §9; the task now reads "With P-17 task 3") and the assessment plan part of P-01 task 3 (directory services approved from the lab segment only; P-01 task 3 now states that value; the firewall rule itself is not yet made). The assessment plan's SSH value names the two servers instead of all three components. P-06 task 2 was completed on October 8, 2026, with P-17 task 2: the agent was removed with the sanitized media. At a glance states that the client has been retired. P-17's risk response no longer states that the client stays in the boundary. P-17, P-06 and P-01 stay open until their re-tests pass; the six entries superseded by P-17 stay open until the retirement is verified. No other entry, status or date changed. |
| 2026-10-10 | At a glance, §3 (P-03, P-07, P-08), §4 (P-16, P-17, P-18), §5 (P-26), §7 | P-17's re-test passed on October 10, 2026 (report §12). P-17 closed, and with it the six entries it superseded (P-03, P-07, P-08, P-16, P-18, P-26); P-17 gains a status line, the six entries' status lines now read closed, and P-17's milestones record the re-test. At a glance states that the retirement was verified and these entries are closed, adds that retirement is the system owner's proposed risk response pending Authorizing Official review, no longer counts the open findings, and points to the system security plan §11 for each finding's status. P-06 stays open. No other entry, status or date changed. |
| 2026-10-12 | At a glance, §1, §2, §3 (P-01, P-02, P-03, P-05, P-06, P-07, P-08), §4 (P-13, P-14, P-16, P-17, P-18), §5 (P-25, P-26), §6, §7 | Wording corrected; no entry added or removed, no status changed, and the target date for open entries is unchanged. At a glance and §1 state that an entry superseded by another closes with the superseding entry's re-test, as the six entries P-17 superseded did on October 10, 2026. At a glance counts 174 results of 73 determination statements, each rated per component, 101 of them other than satisfied; §6's heading, note and summary count results. The note under §2 says that §6 maps each other-than-satisfied result to its entries, and that the superseded entries are kept under their status lines (several were edited after October 1, as this record shows). Evidence lines that are no longer true are in the past tense: P-01, P-02 and P-05 (closed October 12, 2026), P-06, the closed Windows client entries P-03, P-07, P-08, P-16, P-17, P-18 and P-26, and P-13's failure count and P-14's update count, now dated to the assessment. P-17's statements line names the remote-management exchange's CA-3 and SA-9 results that §6 maps to it, and its milestones no longer carry the target date. P-25 states that the Windows client's exchanges ended with its retirement. |
| 2026-10-12 | At a glance, §2, §3 (P-01, P-02, P-05, P-29), §4 (P-13, P-15, P-19), §5 (P-28), §6, §7 | Re-tests on October 12, 2026 (report §13). P-01 passed and closed; its task 4 (the update and time services) is carried by P-13, P-15 and P-19, each of which has a task to allow its own service in the Samba DC's firewall from Ubuntu Server only and to amend the assessment plan §4 inbound value when that entry is remediated (done for P-19). P-02 passed for the share and account listings over file sharing and closed; its task 2, the AC-14 record, is in the system security plan §10.3. The re-test found that the Samba DC still accepts an anonymous file-sharing session and lists all 8 domain user accounts over the network RPC transport: Finding 14, carried by the new entry P-29 (§2, §3, and §6 under AC-03 for the Samba DC; totals unchanged). P-05 passed and closed; its status line records the system owner's decision that the system security plan records cached logons as turned off, rather than that no cached authenticators exist. P-19 passed and closed: §2 adds SC-45(1) to its controls; its evidence adds the state before the change; its tasks add the firewall rule and turning off VMware Tools periodic time synchronization; its re-test reads the time service's synchronization directly instead of assessing AU-8, naming SC-45(1) as the matching control (in no SP 800-53B baseline). The assessment plan §4 inbound value now includes the time service on the Samba DC, from Ubuntu Server only. P-28 states that P-19's re-test has passed. At a glance counts 29 entries and records these closures. No other entry, status or date changed. |
| 2026-10-13 | At a glance, §1, §2, §3 (P-01, P-04, P-29), §4 (P-12, P-13, P-16), §5 (P-22, P-26, P-27), §6, §7 | P-29 tasks 1–3 completed on October 13, 2026: the Samba DC requires encrypted file sharing, which refuses the anonymous file-sharing session, and its firewall admits the RPC ports (135, 49152–65535) from Ubuntu Server only (assessment plan §4, approved by the system owner on October 13, 2026); the AC-14 record is updated (system security plan §10.3). The re-test passed from Kali Linux (system owner's determination; report §14). P-29 stays open for the account listing over `ncacn_ip_tcp`, still reachable from Ubuntu Server; it gains a status line and task 4, to apply a Samba setting if a release adds one (system owner decision; no acceptance proposal), and its evidence line is in the past tense. P-01 task 3 cites the inbound value approved on October 10, 2026; P-22 adds P-29 to the permitted flows; P-26's withdrawn proposal is labeled as withdrawn. Wording corrected in At a glance, §1, §2, §6 and P-04, P-12, P-13, P-16 and P-27, with no meaning changed. No other entry, status or date changed. |
