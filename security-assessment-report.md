# Security Assessment Report — Cybersecurity Home Lab (HL-01)

> **At a glance.** As assessed September 24–28, 2026, a partial self-assessment of the nine controls named in the [security assessment plan](security-assessment-plan.md) is complete: 174 determination statements, 73 satisfied and 101 other than satisfied.
>
> - **Ubuntu Server (SIEM)** runs supported software and is isolated; its firewall allows only its dashboard and SSH (SSH from any address but one IPv4 address). Its security fixes are at least 51 days past release against a 30-day limit.
> - **Samba DC** runs supported software and patches within days, but has no firewall: every directory service and SSH is reachable from the whole home network, and no firewall or SIEM agent records traffic at its interfaces. With no credentials at all, a host on the lab segment, outside the boundary, can list every domain user account and the Samba DC's file shares.
> - **Malicious code protection.** No antivirus was found on either server. Ubuntu Server's only malicious code check is a twice-daily rootkit scan that raises alerts; the Samba DC has none.
> - **Account lockout.** The domain lockout limit is enforced on the Samba DC, and on Ubuntu Server through its online domain-logon path; Ubuntu Server's cached-logon path is untested.
> - **Information exchange.** No information exchange agreements exist for any connection. The one external service, a remote-management agent on the Windows client, runs with no agreement, oversight, or monitoring.
> - **Windows client.** It runs an unsupported operating system with no security update since May 2023. Its intended internet isolation is not in effect and name resolution is disabled. Its antivirus has not updated since August, with most update attempts failing on name resolution, and software Microsoft classifies as adware runs on it undetected.
> - **Every component.** Flaw scanning is absent or not working, no current flaw data is reported, nothing tests updates before installation, and services beyond the mission run.

---

## 1. Scope and Method

This is a partial self-assessment of the nine controls named in the security assessment plan ("the plan" below), using SP 800-53A Rev 5 (Release 5.2.0) procedures, which are unchanged from the base edition for these controls. Each determination statement is rated *satisfied* or *other than satisfied*. The assessor is the system owner; no independent assessor exists (plan §2). Evidence is quoted from live command output, with identifying values replaced or redacted. Timestamps from Ubuntu Server and the Samba DC are UTC; both clocks are set to UTC, and on September 28 Ubuntu Server reported its clock as not synchronized ([evidence appendix §1](evidence-appendix.md#1-wazuh-agent-list-and-server-clocks)). The Windows client's timestamps are as recorded on the host, which displayed local time at UTC−7; its clock was not exact ([evidence appendix](evidence-appendix.md#how-the-records-were-produced)).

**Sequence and schedule.** Evidence was gathered September 24–28, 2026, not in one day as plan §6 scheduled. The September 28 checks were read-only: the server clocks, the Wazuh agent list, Ubuntu Server's cached-logon settings, and the Windows client's SSH rule address filter. The servers' SA-22, SI-2, CM-7, and SC-7 evidence follows the plan's §5 order. Their SI-3 evidence was gathered on September 25 with the Windows client's, before AC-3 (September 26) and AC-7 (September 27, UTC). The Windows client's evidence for all its controls (SA-22, SI-2, CM-7, SC-7, SI-3) was gathered in one connection window on September 25, except where §6.1 gives another date (its firewall profile settings were read on September 17). Two planned scans were not run: Ubuntu Server was not scanned from the home network, where it has no interface (§3.1), and the Windows client was not scanned from Kali Linux (attack simulation), which has no route to it (§6.1). No control was remediated during the assessment, so none was re-tested (plan §3). Every other-than-satisfied result goes to the plan of action and milestones.

**Scan sources.** Port scans were run from Kali Linux on the lab segment and from the MacBook Air (macOS; hypervisor and administration host) on the home network. Both sit outside the authorization boundary, so the scans test the boundary from outside it.

---

## 2. Results

| Control | Component | Satisfied | Other than satisfied | Status |
|---|---|---|---|---|
| SA-22 | Ubuntu Server | 4 | 0 | Complete |
| SI-2 | Ubuntu Server | 2 | 9 | Complete |
| SA-22 | Samba DC | 4 | 0 | Complete |
| SI-2 | Samba DC | 3 | 8 | Complete |
| CM-7 | Ubuntu Server | 6 | 6 | Complete |
| CM-7 | Samba DC | 6 | 6 | Complete |
| SC-7 | Ubuntu Server | 2 | 5 | Complete |
| SC-7 | Samba DC | 2 | 5 | Complete |
| SA-22 | Windows client | 2 | 2 | Complete |
| SI-2 | Windows client | 1 | 10 | Complete |
| CM-7 | Windows client | 6 | 6 | Complete |
| SC-7 | Windows client | 2 | 5 | Complete |
| SI-3 | Windows client | 7 | 6 | Complete |
| SI-3 | Ubuntu Server | 7 | 6 | Complete |
| SI-3 | Samba DC | 5 | 8 | Complete |
| AC-3 | Ubuntu Server | 0 | 1 | Complete |
| AC-3 | Samba DC | 0 | 1 | Complete |
| AC-7 | Ubuntu Server | 4 | 2 | Complete |
| AC-7 | Samba DC | 6 | 0 | Complete |
| CA-3 | All exchanges | 2 | 9 | Complete |
| SA-9 | Windows client · Action1 | 2 | 6 | Complete |

---

## 3. SA-22 and SI-2 — Ubuntu Server

### 3.1 Evidence

**Network path.** The routing table holds the lab segment only; there is no default route.

```
$ ip route
198.51.100.0/24 dev enp2s0 proto kernel scope link src 198.51.100.130 metric 100
```

**Security update index.** The publication stamp in the security repository's index:

```
$ grep -m1 '^Date:' /var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_resolute-security_InRelease
Date: Tue, 04 Aug 2026 16:01:12 UTC
```

**Pending updates.** `apt list --upgradable` returns 63 packages: 11 from the security repository, 49 from the general updates repository only, and 3 from the Wazuh repository. The 11 security-repository packages:

```
distro-info-data/resolute-updates,resolute-security <version> all [upgradable from: <version>]
libc-bin/resolute-updates,resolute-security <version> arm64 [upgradable from: <version>]
libc-dev-bin/resolute-updates,resolute-security <version> arm64 [upgradable from: <version>]
libc-gconv-modules-extra/resolute-updates,resolute-security <version> arm64 [upgradable from: <version>]
libc6-dev/resolute-updates,resolute-security <version> arm64 [upgradable from: <version>]
libc6/resolute-updates,resolute-security <version> arm64 [upgradable from: <version>]
libssl3t64/resolute-updates,resolute-security <version> arm64 [upgradable from: <version>]
locales/resolute-updates,resolute-security <version> all [upgradable from: <version>]
openssl-provider-legacy/resolute-updates,resolute-security <version> arm64 [upgradable from: <version>]
openssl/resolute-updates,resolute-security <version> arm64 [upgradable from: <version>]
tzdata/resolute-updates,resolute-security <version> all [upgradable from: <version>]
```

**Update history.** Selected rows from `apt history-list`; `…` marks omitted rows.

```
96   /usr/bin/unattended-u... 2026-07-19  01:28:55   Upgrade   58
…
114  /usr/bin/unattended-u... 2026-07-23  21:52:07   Upgrade   4
…
124  /usr/bin/unattended-u... 2026-07-23  21:53:08   Upgrade   1
…
140  install -y winbind li... 2026-08-04  17:14:44   Install   16
```

**Automatic updates.**

```
$ systemctl is-enabled unattended-upgrades apt-daily.timer apt-daily-upgrade.timer
enabled
enabled
enabled

$ apt-config dump | grep -E '^APT::Periodic|^Unattended-Upgrade::Allowed-Origins'
APT::Periodic "";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Allowed-Origins "";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESMApps:${distro_codename}-apps-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESM:${distro_codename}-infra-security";
```

**Vulnerability detection.** The Wazuh module is enabled and set to index its results for the dashboard:

```
  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>
```

Its data updates fail in every attempt shown:

```
…
2026/09/24 20:10:49 wazuh-modulesd:content-updater: ERROR: Action for 'vulnerability_feed_manager' failed: Error -1 from server: Could not connect to server - Response body: .
2026/09/24 21:10:49 wazuh-modulesd:content-updater: ERROR: Action for 'vulnerability_feed_manager' failed: Error -1 from server: Could not connect to server - Response body: .
2026/09/24 22:10:49 wazuh-modulesd:content-updater: ERROR: Action for 'vulnerability_feed_manager' failed: Error -1 from server: Could not connect to server - Response body: .
2026/09/24 23:10:49 wazuh-modulesd:content-updater: ERROR: Action for 'vulnerability_feed_manager' failed: Error -1 from server: Could not connect to server - Response body: .
```

The current log begins `2026/09/13 00:00:10 wazuh-monitord: INFO: Starting new log after rotation.` It records 25 failed data updates. The ten most recent non-error vulnerability entries (September 17–24) are module starts, stops, and index connections; none records a successful update. No archived logs are retained.

**Support status.** Ubuntu 26.04 LTS standard security maintenance runs to May 2031, and Expanded Security Maintenance through Ubuntu Pro to May 2036 (https://ubuntu.com/about/release-cycle, checked September 24, 2026).

**Firmware.** Ubuntu Server's platform firmware is virtual firmware supplied by the MacBook Air, which is outside the authorization boundary (system security plan §9).

**Configuration management.** No configuration management plan exists for the system.

### 3.2 Determinations

| Statement | Determination statement (summary) | Result | Basis |
|---|---|---|---|
| SI-02_ODP | Time period to install security-relevant updates is defined | Satisfied | Defined as 30 days from release (plan §4). |
| SI-02a.[01] | System flaws are identified | Other than satisfied | The vulnerability detection module cannot update its data: 25 failed attempts have been logged since the current log began, no successful update appears in the entries read, and the only flaw list available is the package index published August 4. |
| SI-02a.[02] | System flaws are reported | Other than satisfied | Results are set to be indexed for the dashboard, but the module's data updates fail: 25 failures have been logged since the current log began on September 13, and no successful update appears in the entries read; no earlier logs are retained. |
| SI-02a.[03] | System flaws are corrected | Other than satisfied | 11 security fixes published no later than August 4 are not installed. |
| SI-02b.[01]–[04] | Software and firmware updates are tested for effectiveness and side effects before installation | Other than satisfied | Unattended upgrades are configured to install security updates automatically (daily period); no testing step is configured or documented. |
| SI-02c.[01] | Security-relevant software updates are installed within the time period | Other than satisfied | The security index carries the stamp `Date: Tue, 04 Aug 2026 16:01:12 UTC`, and updates to 11 packages from the security repository in that index are not installed — at least 51 days after release, against the 30-day limit. The server sits on an isolated segment by documented design and last installed packages on August 4, 2026; the effect of that isolation on patching has not been assessed or accepted. |
| SI-02c.[02] | Security-relevant firmware updates are installed within the time period | Satisfied | The platform firmware is virtual firmware supplied by the MacBook Air, outside the boundary. The Linux firmware packages installed on this component have pending updates from the general updates repository only; none is from the security repository. |
| SI-02d | Flaw remediation is incorporated into the configuration management process | Other than satisfied | No configuration management plan exists. |
| SA-22_ODP[01]–[02] | Support source is selected and defined | Satisfied | Support from external providers, defined as vendor extended security updates (plan §4). |
| SA-22a | Components are replaced when support is no longer available | Satisfied | The operating system and its main-archive software are supported to May 2031. Wazuh released 4.14.8 in its 4.14 line on September 23, 2026 (https://documentation.wazuh.com/4.14/release-notes/release-4-14-8.html); no end-of-life date for the 4.14 line was found (checked September 24, 2026). No component has reached end of support. |
| SA-22b | The selected source provides options for alternative sources of continued support | Satisfied | Expanded Security Maintenance covers the operating system to May 2036, and unattended upgrades already list its origins. |

---

## 4. SA-22 and SI-2 — Samba DC

### 4.1 Evidence

**Network path.** The Samba DC has a default route through the home-network gateway.

```
$ ip route
default via 192.0.2.254 dev enp2s0 proto dhcp src 192.0.2.201 metric 100
192.0.2.0/24 dev enp2s0 proto kernel scope link src 192.0.2.201 metric 100
192.0.2.254 dev enp2s0 proto dhcp scope link src 192.0.2.201 metric 100
198.51.100.0/24 dev enp26s0 proto kernel scope link src 198.51.100.131 metric 100
198.51.100.1 dev enp26s0 proto dhcp scope link src 198.51.100.131 metric 100
```

**Security update index.**

```
Date: Wed, 23 Sep 2026 18:39:57 UTC
```

**Pending updates.** `apt list --upgradable` returns 65 packages, every one from the general updates repository (`resolute-updates`) only; none is from the security repository. Two packages (AppArmor and its library) remain at a pre-release (beta) version with their release versions available.

**Update history.** The 15 most recent rows of `apt history-list`:

```
139  /usr/bin/unattended-u... 2026-09-16  21:13:48   Upgrade   3
140  /usr/bin/unattended-u... 2026-09-16  21:13:55   Upgrade   4
141  /usr/bin/unattended-u... 2026-09-16  21:14:11   Upgrade   1
142  /usr/bin/unattended-u... 2026-09-24  19:17:52   Upgrade   6
143  /usr/bin/unattended-u... 2026-09-24  19:17:59   Upgrade   4
144  /usr/bin/unattended-u... 2026-09-24  19:18:05   Upgrade   1
145  /usr/bin/unattended-u... 2026-09-24  19:18:10   Upgrade   1
146  /usr/bin/unattended-u... 2026-09-24  19:18:17   I,U       10
147  /usr/bin/unattended-u... 2026-09-24  19:18:44   Upgrade   1
148  /usr/bin/unattended-u... 2026-09-24  19:18:50   Upgrade   1
149  /usr/bin/unattended-u... 2026-09-24  19:18:57   Upgrade   1
150  /usr/bin/unattended-u... 2026-09-24  19:19:04   Remove    3
151  /usr/bin/unattended-u... 2026-09-24  19:19:08   Remove    1
152  /usr/bin/unattended-u... 2026-09-24  19:19:09   Remove    1
153  /usr/bin/unattended-u... 2026-09-24  19:19:11   Remove    2
```

**Automatic updates.** Identical to Ubuntu Server (§3.1): all three update services are `enabled`; package lists refreshed and unattended upgrades run daily; allowed sources are the release, security, and Expanded Security Maintenance repositories — not the general updates repository.

**Flaw reporting.** The component inventory lists no vulnerability scanner or SIEM agent on this host. No report address is set for unattended upgrades, and no mail program is installed:

```
$ apt-config dump | grep -i '^Unattended-Upgrade::Mail'
$ command -v sendmail || echo "no sendmail"
no sendmail
```

**Control wording.** SI-2 part a reads *"Identify, report, and correct system flaws"* without the *"security-relevant"* qualifier that part c carries, and its discussion opens: *"The need to remediate system flaws applies to all types of software and firmware."* (SP 800-53 Rev 5 (Release 5.2.0).)

**Support status, firmware, and configuration management** are as for Ubuntu Server (§3.1): Ubuntu 26.04 LTS supported to May 2031 and Expanded Security Maintenance to May 2036, with Samba, Kerberos tools, and OpenSSH from the Ubuntu archive; virtual firmware supplied by the MacBook Air outside the boundary; no configuration management plan.

### 4.2 Determinations

| Statement | Determination statement (summary) | Result | Basis |
|---|---|---|---|
| SI-02_ODP | Time period to install security-relevant updates is defined | Satisfied | Defined as 30 days from release (plan §4). |
| SI-02a.[01] | System flaws are identified | Other than satisfied | Identification is limited to the vendor's package index; no vulnerability scanning covers this host. |
| SI-02a.[02] | System flaws are reported | Other than satisfied | Nothing reports flaws to the system owner: no SIEM agent, no report address, no mail program. |
| SI-02a.[03] | System flaws are corrected | Other than satisfied | Security fixes are installed, but 65 published updates from the general updates repository are not; part a covers all system flaws, not only security-relevant ones. |
| SI-02b.[01]–[04] | Software and firmware updates are tested for effectiveness and side effects before installation | Other than satisfied | Unattended upgrades are configured to install security updates automatically (daily period); no testing step is configured or documented. |
| SI-02c.[01] | Security-relevant software updates are installed within the time period | Satisfied | No update from the security repository is pending against an index published September 23, 2026; unattended upgrades last ran on September 24. |
| SI-02c.[02] | Security-relevant firmware updates are installed within the time period | Satisfied | The platform firmware is virtual firmware supplied by the MacBook Air, outside the boundary. The Linux firmware packages installed on this component have pending updates from the general updates repository only; none is from the security repository. |
| SI-02d | Flaw remediation is incorporated into the configuration management process | Other than satisfied | No configuration management plan exists. |
| SA-22_ODP[01]–[02] | Support source is selected and defined | Satisfied | Support from external providers, defined as vendor extended security updates (plan §4). |
| SA-22a | Components are replaced when support is no longer available | Satisfied | The operating system and its main-archive software, including Samba, are supported to May 2031. No component has reached end of support. |
| SA-22b | The selected source provides options for alternative sources of continued support | Satisfied | Expanded Security Maintenance covers the operating system to May 2036, and unattended upgrades already list its origins. |

---

## 5. CM-7 and SC-7 — Ubuntu Server and Samba DC

### 5.1 Evidence — Ubuntu Server

**Listening ports.** TCP (`ss -tlnp`), condensed (the header, queue and peer-address columns, and IPv6 duplicates are omitted):

```
LISTEN  0.0.0.0:55000          users:(("python3",…))
LISTEN  0.0.0.0:1515           users:(("wazuh-authd",…))
LISTEN  0.0.0.0:1514           users:(("wazuh-remoted",…))
LISTEN  127.0.0.53%lo:53       users:(("systemd-resolve",…))
LISTEN  0.0.0.0:22             users:(("sshd",…),("systemd",…))
LISTEN  127.0.0.54:53          users:(("systemd-resolve",…))
LISTEN  0.0.0.0:443            users:(("node",…))
LISTEN  [::ffff:127.0.0.1]:9300  users:(("java",…))
LISTEN  [::ffff:127.0.0.1]:9200  users:(("java",…))
```

UDP (`ss -ulnp`): name resolution and the time service on loopback only (53, 323); the address-assignment client on the lab interface (68).

**Firewall.**

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
…

To                         Action      From
--                         ------      ----
22                         DENY IN     198.51.100.128
22/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
443/tcp (v6)               ALLOW IN    Anywhere (v6)
```

The MacBook Air's SSH sessions arrive from a single address, its own on the lab segment, yet the rule allows any address except Kali Linux.

**Running services** include `ModemManager.service` (modem management; the VM has one network adapter), `multipathd.service`, and `udisks2.service`, alongside the Wazuh, SSH, and domain-membership services. No remote-management service runs.

**Scan from the lab segment** (Kali Linux, all TCP ports):

```
…
Not shown: 65534 filtered tcp ports (no-response)
PORT    STATE SERVICE REASON
443/tcp open  https   syn-ack ttl 64
…
```

All ten UDP ports probed returned `open|filtered … no-response`. No scan from the home network was run against Ubuntu Server.

**Firewall log of the scan.** 14 blocked-traffic entries from Kali Linux in the hour of the scan, for example:

```
… [UFW BLOCK] IN=enp2s0 OUT= … SRC=198.51.100.128 DST=198.51.100.130 … PROTO=TCP SPT=54872 DPT=56279 WINDOW=1024 RES=0x00 SYN URGP=0
```

The `low` level *"logs all blocked packets not matching the defined policy (with rate limiting) …"* (ufw manual, Ubuntu 26.04, https://manpages.ubuntu.com/manpages/resolute/en/man8/ufw.8.html, checked September 28, 2026). Allowed traffic is not logged.

### 5.2 Evidence — Samba DC

**Listening ports.** Every directory service, and SSH, binds all interfaces over TCP — `0.0.0.0` on 22, 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 49152–49154 — and over UDP on 53, 88, 137, 138, 389, and 464, including the home-network address directly.

**Firewall.**

```
$ sudo ufw status verbose
Status: inactive

$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
```

No nftables ruleset is loaded.

**Running services** include the same `ModemManager.service`, `multipathd.service`, and `udisks2.service`, alongside Samba, SSH, and time synchronization. No remote-management service runs.

**Scans.** The lab-segment scan (Kali Linux) and the home-network scan (MacBook Air) returned the same result:

```
…
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE          REASON
22/tcp    open  ssh              syn-ack ttl 64
53/tcp    open  domain           syn-ack ttl 64
88/tcp    open  kerberos-sec     syn-ack ttl 64
135/tcp   open  msrpc            syn-ack ttl 64
139/tcp   open  netbios-ssn      syn-ack ttl 64
389/tcp   open  ldap             syn-ack ttl 64
445/tcp   open  microsoft-ds     syn-ack ttl 64
464/tcp   open  kpasswd5         syn-ack ttl 64
636/tcp   open  ldapssl          syn-ack ttl 64
3268/tcp  open  globalcatLDAP    syn-ack ttl 64
3269/tcp  open  globalcatLDAPssl syn-ack ttl 64
49152/tcp open  unknown          syn-ack ttl 64
49153/tcp open  unknown          syn-ack ttl 64
49154/tcp open  unknown          syn-ack ttl 64
…
```

UDP 53, 88, 137, and 389 answered `open … udp-response` from both. Closed ports answer with a reset rather than silence, consistent with the empty firewall ruleset above.

### 5.3 Determinations — CM-7

The approved values (plan §4) define mission-essential capabilities as detection, identity services, and evidence production, and the required inbound set as SSH from the MacBook Air, the SIEM dashboard, and directory services from the lab segment and the Windows client only.

| Statement | Determination statement (summary) | Ubuntu Server | Samba DC |
|---|---|---|---|
| CM-07_ODP[01]–[06] | Capabilities, functions, ports, protocols, software, and services are defined | Satisfied — plan §4 | Satisfied — plan §4 |
| CM-07a | The system is configured to provide only mission-essential capabilities | Other than satisfied — modem, multipath, and disk-management services run; Wazuh agent ports 1514 and 1515 listen, but no agent is enrolled (the agent list, read September 28, shows only the manager; [evidence appendix §1](evidence-appendix.md#1-wazuh-agent-list-and-server-clocks)) | Other than satisfied — the same three services run |
| CM-07b.[01], [05] | Use of non-required functions and services is prohibited or restricted | Other than satisfied — nothing restricts the non-required services | Other than satisfied — nothing restricts the non-required services |
| CM-07b.[02]–[03] | Use of non-required ports and protocols is prohibited or restricted | Other than satisfied — default deny holds (only 443 reachable from Kali Linux), but SSH is allowed from any address except one IPv4 address, not only the MacBook Air | Other than satisfied — no firewall; directory services and SSH are reachable from the whole home network |
| CM-07b.[04] | Use of non-approved software is prohibited or restricted | Other than satisfied — no remote-management tool runs, but no software-restriction policy or approved-software list is documented | Other than satisfied — same |

### 5.4 Determinations — SC-7

Ubuntu Server's single interface is both external (toward Kali Linux, outside the boundary) and internal (toward the Samba DC). The Samba DC's home-network interface is external; its lab-segment interface is internal toward Ubuntu Server and external toward Kali Linux.

| Statement | Determination statement (summary) | Ubuntu Server | Samba DC |
|---|---|---|---|
| SC-07_ODP | Separation method is selected | Satisfied — logically (plan §4) | Satisfied — logically (plan §4) |
| SC-07a.[01], [03] | Communications at external and key internal managed interfaces are monitored | Other than satisfied — only blocked traffic is logged, with rate limiting; 14 entries were recorded for a full-port scan; allowed traffic is not recorded at the interface | Other than satisfied — no firewall or SIEM agent records traffic at its interfaces |
| SC-07a.[02], [04] | Communications at external and key internal managed interfaces are controlled | Other than satisfied — default deny holds, but the SSH rule is broader than the approved value | Other than satisfied — no filtering of any kind |
| SC-07b | Subnetworks for publicly accessible components are logically separated from internal organizational networks | Satisfied — the system has no publicly accessible components | Satisfied — the system has no publicly accessible components |
| SC-07c | External networks are connected only through managed interfaces of boundary protection devices arranged per a security and privacy architecture | Other than satisfied — the host firewall is the only device; no security architecture document exists | Other than satisfied — the home-network interface is unfiltered and routes to the internet through the home gateway; no security architecture document exists |

---

## 6. SA-22, SI-2, CM-7, SC-7, and SI-3 — Windows Client

Evidence was gathered on September 25, 2026, over SSH to PowerShell ([evidence appendix §15](evidence-appendix.md#15-ssh-administration-of-the-windows-client)) and by scans from outside the boundary, except where another date is given.

### 6.1 Evidence

**Operating system and support.**

```
ProductName    : Windows 10 Pro
DisplayVersion : 22H2
…
```

The installed build is the May 2023 cumulative update; Microsoft has published later Windows 10 22H2 security updates, including one on August 11, 2026, none of which is installed. Windows 10 reached end of support on October 14, 2025. Microsoft's consumer Extended Security Updates program runs through October 12, 2027 but excludes devices joined to an Active Directory domain, which this client is ([evidence appendix §3](evidence-appendix.md#3-windows-client-domain-membership)); organizations can buy Extended Security Updates per device. The operating system license listing (`slmgr /dlv`) was read; it does not list add-on licenses, and no Extended Security Updates enrollment was found. The newest entry `Get-HotFix` lists as a security update is dated May 5, 2023 ([evidence appendix §2](evidence-appendix.md#2-windows-client-model-firmware-date-and-hotfix-list)). Sources (checked September 24, 2026): https://support.microsoft.com/en-us/windows/deployment/updates-lifecycle/windows-10-support-has-ended-on-october-14-2025; https://support.microsoft.com/en-us/servicing/os/windows-10/2026/08/kb5120249-windows-10-21h2-22h2-security-update; https://www.microsoft.com/en-us/windows/extended-security-updates and https://learn.microsoft.com/en-us/windows/whats-new/extended-security-updates (both checked October 2, 2026).

**Firmware.** The client is physical, so its firmware is inside the boundary: a vendor release dated October 6, 2023 (read on the client, September 24; [evidence appendix §2](evidence-appendix.md#2-windows-client-model-firmware-date-and-hotfix-list)). The vendor is reported to distribute firmware for this model only with its desktop operating system updates (https://eclecticlight.co/2024/09/23/firmware-updates-with-macos-15-0-14-7-and-13-7/). By its model identifier, the client is a Mac mini (Late 2014) (https://support.apple.com/en-us/102852), which is on macOS Monterey's compatibility list (https://support.apple.com/en-us/103260) and not on the list for the next release, macOS Ventura (https://support.apple.com/en-us/102861); Monterey is therefore the last operating system version the model supports, and it has been unsupported since September 2024 (https://en.wikipedia.org/wiki/MacOS_Monterey). Whether newer firmware was released for this model could not be established.

**Network path and name resolution.**

```
Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Format-List DestinationPrefix,NextHop,InterfaceAlias,Protocol,Store,Publish,ValidLifetime

DestinationPrefix : 0.0.0.0/0
NextHop           : 192.0.2.254
InterfaceAlias    : Wi-Fi
Protocol          : NetMgmt
Store             : ActiveStore
Publish           : No
ValidLifetime     : 10675199.02:48:05.4775807

Test-NetConnection -ComputerName 1.1.1.1 -Port 443 | Format-List ComputerName,InterfaceAlias,SourceAddress,TcpTestSucceeded

ComputerName     : 1.1.1.1
InterfaceAlias   : Wi-Fi
SourceAddress    : 192.0.2.240
TcpTestSucceeded : True

Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,ServerAddresses

InterfaceAlias               ServerAddresses
--------------               ---------------
Ethernet                     {}
Local Area Connection* 9     {}
Local Area Connection* 10    {}
Wi-Fi                        {0.0.0.0}
Bluetooth Network Connection {}
Loopback Pseudo-Interface 1  {}

Resolve-DnsName -Name www.microsoft.com -Type A
Resolve-DnsName : www.microsoft.com : This operation returned because the timeout period expired
…
```

**Malicious code protection.** Selected fields from `Get-MpComputerStatus`:

```
AntivirusEnabled              : True
RealTimeProtectionEnabled     : True
AntivirusSignatureLastUpdated : 8/6/2026 12:43:40 PM
AntivirusSignatureAge         : 50
QuickScanEndTime              : 9/24/2026 3:49:37 PM
QuickScanAge                  : 1
```

Selected fields from `Get-MpPreference`:

```
ScanScheduleDay             : 0
ScanScheduleTime            : 02:00:00
SignatureScheduleDay        : 8
SignatureUpdateInterval     : 0
DisableRealtimeMonitoring   : False
LowThreatDefaultAction      : 0
ModerateThreatDefaultAction : 0
HighThreatDefaultAction     : 0
SevereThreatDefaultAction   : 0
```

```
Get-MpPreference | Format-List PUAProtection

PUAProtection : 0
```

`ScanScheduleDay 0` is every day: Microsoft lists the value as *"0: Everyday"* (https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference, checked September 28, 2026). `SignatureScheduleDay 8` is the default; Microsoft documents that with it, *"Windows Defender checks for definition updates by using a default frequency"* (same page, checked October 2, 2026). The four default threat actions are `0`, Microsoft's documented default: *"Apply action based on the Security Intelligence Update (SIU)"* (https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference, checked September 27, 2026). No detection has ever exercised them. `PUAProtection 0` is *"PUA Protection off … Microsoft Defender Antivirus won't protect against potentially unwanted applications"* (https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus, checked September 28, 2026). `Get-MpThreatDetection` and `Get-MpThreat` return nothing.

Signature update results in the Defender operational log, by date (`2000` succeeded, `2001` failed):

```
Count Name
----- ----
   13 2026-09-25, 2001
   21 2026-09-24, 2001
   14 2026-09-17, 2001
    7 2026-08-12, 2001
    2 2026-08-07, 2000
    7 2026-08-07, 2001
    7 2026-07-28, 2001
    2 2026-07-23, 2000
    7 2026-07-23, 2001
```

Every failure date's most frequent code is `0x80072ee7`: *"The server name or address could not be resolved"* ([evidence appendix §4](evidence-appendix.md#4-windows-client-antivirus-update-failures-by-error-code)). `AntivirusSignatureLastUpdated` gives the date of the installed signatures, August 6; the last successful update in the log is on August 7, and none succeeded after it.

**Software not approved for the system.**

```
DisplayName    : PC App Store
DisplayVersion : <version>
Publisher      : Fast Corporation LTD

Name          Path
----          ----
PCAppStore    C:\Program Files (x86)\PCAppStore\PcAppStore.exe
PCAppStoreSRV C:\Program Files (x86)\PCAppStore\PcAppStoreSRV.exe
Watchdog      C:\Program Files (x86)\PCAppStore\Watchdog.exe
```

Its folder was created July 22, 2026 ([evidence appendix §6](evidence-appendix.md#6-anydesk-download-record-remaining-firewall-rules-and-the-store-folder)). Microsoft Security Intelligence lists it as `Adware:Win32/PCAppStore!MSR`, category Adware (https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Adware:Win32/PCAppStore!MSR, checked September 28, 2026). The remote-management agent also runs, set to start automatically (read September 24; Finding 9; [evidence appendix §5](evidence-appendix.md#5-remote-management-agent-on-the-windows-client)).

**Running services** include `Spooler`, Bluetooth services, `SEMgrSvc` (payments and NFC), `SSDPSRV`, `fdPHost`, `FDResPub`, `DiagTrack`, and `LMS`, alongside the adware and the remote-management agent.

**Firewall.** On in all three profiles, `BlockInbound,AllowOutbound`, with blocked and allowed connections not logged (September 17). Enabled inbound allow rules include SSH from any address (`RemoteAddress : Any`, September 28), file and printer sharing, network discovery, Delivery Optimization, Connected Devices Platform, a remote desktop rule on TCP 33890 (remote desktop connections are denied and its service is stopped), and AnyDesk rules whose program files are absent or inside the adware's folder ([evidence appendix §6](evidence-appendix.md#6-anydesk-download-record-remaining-firewall-rules-and-the-store-folder)).

**Scan from the home network** (MacBook Air, all TCP ports):

```
…
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 128
135/tcp   open  msrpc        syn-ack ttl 128
139/tcp   open  netbios-ssn  syn-ack ttl 128
445/tcp   open  microsoft-ds syn-ack ttl 128
5040/tcp  open  unknown      syn-ack ttl 128
5357/tcp  open  wsdapi       syn-ack ttl 128
7680/tcp  open  pando-pub    syn-ack ttl 128
49668/tcp open  unknown      syn-ack ttl 128
…
```

Port 49668 is the print spooler (`spoolsv`). Of ten UDP ports probed, 137 answered `open … udp-response`; the other nine returned `open|filtered … no-response`.

**Scan from the lab segment** (Kali Linux):

```
…
setup_target: failed to determine route to 192.0.2.240
…
```

Kali Linux has no route to the client.

### 6.2 Determinations

For this component, the approved values (plan §4) require inbound SSH from the MacBook Air only and malicious code protection that is signature-based, scans weekly, scans in real time at the endpoint, quarantines, and alerts the system owner. SI-03_ODP[05] applies only when "take action" is selected; quarantine is selected instead.

| Statement | Determination statement (summary) | Result | Basis |
|---|---|---|---|
| SA-22_ODP[01]–[02] | Support source is selected and defined | Satisfied | Vendor extended security updates (plan §4). |
| SA-22a | Components are replaced when support is no longer available | Other than satisfied | The operating system has been past end of support since October 14, 2025 and is still in service. |
| SA-22b | The selected source provides options for alternative sources of continued support | Other than satisfied | Extended Security Updates exist for organizations, but no enrollment was found, the consumer program excludes domain-joined devices, and the client cannot resolve update servers' names. |
| SI-02_ODP | Time period to install security-relevant updates is defined | Satisfied | 30 days from release (plan §4). |
| SI-02a.[01] | System flaws are identified | Other than satisfied | No scanner or SIEM agent covers the client; no working identification mechanism is shown. |
| SI-02a.[02] | System flaws are reported | Other than satisfied | Nothing is shown reporting flaws to the system owner. |
| SI-02a.[03] | System flaws are corrected | Other than satisfied | No security update since May 2023 is installed; the build is the May 2023 cumulative update. |
| SI-02b.[01]–[04] | Software and firmware updates are tested for effectiveness and side effects before installation | Other than satisfied | No testing step is configured or documented. |
| SI-02c.[01] | Security-relevant software updates are installed within the time period | Other than satisfied | The August 11, 2026 security update is not installed, 45 days after release. |
| SI-02c.[02] | Security-relevant firmware updates are installed within the time period | Other than satisfied | Insufficient information: whether newer firmware was released for this model could not be established. |
| SI-02d | Flaw remediation is incorporated into the configuration management process | Other than satisfied | No configuration management plan exists. |
| CM-07_ODP[01]–[06] | Capabilities, functions, ports, protocols, software, and services are defined | Satisfied | Plan §4. |
| CM-07a | The system is configured to provide only mission-essential capabilities | Other than satisfied | Adware, an unapproved remote-management agent, the print spooler, and Bluetooth, payment, discovery, and telemetry services run. |
| CM-07b.[01], [05] | Use of non-required functions and services is prohibited or restricted | Other than satisfied | Nothing restricts the non-required services. |
| CM-07b.[02]–[03] | Use of non-required ports and protocols is prohibited or restricted | Other than satisfied | Eight TCP ports answer from the home network, seven outside the approved set; SSH is allowed from any address, not only the MacBook Air; allow rules remain for unused remote-access tools. |
| CM-07b.[04] | Use of non-approved software is prohibited or restricted | Other than satisfied | Adware and an unapproved remote-management agent run; no software-restriction policy or approved-software list is documented. |
| SC-07_ODP | Separation method is selected | Satisfied | Logically (plan §4). |
| SC-07a.[01], [03] | Communications at external and key internal managed interfaces are monitored | Other than satisfied | Firewall logging is off; no SIEM agent. |
| SC-07a.[02], [04] | Communications at external and key internal managed interfaces are controlled | Other than satisfied | Default block inbound, but eight ports are open to the home network and outbound traffic is unrestricted over an open internet path. |
| SC-07b | Subnetworks for publicly accessible components are logically separated from internal organizational networks | Satisfied | The system has no publicly accessible components. |
| SC-07c | External networks are connected only through managed interfaces of boundary protection devices arranged per a security and privacy architecture | Other than satisfied | The host firewall is the only device; the interface connects to the home network and, through the home gateway, to the internet, with no boundary protection device of the system in the path; no security architecture document exists. |
| SI-03_ODP[01]–[04], [06] | Mechanism type, scan frequency, scan points, response, and alert recipient are defined | Satisfied | Plan §4. |
| SI-03a.[01] | Signature-based mechanisms are implemented at system entry and exit points to detect malicious code | Other than satisfied | The mechanism runs, but its signatures have not updated since August 7 and it has not detected adware installed since July 22. |
| SI-03a.[02] | Signature-based mechanisms are implemented at system entry and exit points to eradicate malicious code | Other than satisfied | The adware remains in place. |
| SI-03b | Mechanisms are updated automatically as new releases are available per configuration management policy | Other than satisfied | Automatic update attempts fail, most often on name resolution; the last success was August 7, 2026. |
| SI-03c.01[01] | Mechanisms are configured to perform periodic scans weekly | Satisfied | Daily scans are scheduled; a quick scan completed September 24. |
| SI-03c.01[02] | Mechanisms are configured to perform real-time scans of files from external sources at the endpoint | Satisfied | Real-time protection is on. |
| SI-03c.02[01] | Mechanisms are configured to quarantine malicious code in response to detection | Other than satisfied | The four default threat actions are left at Microsoft's default (`0`), which applies the action Microsoft's threat data recommends for each detection; quarantine is not configured, and no detection has exercised the actions. |
| SI-03c.02[02] | Mechanisms are configured to alert the system owner in response to detection | Other than satisfied | No alert path to the system owner beyond the device itself. |
| SI-03d | False positives and their potential impact on availability are addressed | Other than satisfied | No procedure exists. |

**Findings raised by this assessment:** 10 (internet isolation not in effect; name resolution disabled) and 11 (adware installed and running). Finding 4 (antivirus signatures out of date) fails most often on name resolution, which Finding 10 records as disabled. All three are recorded in the system security plan (§11).

---

## 7. SI-3 — Ubuntu Server and Samba DC

Evidence was gathered on September 25, 2026, over SSH.

### 7.1 Evidence — Ubuntu Server

**Installed protection.** A search of installed packages for common antivirus and rootkit scanners (ClamAV, rkhunter, chkrootkit, Microsoft Defender for Endpoint, CrowdStrike Falcon, Sophos, ESET) matched only the Wazuh dashboard, whose description contains the word "ruleset". The component inventory lists no antivirus or rootkit scanner either.

**Wazuh rootcheck.** The only malicious code mechanism found on the server is the Wazuh manager's rootcheck module:

```
$ sudo grep -A25 '<rootcheck>' /var/ossec/etc/ossec.conf
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <skip_nfs>yes</skip_nfs>

    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>
…
```

Its most recent scan in the manager log:

```
2026/09/25 19:01:00 rootcheck: INFO: Starting rootcheck scan.
2026/09/25 19:01:50 rootcheck: INFO: Ending rootcheck scan.
```

Rootcheck compares the host against rootkit and trojan signature files and raises alerts; the documentation describes no removal or quarantine, and the configuration sets none (Wazuh documentation, https://documentation.wazuh.com/4.14/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html). The server has no path to update sources (§3.1).

### 7.2 Evidence — Samba DC

**Installed protection.** The same package search returned nothing:

```
$ dpkg -l | grep -iE 'clamav|rkhunter|chkrootkit|mdatp|falcon|sophos|eset' | cat
$
```

The component inventory lists Samba, Kerberos tools, OpenSSH, and an inactive host firewall on this host, and no SIEM agent. No report address is set for unattended upgrades, and no mail program is installed (§4.1).

### 7.3 Determinations

The approved values (plan §4) call for malicious code protection that is signature-based, scans weekly, scans in real time at the endpoint, quarantines, and alerts the system owner. SI-03_ODP[05] applies only when "take action" is selected; quarantine is selected instead.

| Statement | Determination statement (summary) | Ubuntu Server | Samba DC |
|---|---|---|---|
| SI-03_ODP[01]–[04], [06] | Mechanism type, scan frequency, scan points, response, and alert recipient are defined | Satisfied — plan §4 | Satisfied — plan §4 |
| SI-03a.[01] | Signature-based mechanisms are implemented at system entry and exit points to detect malicious code | Other than satisfied — no antivirus was found; rootcheck checks the host itself for rootkits and trojans every 12 hours | Other than satisfied — no malicious code protection is installed |
| SI-03a.[02] | Signature-based mechanisms are implemented at system entry and exit points to eradicate malicious code | Other than satisfied — rootcheck only raises alerts; nothing removes malicious code | Other than satisfied — no malicious code protection is installed |
| SI-03b | Mechanisms are updated automatically as new releases are available per configuration management policy | Other than satisfied — rootcheck reads local signature files, and the server has no path to update sources | Other than satisfied — no mechanism exists to update |
| SI-03c.01[01] | Mechanisms are configured to perform periodic scans weekly | Satisfied — rootcheck is configured to run every 12 hours; the last scan completed September 25 | Other than satisfied — no scanner is installed |
| SI-03c.01[02] | Mechanisms are configured to perform real-time scans of files from external sources at the endpoint | Other than satisfied — rootcheck runs on a schedule only | Other than satisfied — no scanner is installed |
| SI-03c.02[01] | Mechanisms are configured to quarantine malicious code in response to detection | Other than satisfied — rootcheck does not quarantine | Other than satisfied — no mechanism exists |
| SI-03c.02[02] | Mechanisms are configured to alert the system owner in response to detection | Satisfied — rootcheck is enabled on the manager, whose detections are written as alerts (Wazuh documentation); the manager's alert archives hold rootcheck alerts (for example, July 24 and July 28, 2026); none was exercised during this assessment | Other than satisfied — no SIEM agent, report address, or mail program |
| SI-03d | False positives and their potential impact on availability are addressed | Other than satisfied — no procedure exists | Other than satisfied — no procedure exists |

**Finding raised by this assessment:** 12 (neither server has malicious code protection meeting the approved values). Recorded in the system security plan (§11).

---

## 8. AC-3 — Ubuntu Server and Samba DC

Evidence was gathered on September 26, 2026, over SSH. The directory test ran from Kali Linux on the lab segment, outside the boundary, with no username or password.

### 8.1 Evidence — Ubuntu Server

**Exercise evidence files (Finding 5).** Five files sit in the operator's home folder. For each, the permissions of every folder on its path were listed, and a read was attempted as `nobody`, an account with no privileges (contents discarded). One file shown; all five returned the same path and read result ([evidence appendix §7](evidence-appendix.md#7-exercise-file-permissions-and-the-unprivileged-read)):

```
…
drwxr-xr-x root      root      /
drwxr-xr-x root      root      home
drwxr-x--- labadmin labadmin labadmin
-rw-rw-r-- labadmin labadmin plaintext_credentials.txt
cat: /home/labadmin/plaintext_credentials.txt: Permission denied
nobody: read failed - /home/labadmin/plaintext_credentials.txt
```

The two packet captures are `-rw-------`; the three text files, including the one holding a captured test credential, are `-rw-rw-r--`. The home folder admits only its owner and its group, and the group lists no additional members; no other account exists in the local user range.

**Policy.** No access control policy is issued (system security plan §3), and no list of approved authorizations exists.

### 8.2 Evidence — Samba DC

**Directory and file-service access without credentials**, from Kali Linux:

```
--- ldapsearch
…
result: 1 Operations error
text: 00002020: Operation unavailable without authentication
…
--- smbclient
Anonymous login successful

Sharename       Type      Comment
---------       ----      -------
sysvol          Disk
netlogon        Disk
IPC$            IPC       IPC Service (<version>)
…
--- rpcclient
user:[Administrator] rid:[0x1f4]
…
```

The anonymous directory search was refused. The anonymous file-service login succeeded and listed the shares. The anonymous remote procedure call returned all 8 domain user accounts, including the built-in administrator and the Kerberos service account ([evidence appendix §8](evidence-appendix.md#8-anonymous-account-and-share-listing-from-the-lab-segment)).

**Anonymous-access setting.**

```
$ testparm -s --parameter-name="restrict anonymous" 2>/dev/null; sudo grep -iE 'restrict anonymous|guest|map to guest' /etc/samba/smb.conf
0
```

`smb.conf` does not set the value or any guest option; `0` is Samba's default.

**Policy.** No access control policy is issued (system security plan §3).

### 8.3 Determinations

| Statement | Determination statement (summary) | Ubuntu Server | Samba DC |
|---|---|---|---|
| AC-03 | Approved authorizations for logical access are enforced in accordance with applicable access control policies | Other than satisfied — the home folder's permissions block every non-administrative account but the owner, which a failed read as an unprivileged account confirmed; however, no access control policy or list of approved authorizations exists to show that this access is the approved one | Other than satisfied — anonymous requesters on the lab segment, outside the boundary, obtain the full list of domain user accounts and the share list; no authorization grants that access, and no access control policy exists |

**Finding raised by this assessment:** 13 (the Samba DC lists every domain user account and its shares to anonymous requesters). Recorded in the system security plan (§11). AC-14, named by Finding 13, is outside this assessment's scope and goes to the plan of action and milestones.

---

## 9. AC-7 — Ubuntu Server and Samba DC

Evidence was gathered on September 27, 2026 (UTC), over SSH. The domain lockout policy was read on the Samba DC, and the lockout was tested live against a test account per the assessment plan (§5): first directly against the Samba DC, then through Ubuntu Server's winbind authentication path.

### 9.1 Evidence — Samba DC

**Domain lockout policy and test account baseline**, read before any failed logon; earlier policy lines omitted (`…`):

```
…
Account lockout duration (mins): 15
Account lockout threshold (attempts): 5
Reset account lockout after (mins): 15
```

```
…
badPwdCount: 0
badPasswordTime: 0
```

No `lockoutTime` attribute was returned, confirming the test account was unlocked. The approved values (plan §4) are threshold 5 attempts, reset window 15 minutes, lock duration 15 minutes.

**Lockout test.** Five consecutive domain logons with an incorrect password were made directly against the Samba DC (Kerberos authentication for the test account), started 03:00:16–03:00:28 UTC; each was rejected (`Password incorrect while getting initial credentials`). Both tests' attempts, and every counter read after them, are in [evidence appendix §9](evidence-appendix.md#9-domain-lockout-test-attempt-by-attempt). The account's counters immediately after (03:00:42 UTC):

```
…
badPwdCount: 5
badPasswordTime: 134349516316057010
lockoutTime: 134349516316057010
```

`badPwdCount` reached the threshold of 5 and `lockoutTime` was set to a non-zero value as the fifth attempt failed (03:00:31 UTC): the account locked automatically.

### 9.2 Evidence — Ubuntu Server

**Winbind connection state**, read on Ubuntu Server at the time of the test:

```
…
EXAMPLE : active connection
```

Winbind was online — the domain showed an active connection. A clean baseline was re-established on the Samba DC first (`badPwdCount: 0`, `lockoutTime: 0`, 03:07:57 UTC).

**Lockout test through Ubuntu Server.** Five consecutive domain logons with an incorrect password were made through Ubuntu Server's winbind authentication path for the same test account. Each attempt tried a plaintext logon and then a challenge/response logon, and both failed. After the first attempt the Samba DC's `badPwdCount` read 1; after the fifth, 5 ([evidence appendix §9](evidence-appendix.md#9-domain-lockout-test-attempt-by-attempt)). The counters read on the Samba DC immediately after (03:12:06 UTC):

```
…
badPwdCount: 5
badPasswordTime: 134349523157345630
lockoutTime: 134349523157345630
```

The account locked automatically at the fifth attempt (03:11:55 UTC): while winbind was online, the domain lockout was enforced through Ubuntu Server.

**Not tested — the cached-logon path.** Ubuntu Server is configured for cached domain logons (`winbind offline logon = Yes`; `cached_login` in the shared authentication stack; configuration read September 23 and again September 28, the September 28 read in [evidence appendix §10](evidence-appendix.md#10-cached-logon-settings-on-ubuntu-server)), and its winbind offline flag has been observed set while the Samba DC was reachable (Finding 7): on September 23, while the server's domain join test succeeded, and on October 2, after the assessment, while its connection check to the Samba DC succeeded. While that flag is set, a domain logon on this host may be validated against the local cache rather than by the Samba DC; whether and how the lockout limit is then applied is not established and was not tested. Exercising that path would require a cached credential and the offline-flag condition; the plan of action and milestones (P-05) instead removes the path by disabling cached logons and repeats the lockout test.

### 9.3 Determinations

The approved values (plan §4) are ODP[01] 5 consecutive attempts, ODP[02] 15 minutes, ODP[03] lock the account, ODP[04] 15 minutes. ODP[05] and ODP[06] are not applicable (delay algorithm and "other" action are not selected).

| Statement | Determination statement (summary) | Samba DC | Ubuntu Server |
|---|---|---|---|
| AC-07_ODP[01]–[04] | Number of attempts, time period, action when exceeded, and lock period are defined | Satisfied — plan §4 | Satisfied — plan §4 |
| AC-07a | A limit of 5 consecutive invalid logon attempts during 15 minutes is enforced | Satisfied — five failed domain logons drove the count to the threshold of 5 and the account locked; the limit was enforced live on the Samba DC | Other than satisfied — the limit was enforced through the online winbind path; enforcement is not shown for the cached-logon path (Finding 7), which was not tested |
| AC-07b | The account is automatically locked for 15 minutes when the maximum number of unsuccessful attempts is exceeded | Satisfied — `lockoutTime` was set automatically at the fifth attempt; the configured lock duration is 15 minutes (examined; the account was unlocked manually before it would have expired) | Other than satisfied — the automatic lock operated through the online winbind path but is not demonstrated for the cached-logon path (Finding 7), which was not tested |

---

## 10. CA-3 — Information Exchange

Documentation assessment; no commands. Scope: all information exchanges (system security plan §8).

### 10.1 Evidence

The system security plan §8 records five information exchanges and states: *"No information exchange agreements exist; none of the connected systems is separately authorized."* Each exchange is documented in a summary table — counterpart, components, what crosses the boundary, and security consideration — but not as an agreement. The one external service, the remote-management agent on the Windows client, runs with no agreement (Finding 9). No exchange or access control policy is issued (system security plan §3).

Approved parameter values (plan §4): the agreement types are service level or user agreements for external services and an information exchange record in the system security plan for every other exchange (CA-03_ODP[01]; the second is an organization-defined type, CA-03_ODP[02]); the review-and-update frequency is annual (CA-03_ODP[03]).

### 10.2 Determinations

| Statement | Determination statement (summary) | Result | Basis |
|---|---|---|---|
| CA-03_ODP[01] | Agreement types are selected | Satisfied | Defined (plan §4). |
| CA-03_ODP[02] | Type of agreement is defined | Other than satisfied | A type is named (plan §4): an information exchange record in the system security plan. That is a one-party record, not an agreement between the parties to an exchange. |
| CA-03_ODP[03] | Review-and-update frequency is defined | Satisfied | Annually (plan §4). |
| CA-03a | Each exchange is approved and managed using the selected agreement types | Other than satisfied | The external service has no agreement (Finding 9); the system security plan's §8 exchange records for the other four exchanges do not document approval or management of the exchanges. |
| CA-03b.[01] | Interface characteristics are documented as part of each exchange agreement | Other than satisfied | The external service has no agreement (Finding 9); the system security plan's §8 exchange records for the other four exchanges do not document interface characteristics. |
| CA-03b.[02] | Security requirements are documented as part of each exchange agreement | Other than satisfied | The external service has no agreement (Finding 9); the system security plan's §8 exchange records for the other four exchanges note a security consideration for each exchange but do not document security requirements. |
| CA-03b.[03] | Privacy requirements are documented as part of each exchange agreement | Other than satisfied | The external service has no agreement (Finding 9); the system security plan's §8 exchange records for the other four exchanges do not document privacy requirements. |
| CA-03b.[04] | Controls are documented as part of each exchange agreement | Other than satisfied | The external service has no agreement (Finding 9); the system security plan's §8 exchange records for the other four exchanges do not document controls. |
| CA-03b.[05] | Responsibilities for each system are documented as part of each exchange agreement | Other than satisfied | The external service has no agreement (Finding 9); the system security plan's §8 exchange records for the other four exchanges do not document responsibilities for each system. |
| CA-03b.[06] | The impact level of the information communicated is documented as part of each exchange agreement | Other than satisfied | The external service has no agreement (Finding 9); the system security plan's §8 exchange records for the other four exchanges do not document the impact level of the information communicated; categorization is recorded at the system level (system security plan §6), not per exchange. |
| CA-03c | Agreements are reviewed and updated at the defined frequency | Other than satisfied | The external service has no agreement to review (Finding 9); the system security plan's §8 exchange records for the other four exchanges carry no review date or review schedule. |

The other-than-satisfied results are carried by the existing findings — Finding 9 (remote-management agent, no agreement) and the system security plan's recorded state that no exchange agreements exist — and go to the plan of action and milestones. No new finding is raised.

---

## 11. SA-9 — External System Services

Documentation assessment; no commands. Scope: the external system service — the Action1 remote monitoring and management agent on the Windows client (Finding 9).

### 11.1 Evidence

The external system service reports the Windows client's inventory to a vendor cloud console, and the console can push software to the client. No agreement covers the connection (system security plan §8, remote-management cloud console row). No organizational security or privacy requirements are issued (system security plan §3), and no oversight, roles, or monitoring for the service are documented.

Approved parameter values (plan §4): the controls to be employed are the provider's published security commitments (SA-09_ODP[01]); the monitoring is an annual review of the provider's security documentation (SA-09_ODP[02]).

### 11.2 Determinations

| Statement | Determination statement (summary) | Result | Basis |
|---|---|---|---|
| SA-09_ODP[01] | Controls to be employed by the provider are defined | Satisfied | The provider's published security commitments (plan §4). |
| SA-09_ODP[02] | Monitoring processes, methods, and techniques are defined | Satisfied | Annual review of the provider's security documentation (plan §4). |
| SA-09a.[01] | The provider complies with organizational security requirements | Other than satisfied | No organizational security requirements are issued (system security plan §3), and no verification of the provider's compliance exists. |
| SA-09a.[02] | The provider complies with organizational privacy requirements | Other than satisfied | No organizational privacy requirements are issued (system security plan §3), and no verification exists. |
| SA-09a.[03] | The provider employs the defined controls | Other than satisfied | The provider's published commitments have not been obtained or verified, and no agreement binds them. |
| SA-09b.[01] | Organizational oversight is defined and documented | Other than satisfied | No oversight of the service is defined or documented. |
| SA-09b.[02] | User roles and responsibilities are defined and documented | Other than satisfied | None are documented for the service. |
| SA-09c | The defined monitoring is employed on an ongoing basis | Other than satisfied | No monitoring of the provider's compliance occurs. |

The other-than-satisfied results are carried by Finding 9 (remote-management agent, no agreement in place) and go to the plan of action and milestones. No new finding is raised.
