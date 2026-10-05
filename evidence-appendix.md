# Evidence Appendix — Cybersecurity Home Lab (HL-01)

> **At a glance.** Command output and log records behind statements in the [system security plan](system-security-plan.md), the [security assessment report](security-assessment-report.md) and the [plan of action and milestones](poam.md); each of those statements links to its section here. Every section names the component, the date, and the command or source file. Identifying values are replaced or redacted.

---

## How the records were produced

- **Command output.** Commands were run on the component named and their output pasted from the terminal into a working record at the time. Long command lines are shown without the terminal's line wrapping. Runs of blank lines are shortened to one, trailing spaces removed and sudo password prompts left out; any other omission is marked `…` or described in brackets.
- **From an earlier working record.** The August 7, 2026 block in section 13 was pasted at the time into an earlier working record and survives only there; no saved output or log holds it. It is labeled where it appears.
- **Windows client records.** Records were copied from the client on October 1, 2026, the day its retirement was decided. Those used here are its System, Windows Firewall and OpenSSH event logs, its Edge browser history, a Prefetch file, the PC App Store's download-manager file, and two text captures of its state. The copies are not published; each section gives the SHA-256 of the copy it reads. Event logs were read with python-evtx 0.8.1 by `parse_evtx.py`, the browser history with `query_history.py` (both below), and the Prefetch file with libscca-python 20260527. Times are UTC as recorded by the client's clock; event-log times are taken from each record's raw 100-nanosecond timestamp. That clock was not exact: on October 1 it ran about three hours ahead, so later records can carry later dates and times than the actual ones. For July 22, its times agree with the independent clock of the MacBook Air (macOS; hypervisor and administration host). The client displayed local times at UTC−7.

`parse_evtx.py`:

```python
# Print selected records of a Windows event log (.evtx), read-only, with python-evtx.
# usage: python3 parse_evtx.py LOG EVENT_IDS FROM TO FIELDS [FIELD=TEXT]
#   EVENT_IDS  comma-separated event IDs;  FROM, TO  UTC bounds (FROM inclusive, TO exclusive)
#   FIELDS     comma-separated EventData names to print;  FIELD=TEXT  keep records whose FIELD starts with TEXT
import sys, datetime, xml.etree.ElementTree as ET
import Evtx.Evtx as evtx, Evtx.Nodes as N
NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'
log, lo, hi = sys.argv[1], sys.argv[3], sys.argv[4]
ids = {int(x) for x in sys.argv[2].split(',')}
fields = sys.argv[5].split(',')
match = sys.argv[6].split('=', 1) if len(sys.argv) > 6 else None
print(' | '.join(['EventRecordID', 'EventID', 'TimeCreated (UTC, 100-ns)'] + fields))
with evtx.Evtx(log) as f:
    for rec in f.records():
        root = ET.fromstring(rec.xml())
        sysn = root.find(NS + 'System')
        eid = int(sysn.find(NS + 'EventID').text)
        if eid not in ids:
            continue
        shown = sysn.find(NS + 'TimeCreated').get('SystemTime')
        # the raw FILETIME behind TimeCreated; python-evtx's own print stops at microseconds
        ft = [s.unpack_qword(0) for s in rec.root().substitutions()
              if isinstance(s, N.FiletimeTypeNode) and s.string() == shown][0]
        sec, ticks = divmod(ft, 10**7)
        utc = (datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=sec)).strftime('%Y-%m-%dT%H:%M:%S') + '.%07dZ' % ticks
        if not lo <= utc < hi:
            continue
        ed = root.find(NS + 'EventData')
        d = {e.get('Name'): (e.text or '') for e in ed} if ed is not None else {}
        if match and not d.get(match[0], '').startswith(match[1]):
            continue
        print(' | '.join([sysn.find(NS + 'EventRecordID').text, str(eid), utc] + [d.get(k, '-') for k in fields]))
```

`query_history.py`:

```python
# Read a Chromium/Edge History database read-only and print selected visits and one download.
# usage: python3 query_history.py DB FIRST_VISIT LAST_VISIT DOWNLOAD_ID
import sys, sqlite3, datetime
db, first, last, dl = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
c = sqlite3.connect('file:%s?mode=ro&immutable=1' % db, uri=True)
utc = lambda us: (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
print('visit | time (UTC) | from_visit | transition core | qualifiers | url | title')
for vid, t, fv, tr, url, title in c.execute(
        'SELECT v.id, v.visit_time, v.from_visit, v.transition, u.url, u.title FROM visits v '
        'JOIN urls u ON u.id = v.url WHERE v.id BETWEEN ? AND ? ORDER BY v.id', (first, last)):
    print(' | '.join(map(str, (vid, utc(t), fv, tr & 0xFF, '0x%08X' % (tr & 0xFFFFFF00), url, title))))
row = c.execute('SELECT id, start_time, end_time, target_path, received_bytes, total_bytes, state, danger_type, '
                'tab_url FROM downloads WHERE id = ?', (dl,)).fetchone()
for k, v in zip(('id', 'start_time', 'end_time', 'target_path', 'received_bytes', 'total_bytes', 'state', 'danger_type', 'tab_url'), row):
    print('%s = %s' % (k, utc(v) if k.endswith('_time') else v))
for (url,) in c.execute('SELECT url FROM downloads_url_chains WHERE id = ? ORDER BY chain_index', (dl,)):
    print('url_chain = %s' % url)
```

---

## 1. Wazuh agent list and server clocks

Supports the assessment report §1 (both server clocks are set to UTC) and §5.3 (CM-07a: no agent is enrolled), and plan of action and milestones entries P-11 and P-19. Ubuntu Server (SIEM) and Samba DC, September 28, 2026.

```
labadmin@ubuntu-target:~$ timedatectl; sudo /var/ossec/bin/agent_control -l
               Local time: Mon 2026-09-28 17:27:10 UTC
           Universal time: Mon 2026-09-28 17:27:10 UTC
                 RTC time: Mon 2026-09-28 17:27:10
                Time zone: Etc/UTC (UTC, +0000)
System clock synchronized: no
              NTP service: active
          RTC in local TZ: no

Wazuh agent_control. List of available agents:
   ID: 000, Name: ubuntu-target (server), IP: 127.0.0.1, Active/Local

List of agentless devices:
```

```
dcadmin@samba-dc:~$ timedatectl
               Local time: Mon 2026-09-28 17:28:19 UTC
           Universal time: Mon 2026-09-28 17:28:19 UTC
                 RTC time: Mon 2026-09-28 17:28:20
                Time zone: Etc/UTC (UTC, +0000)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
```

Both clocks run on UTC. Ubuntu Server reports its clock as not synchronized, the Samba DC as synchronized. The agent list holds only the manager itself (ID 000).

## 2. Windows client model, firmware date and hotfix list

Supports the assessment report §6.1 (the newest security update `Get-HotFix` lists is dated May 5, 2023; the firmware release date; the model identifier) and system security plan Finding 8. Windows client, September 24, 2026, PowerShell; two commands, each shown with only the output cited.

```
PS C:\Users\winadmin> Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model; Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate; $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; $cv | Select-Object ProductName, DisplayVersion, CurrentBuild, UBR; [DateTimeOffset]::FromUnixTimeSeconds($cv.InstallDate).UtcDateTime; Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3 HotFixID, Description, InstalledOn; Get-MpComputerStatus | Select-Object AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, AntivirusSignatureLastUpdated; $s = Get-CimInstance Win32_Service -Filter "Name='sshd'"; $s | Select-Object Name, State, PathName; (Get-Item $s.PathName.Trim('"')).VersionInfo.ProductVersion; Get-Service A1Agent, WazuhSvc -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType

Manufacturer Model
------------ -----
Apple Inc.   Macmini7,1
[rest of the output omitted]
```

```
PS C:\Users\winadmin> Get-CimInstance Win32_BIOS | Format-List Manufacturer, SMBIOSBIOSVersion, ReleaseDate; $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; $cv | Format-List ProductName, DisplayVersion, CurrentBuild, UBR; "InstallDate (UTC): " + [DateTimeOffset]::FromUnixTimeSeconds($cv.InstallDate).UtcDateTime; Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3 | Format-List HotFixID, Description, InstalledOn; Get-MpComputerStatus | Format-List AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, AntivirusSignatureLastUpdated; Get-CimInstance Win32_Service -Filter "Name='sshd'" | Format-List Name, State, PathName; Get-Service A1Agent, WazuhSvc -ErrorAction SilentlyContinue | Format-List Name, Status, StartType; "Service check done"

Manufacturer      : Apple Inc.
SMBIOSBIOSVersion : <version>
ReleaseDate       : 10/6/2023 5:00:00 PM

[operating system and install date omitted]

HotFixID    : KB5033052
Description : Update
InstalledOn : 8/7/2026 12:00:00 AM

HotFixID    : KB5011048
Description : Update
InstalledOn : 7/28/2026 12:00:00 AM

HotFixID    : KB5014032
Description : Security Update
InstalledOn : 5/5/2023 12:00:00 AM

[Defender, SSH service and Get-Service output, and the closing `Service check done` line, omitted; the Get-Service output is in section 5]
```

`Select-Object -First 3` keeps the three most recent entries. The two newest are listed as `Update`; the third, `KB5014032`, is a `Security Update` dated May 5, 2023. The firmware version string is redacted.

## 3. Windows client domain membership

Supports the assessment report §6.1: the consumer Extended Security Updates program excludes devices joined to an Active Directory domain, "which this client is". Windows client, September 28, 2026.

```
PS C:\Users\winadmin> Get-CimInstance Win32_ComputerSystem | Format-List Name,PartOfDomain,Domain

Name         : DESKTOP-QLHBOB7
PartOfDomain : True
Domain       : example.test
```

## 4. Windows client antivirus update failures by error code

Supports the assessment report §6.1 ("Every failure date's most frequent code is `0x80072ee7`") and system security plan Finding 4. Windows client, September 25, 2026. Dates and times are the client's local time. Every failed signature update (event 2001) in Defender's operational log, counted by date and error code:

```
PS C:\Users\winadmin> Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath '*[System[(EventID=2001)]]' | ForEach-Object { $c = if ($_.Message -match 'Error code:\s*(\S+)') { $Matches[1] } else { 'none' }; '{0:yyyy-MM-dd}  {1}' -f $_.TimeCreated, $c } | Group-Object | Format-Table Count,Name -AutoSize

Count Name
----- ----
   12 2026-09-25  0x80072ee7
    1 2026-09-25  0x8024402c
   18 2026-09-24  0x80072ee7
    2 2026-09-24  0x80072f8f
    1 2026-09-24  0x8024402c
   12 2026-09-17  0x80072ee7
    1 2026-09-17  0x80072f8f
    1 2026-09-17  0x8024402c
    6 2026-08-12  0x80072ee7
    1 2026-08-12  0x80072f8f
    6 2026-08-07  0x80072ee7
    1 2026-08-07  0x8024402c
    6 2026-07-28  0x80072ee7
    1 2026-07-28  0x80072f8f
    6 2026-07-23  0x80072ee7
    1 2026-07-23  0x80240438
```

On every date, `0x80072ee7` is the most frequent code; other codes appear once or twice per date. One failure event in full, with version numbers redacted. It is the most recent update event; the ten latest are all failures:

```
PS C:\Users\winadmin> Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath '*[System[(EventID=2000 or EventID=2001)]]' -MaxEvents 10 | Format-List TimeCreated,Id,Message

TimeCreated : 9/25/2026 4:18:06 PM
Id          : 2001
Message     : Microsoft Defender Antivirus has encountered an error trying to update security intelligence.
                New security intelligence Version:
                Previous security intelligence Version: <version>
                Update Source: Microsoft Malware Protection Center
                Security intelligence Type: AntiVirus
                Update Type: Full
                User: NT AUTHORITY\SYSTEM
                Current Engine Version:
                Previous Engine Version: <version>
                Error code: 0x80072ee7
                Error description: The server name or address could not be resolved
```

## 5. Remote-management agent on the Windows client

Supports the assessment report §6.1 ("The remote-management agent also runs, set to start automatically") and system security plan Finding 9. Three records from the Windows client.

The `Get-Service` output of the second command in [section 2](#2-windows-client-model-firmware-date-and-hotfix-list) (September 24, 2026). The query also named `WazuhSvc`, the Wazuh agent service, and returned nothing for it:

```
Name      : A1Agent
Status    : Running
StartType : Automatic
```

The agent's service installation in the System log:

```
$ shasum -a 256 log_System.evtx
4cfa83d2fc5b9087fbf72202831c814e77a2b8e90a1f65c19660fe74fa3fe7e5  log_System.evtx

$ python3 parse_evtx.py log_System.evtx 7045 2026-08-07T07:54 2026-08-07T07:55 ServiceName,ImagePath,StartType,AccountName
EventRecordID | EventID | TimeCreated (UTC, 100-ns) | ServiceName | ImagePath | StartType | AccountName
1667 | 7045 | 2026-08-07T07:54:51.9577096Z | Action1 Agent | C:\Windows\Action1\action1_agent.exe service | auto start | LocalSystem
```

The agent's firewall rules among the client's enabled rules on October 1, 2026 (`state-at-retirement.txt`, lines 2153–2154 and 2157–2159, SHA-256 `949129d4ec0da0fcfa58b7609d13e95ad855a65022ac622734d014e315ac482c`):

```
DisplayName                                                                Direction Action                 Profile
-----------                                                                --------- ------                 -------
[lines 2155–2156 omitted]
Action1 Agent (TCP-In)                                                       Inbound  Allow                     Any
Action1 Agent (UDP-In)                                                       Inbound  Allow                     Any
Action1 Agent LPD (UDP-In)                                                   Inbound  Allow                     Any
```

## 6. AnyDesk download record, remaining firewall rules and the store folder

Supports system security plan Finding 11 and the assessment report §6.1. For Finding 11: the download manager records one completed AnyDesk download from AnyDesk's official address, with the same install path as the service; all eight AnyDesk allow rules remain enabled; AnyDesk itself is no longer installed. For §6.1: the store's folder was created July 22, 2026; AnyDesk rules point to program files that are absent or inside the adware's folder; and the remote desktop rule on TCP 33890 remains, with connections denied and the service stopped.

The PC App Store's download-manager file, `settings\dl_manager.json`, copied from the client on October 1, 2026 (SHA-256 `9440e8d00a151c4f5303692dad5619f20c0d66912cdaba8e4febbcdc962a03df`), in full:

```json
{"completed":[{"dlData":{"appData":{"appId":"73264","dlSource":0,"dmTracking":true,"eventData":{"adGroupId":0,"appId":0,"behavior_ids":[],"bundle_id":0,"campaignId":0,"configId":0,"partnerId":0,"productId":0,"productType":"","strategy_id":"267","trigger":""},"filePath":"%PROGRAMFILES(X86)%\\\\AnyDesk\\\\AnyDesk.exe","hideWindow":false,"isAdmin":2,"name":"Anydesk.exe","oid":467,"params":"","sourceWnd":"store","url":"https://download.anydesk.com/AnyDesk.exe"},"current":8367032,"extendedStatus":5,"progress":0.0,"size":8367032,"status":3,"total":8367032},"installDate":1784757726}],"current":null,"queue":[]}
```

`installDate` 1784757726 is 2026-07-22 22:02:06 UTC (computed, Unix time). `filePath` is the path of the `AnyDesk Service` installed at 22:01:59 UTC ([section 12](#12-adware-delivery-installer-runs-service-installs-and-firewall-rules)), written with the `%PROGRAMFILES(X86)%` variable.

The AnyDesk rows among the client's enabled firewall rules on October 1, 2026 (`state-at-retirement.txt`, lines 2153–2154 and 2162–2169, SHA-256 `949129d4ec0da0fcfa58b7609d13e95ad855a65022ac622734d014e315ac482c`):

```
DisplayName                                                                Direction Action                 Profile
-----------                                                                --------- ------                 -------
[lines 2155–2161 omitted]
AnyDesk                                                                      Inbound  Allow                 Private
AnyDesk                                                                      Inbound  Allow                 Private
AnyDesk                                                                      Inbound  Allow                  Domain
AnyDesk                                                                      Inbound  Allow                  Domain
AnyDesk                                                                      Inbound  Allow                  Domain
AnyDesk                                                                      Inbound  Allow                  Domain
AnyDesk                                                                      Inbound  Allow                 Private
AnyDesk                                                                      Inbound  Allow                 Private
```

September 25, 2026, PowerShell, three pastes in the order run (18:16, 18:18 and 18:22 EDT); from the second and third, only the commands cited are shown. The first line of the second paste lost its leading `P` in copying and is restored here. The folder's creation time is the client's local time.

```
PS C:\Users\winadmin> Get-NetFirewallRule -DisplayName 'RDP-CustomPort' | Get-NetFirewallPortFilter | Format-List Protocol,LocalPort

Protocol  : TCP
LocalPort : 33890

PS C:\Users\winadmin> (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
1
PS C:\Users\winadmin> Get-Service TermService | Format-List Name,Status,StartType

Name      : TermService
Status    : Stopped
StartType : Manual

PS C:\Users\winadmin> Get-NetFirewallRule -DisplayName 'AnyDesk' | Get-NetFirewallApplicationFilter | Select-Object -Unique Program

Program
-------
C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
C:\Program Files (x86)\AnyDesk\AnyDesk.exe
```

```
PS C:\Users\winadmin> Test-Path 'C:\Program Files (x86)\AnyDesk\AnyDesk.exe'
False
[remaining commands of this paste omitted]
```

```
PS C:\Users\winadmin> (Get-Item 'C:\Program Files (x86)\PCAppStore').CreationTime

Wednesday, July 22, 2026 2:48:34 PM

[remaining commands of this paste omitted]
```

At UTC−7, the folder's creation time is 21:48:34 UTC. That is later than the first service installation from the folder (21:44:04 UTC, section 12) and falls between the fourth installer run (21:48:32 UTC) and the second service installation (21:48:35 UTC). The records do not show why the creation time is later than the first installation.

## 7. Exercise file permissions and the unprivileged read

Supports the assessment report §8.1 (all five files returned the same path and read result; the two captures are `-rw-------` and the three text files `-rw-rw-r--`; the group lists no additional members, and no other account exists in the local user range) and system security plan Finding 5. Ubuntu Server, September 26, 2026.

```
labadmin@ubuntu-target:~$ for f in $(sudo find /home -type f \( -name 'plaintext_*' -o -name 'recon_*' \)); do sudo namei -l "$f"; sudo -u nobody cat "$f" > /dev/null && echo "nobody: read succeeded - $f" || echo "nobody: read failed - $f"; done
f: /home/labadmin/plaintext_capture.pcap
drwxr-xr-x root      root      /
drwxr-xr-x root      root      home
drwxr-x--- labadmin labadmin labadmin
-rw------- labadmin labadmin plaintext_capture.pcap
cat: /home/labadmin/plaintext_capture.pcap: Permission denied
nobody: read failed - /home/labadmin/plaintext_capture.pcap
f: /home/labadmin/recon_ssh_traffic.txt
drwxr-xr-x root      root      /
drwxr-xr-x root      root      home
drwxr-x--- labadmin labadmin labadmin
-rw-rw-r-- labadmin labadmin recon_ssh_traffic.txt
cat: /home/labadmin/recon_ssh_traffic.txt: Permission denied
nobody: read failed - /home/labadmin/recon_ssh_traffic.txt
f: /home/labadmin/recon_capture.pcap
drwxr-xr-x root      root      /
drwxr-xr-x root      root      home
drwxr-x--- labadmin labadmin labadmin
-rw------- labadmin labadmin recon_capture.pcap
cat: /home/labadmin/recon_capture.pcap: Permission denied
nobody: read failed - /home/labadmin/recon_capture.pcap
f: /home/labadmin/plaintext_credentials.txt
drwxr-xr-x root      root      /
drwxr-xr-x root      root      home
drwxr-x--- labadmin labadmin labadmin
-rw-rw-r-- labadmin labadmin plaintext_credentials.txt
cat: /home/labadmin/plaintext_credentials.txt: Permission denied
nobody: read failed - /home/labadmin/plaintext_credentials.txt
f: /home/labadmin/recon_nmap_scan.txt
drwxr-xr-x root      root      /
drwxr-xr-x root      root      home
drwxr-x--- labadmin labadmin labadmin
-rw-rw-r-- labadmin labadmin recon_nmap_scan.txt
cat: /home/labadmin/recon_nmap_scan.txt: Permission denied
nobody: read failed - /home/labadmin/recon_nmap_scan.txt
```

```
labadmin@ubuntu-target:~$ getent group labadmin; getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $4}'
labadmin:x:1000:
labadmin 1000 1000
```

## 8. Anonymous account and share listing from the lab segment

Supports the assessment report §8.2 (the anonymous directory search was refused; the anonymous file-service login listed the shares; the anonymous remote procedure call returned all 8 domain user accounts, including the built-in administrator and the Kerberos service account) and system security plan Finding 13. Run from Kali Linux (attack simulation) on the lab segment, outside the boundary, against the Samba DC's lab-segment address, with no username or password; September 26, 2026.

```
┌──(labadmin㉿kali-attacker)-[~]
└─$ which ldapsearch smbclient rpcclient; echo "--- ldapsearch"; ldapsearch -x -H ldap://198.51.100.131 -b "DC=example,DC=test" "(objectClass=user)" sAMAccountName; echo "--- smbclient"; smbclient -L //198.51.100.131 -N; echo "--- rpcclient"; rpcclient -U "" -N 198.51.100.131 -c enumdomusers
/usr/bin/ldapsearch
/usr/bin/smbclient
/usr/bin/rpcclient
--- ldapsearch
# extended LDIF
#
# LDAPv3
# base <DC=example,DC=test> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName
#

# search result
search: 2
result: 1 Operations error
text: 00002020: Operation unavailable without authentication

# numResponses: 1
--- smbclient
Anonymous login successful

Sharename       Type      Comment
---------       ----      -------
sysvol          Disk
netlogon        Disk
IPC$            IPC       IPC Service (<version>)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 198.51.100.131 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
--- rpcclient
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[jsmith] rid:[0x44f]
user:[agarcia] rid:[0x450]
user:[mchen] rid:[0x451]
user:[tjones] rid:[0x454]
user:[rwhite] rid:[0x455]
```

## 9. Domain lockout test, attempt by attempt

Supports the assessment report §9.1 and §9.2. September 27, 2026 (UTC). `<wrong password>` stands for a deliberately wrong password; one was also typed at each `kinit` prompt.

Five Kerberos logons directly against the Samba DC, then the account's counters:

```
dcadmin@samba-dc:~$ for i in 1 2 3 4 5; do echo "=== attempt $i ($(date -u +%T) UTC) ==="; kinit rwhite@EXAMPLE.TEST; done; echo "=== 5 attempts done ($(date -u +%T) UTC) ==="
=== attempt 1 (03:00:16 UTC) ===
Password for rwhite@EXAMPLE.TEST:
kinit: Password incorrect while getting initial credentials
=== attempt 2 (03:00:21 UTC) ===
Password for rwhite@EXAMPLE.TEST:
kinit: Password incorrect while getting initial credentials
=== attempt 3 (03:00:24 UTC) ===
Password for rwhite@EXAMPLE.TEST:
kinit: Password incorrect while getting initial credentials
=== attempt 4 (03:00:26 UTC) ===
Password for rwhite@EXAMPLE.TEST:
kinit: Password incorrect while getting initial credentials
=== attempt 5 (03:00:28 UTC) ===
Password for rwhite@EXAMPLE.TEST:
kinit: Password incorrect while getting initial credentials
=== 5 attempts done (03:00:31 UTC) ===
dcadmin@samba-dc:~$ sudo samba-tool user show rwhite --attributes=badPwdCount,lockoutTime,badPasswordTime; date -u
dn: CN=Robin,OU=IT,DC=example,DC=test
badPwdCount: 5
badPasswordTime: 134349516316057010
lockoutTime: 134349516316057010

Sun Sep 27 03:00:42 AM UTC 2026
```

A clean baseline re-established on the Samba DC:

```
dcadmin@samba-dc:~$ sudo samba-tool user unlock rwhite; sudo samba-tool user show rwhite --attributes=badPwdCount,lockoutTime,badPasswordTime; date -u
dn: CN=Robin,OU=IT,DC=example,DC=test
badPasswordTime: 134349516316057010
lockoutTime: 0
badPwdCount: 0

Sun Sep 27 03:07:57 AM UTC 2026
```

On Ubuntu Server: winbind's connection state, and the first failed logon through its winbind path:

```
labadmin@ubuntu-target:~$ echo "=== winbind state ($(date -u +%T) UTC) ==="; wbinfo --online-status EXAMPLE; echo "=== siem attempt 1 ($(date -u +%T) UTC) ==="; wbinfo -a 'EXAMPLE\rwhite%<wrong password>'; echo "=== end ($(date -u +%T) UTC) ==="
=== winbind state (03:09:22 UTC) ===
BUILTIN : active connection
UBUNTU-TARGET : active connection
EXAMPLE : active connection
=== siem attempt 1 (03:09:22 UTC) ===
plaintext password authentication failed
Could not authenticate user EXAMPLE\rwhite%<wrong password> with plaintext password
challenge/response password authentication failed
Could not authenticate user EXAMPLE\rwhite with challenge/response
=== end (03:09:22 UTC) ===
```

The Samba DC's counter after that one attempt:

```
dcadmin@samba-dc:~$ sudo samba-tool user show rwhite --attributes=badPwdCount,lockoutTime,badPasswordTime; date -u
dn: CN=Robin,OU=IT,DC=example,DC=test
lockoutTime: 0
badPwdCount: 1
badPasswordTime: 134349521621146890

Sun Sep 27 03:10:21 AM UTC 2026
```

Four more failed logons through Ubuntu Server:

```
labadmin@ubuntu-target:~$ for i in 2 3 4 5; do echo "=== siem attempt $i ($(date -u +%T) UTC) ==="; wbinfo -a 'EXAMPLE\rwhite%<wrong password>'; done; echo "=== done ($(date -u +%T) UTC) ==="
=== siem attempt 2 (03:11:55 UTC) ===
plaintext password authentication failed
Could not authenticate user EXAMPLE\rwhite%<wrong password> with plaintext password
challenge/response password authentication failed
Could not authenticate user EXAMPLE\rwhite with challenge/response
=== siem attempt 3 (03:11:55 UTC) ===
plaintext password authentication failed
Could not authenticate user EXAMPLE\rwhite%<wrong password> with plaintext password
challenge/response password authentication failed
Could not authenticate user EXAMPLE\rwhite with challenge/response
=== siem attempt 4 (03:11:55 UTC) ===
plaintext password authentication failed
Could not authenticate user EXAMPLE\rwhite%<wrong password> with plaintext password
challenge/response password authentication failed
Could not authenticate user EXAMPLE\rwhite with challenge/response
=== siem attempt 5 (03:11:55 UTC) ===
plaintext password authentication failed
Could not authenticate user EXAMPLE\rwhite%<wrong password> with plaintext password
challenge/response password authentication failed
Could not authenticate user EXAMPLE\rwhite with challenge/response
=== done (03:11:55 UTC) ===
```

The Samba DC's counters after them:

```
dcadmin@samba-dc:~$ sudo samba-tool user show rwhite --attributes=badPwdCount,lockoutTime,badPasswordTime; date -u
dn: CN=Robin,OU=IT,DC=example,DC=test
badPwdCount: 5
badPasswordTime: 134349523157345630
lockoutTime: 134349523157345630

Sun Sep 27 03:12:06 AM UTC 2026
```

`lockoutTime` counts 100-nanosecond intervals since January 1, 1601 (UTC): 134349516316057010 is 03:00:31.6057010 and 134349523157345630 is 03:11:55.7345630 on September 27, 2026 (computed).

## 10. Cached-logon settings on Ubuntu Server

Supports the assessment report §9.2 (Ubuntu Server is configured for cached domain logons) and system security plan Finding 7. Ubuntu Server, September 28, 2026. `testparm -v` also prints settings left at their defaults.

```
labadmin@ubuntu-target:~$ testparm -s -v 2>/dev/null | grep -iE 'winbind|offline|cache'; grep -n pam_winbind /etc/pam.d/common-auth
cache directory = /var/cache/samba
winbind debug traceid = Yes
getwd cache = Yes
idmap cache time = 604800
idmap negative cache time = 120
lpq cache time = 30
max stat cache size = 512
name cache timeout = 660
printcap cache time = 750
server services = s3fs, rpc, nbt, wrepl, ldap, cldap, kdc, drepl, ft_scanner, winbindd, ntp_signd, kcc, dnsupdate, dns
stat cache = Yes
username map cache time = 0
winbind cache time = 300
winbindd socket directory = /run/samba/winbindd
winbind enum groups = No
winbind enum users = No
winbind expand groups = 0
winbind max clients = 200
winbind max domain connections = 1
winbind nested groups = Yes
winbind normalize names = No
winbind nss info = template
winbind offline logon = Yes
winbind reconnect delay = 30
winbind refresh tickets = Yes
winbind request timeout = 60
winbind rpc only = No
winbind scan trusted domains = No
winbind sealed pipes = Yes
winbind separator = \
winbind use default domain = Yes
winbind use krb5 enterprise principals = Yes
winbind varlink service = No
dfree cache time = 0
18:auth [success=1 default=ignore] pam_winbind.so krb5_auth krb5_ccache_type=FILE cached_login try_first_pass
```

`winbind offline logon = Yes`, and the authentication module line in `common-auth` carries `cached_login`.

## 11. Adware delivery: the browser record

Supports system security plan Finding 11 (a paid Bing search ad led to a third-party download site, and eight seconds later an ad-tagged PC App Store page opened) and shows the store installer's download. The Windows client's Edge history database, copied October 1, 2026, read-only; visits 6 to 11 (visits 1 to 5 are Edge's first-run pages) and the one download. Identifiers in the URLs are replaced with `<id>`, and parameters left out are marked `…`.

```
$ shasum -a 256 Edge_Default_History
a637f92738957dac708905b67ba830f85bcfac6c8ff49f682be552ed679f62c8  Edge_Default_History

$ python3 query_history.py Edge_Default_History 6 11 1
visit | time (UTC) | from_visit | transition core | qualifiers | url | title
6 | 2026-07-22T21:42:43.571292Z | 0 | 7 | 0x30000000 | https://www.bing.com/search?q=anydesk+download&… | https://www.bing.com/search?q=anydesk+download&…
7 | 2026-07-22T21:42:46.549041Z | 0 | 0 | 0x30000000 | https://www.bing.com/aclk?ld=<id>&… |
8 | 2026-07-22T21:42:46.580742Z | 0 | 0 | 0x30000000 | https://www.bing.com/search?q=anydesk+download&… | https://www.bing.com/search?q=anydesk+download&…
9 | 2026-07-22T21:42:46.993950Z | 8 | 0 | 0x60000000 | https://www.popsilla.com/en/pc/anydesk?bingcust=popsilla&msclkid=<id>&utm_source=bing&utm_medium=cpc&… | AnyDesk - Free Download for PC
10 | 2026-07-22T21:42:54.661596Z | 0 | 0 | 0x30000000 | https://cdn.pcappstore.com/lp/lpr.html?ap=adwp&…&gad_source=5&…&gclid=<id> | Download PcAppStore
11 | 2026-07-22T21:42:57.981478Z | 0 | 0 | 0x30000000 | https://cdn.pcappstore.com/lp/downloading2_cdn.html?… | Downloading
id = 1
start_time = 2026-07-22T21:43:01.786072Z
end_time = 2026-07-22T21:43:03.667023Z
target_path = C:\Users\winadmin\Downloads\Setup.exe
received_bytes = 4682128
total_bytes = 4682128
state = 1
danger_type = 4
tab_url = https://cdn.pcappstore.com/lp/downloading2_cdn.html?…
url_chain = blob:https://cdn.pcappstore.com/<id>
```

Meanings, from Chromium's source (Edge is built on Chromium): transition core 7 is `FORM_SUBMIT` and 0 is `LINK`; qualifier bits `0x10000000` `CHAIN_START`, `0x20000000` `CHAIN_END`, `0x40000000` `CLIENT_REDIRECT` ([`page_transition_types.h`](https://github.com/chromium/chromium/blob/main/ui/base/page_transition_types.h)); danger type 4 is `MAYBE_DANGEROUS_CONTENT`, "The content of this download may be malicious (e.g., extension is exe but SafeBrowsing has not finished checking the content)" ([`download_danger_type.h`](https://github.com/chromium/chromium/blob/main/components/download/public/common/download_danger_type.h)). Visit 9, the download site, is recorded 0.444909 seconds after the ad click (visit 7), with the `CLIENT_REDIRECT` qualifier; its `from_visit` is visit 8, a second visit to the search page. Visit 10, the ad-tagged store page (`gad_source`, `gclid`), opens 7.667646 seconds after visit 9 (intervals computed). The downloaded file is the installer whose runs are in [section 12](#12-adware-delivery-installer-runs-service-installs-and-firewall-rules).

## 12. Adware delivery: installer runs, service installs and firewall rules

Supports system security plan Finding 11 (the installer was run four times; AnyDesk ran from the store's download folder and left four inbound allow rules; about twelve minutes later AnyDesk was installed as a service, which left four more). Records copied from the Windows client on October 1, 2026.

Prefetch record of the downloaded installer:

```
$ shasum -a 256 SETUP.EXE-<id>.pf
3ee237c286d61a951037f60c6ea3fd0688e24d351ba8bc32ca38b39a8dc0f458  SETUP.EXE-<id>.pf

$ python3 -c "import pyscca, datetime as d; p = pyscca.open('SETUP.EXE-<id>.pf'); print('run count:', p.run_count); [print('run time %d: %s.%07dZ' % (i, (d.datetime(1601, 1, 1) + d.timedelta(seconds=t // 10**7)).isoformat(), t % 10**7)) for i, t in enumerate(p.get_last_run_time_as_integer(i) for i in range(p.run_count))]"
run count: 4
run time 0: 2026-07-22T21:48:32.9512441Z
run time 1: 2026-07-22T21:48:16.9718857Z
run time 2: 2026-07-22T21:44:03.0811564Z
run time 3: 2026-07-22T21:43:51.7182808Z
```

Service installations (System log, event 7045) on July 22, 2026:

```
$ shasum -a 256 log_System.evtx
4cfa83d2fc5b9087fbf72202831c814e77a2b8e90a1f65c19660fe74fa3fe7e5  log_System.evtx

$ python3 parse_evtx.py log_System.evtx 7045 2026-07-22T21:00 2026-07-22T23:00 ServiceName,ImagePath,StartType,AccountName
EventRecordID | EventID | TimeCreated (UTC, 100-ns) | ServiceName | ImagePath | StartType | AccountName
935 | 7045 | 2026-07-22T21:44:04.6362721Z | PcAppStore Service | C:\Program Files (x86)\PCAppStore\PcAppStoreSRV.exe | auto start | LocalSystem
941 | 7045 | 2026-07-22T21:48:35.2949917Z | PcAppStore Service | C:\Program Files (x86)\PCAppStore\PcAppStoreSRV.exe | auto start | LocalSystem
943 | 7045 | 2026-07-22T22:01:59.9736860Z | AnyDesk Service | "C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service | auto start | LocalSystem
```

Windows Firewall log, events 2097 and 2006 naming AnyDesk:

```
$ shasum -a 256 log_Microsoft-Windows-Windows_Firewall_With_Advanced_Security_Firewall.evtx
8d7c6ae4cc6b22655dc249a59e67eec249bb311e074b18a5b017bdd0865b0e54  log_Microsoft-Windows-Windows_Firewall_With_Advanced_Security_Firewall.evtx

$ python3 parse_evtx.py log_Microsoft-Windows-Windows_Firewall_With_Advanced_Security_Firewall.evtx 2097,2006 2026-07-22T21:49 2026-07-22T22:03 RuleId,RuleName,ApplicationPath,Direction,Action,Protocol,Profiles,ModifyingUser,ModifyingApplication
EventRecordID | EventID | TimeCreated (UTC, 100-ns) | RuleId | RuleName | ApplicationPath | Direction | Action | Protocol | Profiles | ModifyingUser | ModifyingApplication
1079 | 2097 | 2026-07-22T21:49:33.3061696Z | {80703645-03AA-4AC2-99F7-176D7E177388} | AnyDesk | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe | 1 | 3 | 6 | 2 | S-1-5-21-2000000001-2000000002-2000000003-1001 | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
1080 | 2097 | 2026-07-22T21:49:33.3123876Z | {46B669AF-9DD7-4F0F-95D5-1A71B5744058} | AnyDesk | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe | 1 | 3 | 17 | 2 | S-1-5-21-2000000001-2000000002-2000000003-1001 | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
1081 | 2006 | 2026-07-22T21:49:33.5178960Z | {46B669AF-9DD7-4F0F-95D5-1A71B5744058} | AnyDesk | - | - | - | - | - | S-1-5-21-2000000001-2000000002-2000000003-1001 | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
1082 | 2006 | 2026-07-22T21:49:33.5234448Z | {80703645-03AA-4AC2-99F7-176D7E177388} | AnyDesk | - | - | - | - | - | S-1-5-21-2000000001-2000000002-2000000003-1001 | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
1083 | 2097 | 2026-07-22T21:49:33.5349155Z | {A1E9EFD8-4CDC-4DC3-B54B-FA29A19CAE7C} | AnyDesk | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe | 1 | 3 | 6 | 2 | S-1-5-21-2000000001-2000000002-2000000003-1001 | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
1084 | 2097 | 2026-07-22T21:49:33.5542663Z | {D0F46165-DEFB-4FFD-8B62-69D0A017E361} | AnyDesk | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe | 1 | 3 | 17 | 2 | S-1-5-21-2000000001-2000000002-2000000003-1001 | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
1085 | 2097 | 2026-07-22T21:49:33.7658700Z | {30CD37E6-000E-4D26-9198-80554372B2DD} | AnyDesk | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe | 1 | 3 | 6 | 1 | S-1-5-21-2000000001-2000000002-2000000003-1001 | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
1086 | 2097 | 2026-07-22T21:49:33.7703710Z | {F869C014-C8F9-4138-9637-279860B9FB45} | AnyDesk | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe | 1 | 3 | 17 | 1 | S-1-5-21-2000000001-2000000002-2000000003-1001 | C:\Program Files (x86)\PCAppStore\download\Anydesk.exe
1087 | 2097 | 2026-07-22T22:02:05.0853925Z | {BEAC7747-C10E-4FFF-A9F1-B3C8D97C237A} | AnyDesk | C:\Program Files (x86)\AnyDesk\AnyDesk.exe | 1 | 3 | 6 | 2 | S-1-5-18 | C:\Program Files (x86)\AnyDesk\AnyDesk.exe
1088 | 2097 | 2026-07-22T22:02:05.0997867Z | {C4B959BE-1F64-4C72-886E-29738B5D8474} | AnyDesk | C:\Program Files (x86)\AnyDesk\AnyDesk.exe | 1 | 3 | 17 | 2 | S-1-5-18 | C:\Program Files (x86)\AnyDesk\AnyDesk.exe
1089 | 2006 | 2026-07-22T22:02:05.3337131Z | {C4B959BE-1F64-4C72-886E-29738B5D8474} | AnyDesk | - | - | - | - | - | S-1-5-18 | C:\Program Files (x86)\AnyDesk\AnyDesk.exe
1090 | 2006 | 2026-07-22T22:02:05.3528579Z | {BEAC7747-C10E-4FFF-A9F1-B3C8D97C237A} | AnyDesk | - | - | - | - | - | S-1-5-18 | C:\Program Files (x86)\AnyDesk\AnyDesk.exe
1091 | 2097 | 2026-07-22T22:02:05.3712181Z | {DC457AA8-9B90-4A7D-BDF1-D1A6E558EBB9} | AnyDesk | C:\Program Files (x86)\AnyDesk\AnyDesk.exe | 1 | 3 | 6 | 2 | S-1-5-18 | C:\Program Files (x86)\AnyDesk\AnyDesk.exe
1092 | 2097 | 2026-07-22T22:02:05.3796177Z | {287E1DF9-FF79-475E-AB3B-B52010A0FC57} | AnyDesk | C:\Program Files (x86)\AnyDesk\AnyDesk.exe | 1 | 3 | 17 | 2 | S-1-5-18 | C:\Program Files (x86)\AnyDesk\AnyDesk.exe
1093 | 2097 | 2026-07-22T22:02:05.6193272Z | {147D3FD8-8BE0-4DC6-89E2-D7B209DADB69} | AnyDesk | C:\Program Files (x86)\AnyDesk\AnyDesk.exe | 1 | 3 | 6 | 1 | S-1-5-18 | C:\Program Files (x86)\AnyDesk\AnyDesk.exe
1094 | 2097 | 2026-07-22T22:02:05.6236582Z | {0F07270E-D25A-4C48-B1DF-75EA2C8623E7} | AnyDesk | C:\Program Files (x86)\AnyDesk\AnyDesk.exe | 1 | 3 | 17 | 1 | S-1-5-18 | C:\Program Files (x86)\AnyDesk\AnyDesk.exe
```

Each 2097 record carries a new rule's settings. Each 2006 record names, by its `RuleId`, a rule added a moment earlier but carries none of its settings; Microsoft does not document these event IDs, but the count that follows matches the client's rule listing of October 1, 2026. At 21:49:33 the store's downloaded `Anydesk.exe` (`ModifyingApplication`) added six rules under the client's administrator account (RID 1001), and two of their IDs then appear in 2006 records, leaving four whose program is that file. The AnyDesk service was installed 12 minutes 26.7 seconds after those first rules; at 22:02:05, 5.1 seconds after it, the same pattern left four more for the installed AnyDesk, created by `S-1-5-18` (SYSTEM) (intervals computed). Direction 1 is inbound ([`FW_DIRECTION`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/34806362-c31f-4531-ad8c-5a43d5870223)) and action 3 is allow ([`FW_RULE_ACTION`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/702e3c23-c9d8-43db-8380-b4c670dd7f7d)); protocol 6 is TCP and 17 is UDP; profile 1 is Domain and 2 is Private ([`NET_FW_PROFILE_TYPE2`](https://learn.microsoft.com/en-us/windows/win32/api/icftypes/ne-icftypes-net_fw_profile_type2)). The eight rules left are the eight AnyDesk rules enabled on October 1, 2026, four Private and four Domain ([section 6](#6-anydesk-download-record-remaining-firewall-rules-and-the-store-folder)).

## 13. The August 7 disconnect and the September 25 default route

Supports system security plan Finding 10 (an earlier disconnect was verified only within its session and did not persist) and plan of action and milestones entry P-07. Windows client, PowerShell.

**August 7, 2026 — terminal output pasted at the time, from an earlier working record.** The default route deleted, then the route table and the output of a connection test to a public address (its command line was not in the paste):

```
PS C:\Users\winadmin> route delete 0.0.0.0 mask 0.0.0.0 192.0.2.254
 OK!
PS C:\Users\winadmin> route print -4
[Interface List omitted]

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
      192.0.2.0    255.255.255.0         On-link     192.0.2.240    301
    192.0.2.240  255.255.255.255         On-link     192.0.2.240    301
    192.0.2.255  255.255.255.255         On-link     192.0.2.240    301
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link     192.0.2.240    301
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link     192.0.2.240    301
===========================================================================
Persistent Routes:
  None
PS C:\Users\winadmin>
```

```
WARNING: Ping to 8.8.8.8 failed

ComputerName          : 8.8.8.8
RemoteAddress         : 8.8.8.8
NameResolutionResults : 8.8.8.8
InterfaceAlias        :
SourceAddress         :
NetRoute (NextHop)    :
PingSucceeded         : False
```

**September 25, 2026.** The default route in the active store and in the persistent store, then the route table:

```
PS C:\Users\winadmin> Get-NetRoute -DestinationPrefix 0.0.0.0/0 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Format-Table InterfaceAlias,NextHop,RouteMetric

InterfaceAlias NextHop       RouteMetric
-------------- -------       -----------
Wi-Fi          192.0.2.254           0

PS C:\Users\winadmin> Get-NetRoute -DestinationPrefix 0.0.0.0/0 -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Format-Table InterfaceAlias,NextHop,RouteMetric
PS C:\Users\winadmin> route print -4
[Interface List omitted]

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0    192.0.2.254    192.0.2.240     45
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
      192.0.2.0    255.255.255.0         On-link     192.0.2.240    301
    192.0.2.240  255.255.255.255         On-link     192.0.2.240    301
    192.0.2.255  255.255.255.255         On-link     192.0.2.240    301
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link     192.0.2.240    301
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link     192.0.2.240    301
===========================================================================
Persistent Routes:
  None
```

On August 7, after the deletion, the table held no default route and no persistent route, and the test failed. On September 25 a default route through the home gateway was in the active store again, the persistent-store query returned nothing, and the table listed no persistent route.

## 14. Boot Camp on the Windows client

Supports system security plan §9 (the Windows client's hardware: an Apple Mac mini running Windows through Boot Camp). Records from the Windows client.

Installed software on October 1, 2026 (`state-at-retirement.txt`, lines 16–20, SHA-256 `949129d4ec0da0fcfa58b7609d13e95ad855a65022ac622734d014e315ac482c`), with the version redacted, and a running service (lines 300–305):

```
DisplayName     : Boot Camp Services
DisplayVersion  : <version>
Publisher       : Apple Inc.
InstallDate     : 20260722
InstallLocation : C:\Program Files\Boot Camp\
```

```
Name        : AppleOSSMgr
DisplayName : Apple OS Switch Manager
State       : Running
StartMode   : Auto
StartName   : LocalSystem
PathName    : C:\Windows\system32\AppleOSSMgr.exe
```

An autostart registry entry (October 1, 2026; `adware-investigation.txt`, lines 101 and 104–105, SHA-256 `24d1dabbcbe1fc33dc0271ff6e93cdb978b8093d0fa7a23b4781bc1ffaf74b9f`):

```
[HKLM:\Software\Microsoft\Windows\CurrentVersion\Run]
SecurityHealth : C:\Windows\system32\SecurityHealthSystray.exe
Apple_KbdMgr   : C:\Program Files\Boot Camp\Bootcamp.exe
```

Service and driver installations on July 23, 2026, including a driver installed from a `BootCamp\Drivers` folder and the Apple OS Switch Manager service above:

```
$ shasum -a 256 log_System.evtx
4cfa83d2fc5b9087fbf72202831c814e77a2b8e90a1f65c19660fe74fa3fe7e5  log_System.evtx

$ python3 parse_evtx.py log_System.evtx 7045 2026-07-23T01:12 2026-07-23T01:15 ServiceName,ImagePath,StartType
EventRecordID | EventID | TimeCreated (UTC, 100-ns) | ServiceName | ImagePath | StartType
273 | 7045 | 2026-07-23T01:12:02.1945651Z | AtiDCM | D:\BootCamp\Drivers\AMD\AMDGraphics\Bin64\atdcm64a.sys | demand start
275 | 7045 | 2026-07-23T01:12:55.9732376Z | Broadcom 802.11 Network Adapter Driver | \SystemRoot\system32\DRIVERS\bcmwl63a.sys | demand start
281 | 7045 | 2026-07-23T01:12:57.5201109Z | Virtual WiFi Miniport Service | \SystemRoot\System32\drivers\vwifimp.sys | demand start
282 | 7045 | 2026-07-23T01:13:05.6004242Z | bScsiSDa | \SystemRoot\System32\drivers\bScsiSDa.sys | demand start
284 | 7045 | 2026-07-23T01:13:13.7009827Z | CS42xxLowerFilter | \SystemRoot\system32\DRIVERS\CSLFD.sys | demand start
286 | 7045 | 2026-07-23T01:13:13.7166075Z | CS42xxUpperFilter | \SystemRoot\system32\DRIVERS\CSUFD.sys | demand start
288 | 7045 | 2026-07-23T01:13:17.5134767Z | IR Receiver Filter Driver | \SystemRoot\System32\drivers\IRFilter.sys | demand start
292 | 7045 | 2026-07-23T01:14:11.8916069Z | Intel(R) HD Graphics Control Panel Service | %SystemRoot%\system32\igfxCUIService.exe | auto start
295 | 7045 | 2026-07-23T01:14:16.8889677Z | Apple OS Switch Manager | C:\Windows\system32\AppleOSSMgr.exe | auto start
296 | 7045 | 2026-07-23T01:14:16.9045930Z | KeyAgent | C:\Windows\system32\drivers\KeyAgent.sys | auto start
297 | 7045 | 2026-07-23T01:14:16.9202178Z | Mac HAL | C:\Windows\system32\drivers\MacHALDriver.sys | system start
```

[Section 2](#2-windows-client-model-firmware-date-and-hotfix-list) gives the model identifier, `Macmini7,1`.

## 15. SSH administration of the Windows client

Supports system security plan §2 (the operator administers every component over SSH) and the assessment report §6 (the Windows client's evidence was gathered over SSH). The Windows client's OpenSSH log, copied October 1, 2026: every accepted login it records.

```
$ shasum -a 256 log_OpenSSH_Operational.evtx
f74450d4256c04e456dd1abbc282ac2c8233e02478de9cc47631dfb3b62a60ee  log_OpenSSH_Operational.evtx

$ python3 parse_evtx.py log_OpenSSH_Operational.evtx 4 2026-01-01 2027-01-01 payload payload=Accepted
EventRecordID | EventID | TimeCreated (UTC, 100-ns) | payload
989 | 4 | 2026-08-12T19:32:19.1595027Z | Accepted password for winadmin from 192.0.2.180 port 49347 ssh2
992 | 4 | 2026-08-12T19:41:20.6080251Z | Accepted password for winadmin from 192.0.2.180 port 49356 ssh2
995 | 4 | 2026-08-12T19:41:24.7642983Z | Accepted password for winadmin from 192.0.2.180 port 49357 ssh2
1728 | 4 | 2026-09-17T20:36:45.7070403Z | Accepted password for winadmin from 192.0.2.180 port 49676 ssh2
2462 | 4 | 2026-09-24T22:24:11.1325271Z | Accepted password for winadmin from 192.0.2.180 port 49504 ssh2
2466 | 4 | 2026-09-26T00:14:24.2294045Z | Accepted password for winadmin from 192.0.2.180 port 50218 ssh2
2467 | 4 | 2026-09-26T00:37:10.6076196Z | Accepted password for winadmin from 192.0.2.180 port 50272 ssh2
2468 | 4 | 2026-09-26T00:47:37.3294687Z | Accepted password for winadmin from 192.0.2.180 port 50288 ssh2
2469 | 4 | 2026-09-26T01:19:25.2736096Z | Accepted password for winadmin from 192.0.2.180 port 50367 ssh2
2472 | 4 | 2026-09-26T01:35:45.6237090Z | Accepted password for winadmin from 192.0.2.180 port 50417 ssh2
3205 | 4 | 2026-09-28T20:34:07.2920135Z | Accepted password for winadmin from 192.0.2.180 port 51742 ssh2
3209 | 4 | 2026-09-28T23:54:01.2524301Z | Accepted password for winadmin from 192.0.2.180 port 52140 ssh2
3213 | 4 | 2026-09-30T05:14:42.9140528Z | Accepted password for winadmin from 192.0.2.180 port 50447 ssh2
3217 | 4 | 2026-10-01T08:46:32.5306726Z | Accepted password for winadmin from 192.0.2.180 port 49347 ssh2
3218 | 4 | 2026-10-01T09:06:47.0671529Z | Accepted password for winadmin from 192.0.2.180 port 49350 ssh2
3219 | 4 | 2026-10-01T09:11:42.1080043Z | Accepted password for winadmin from 192.0.2.180 port 49351 ssh2
3222 | 4 | 2026-10-01T09:14:55.3366422Z | Accepted password for winadmin from 192.0.2.180 port 49353 ssh2
3225 | 4 | 2026-10-01T09:35:12.0651833Z | Accepted password for winadmin from 192.0.2.180 port 49665 ssh2
```

All 18 accepted logins are password logins to the client's administrator account from 192.0.2.180, the MacBook Air's home-network address. The log's oldest record is from August 12, 2026, 19:23 UTC; earlier logins are not in it. In EDT (UTC−4), the logins dated 2026-09-26 00:14–01:35 UTC fall on the evening of September 25, the session the assessment report cites. The client's clock was not exact; if the true times were earlier, they still fall on that evening.
