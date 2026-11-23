"""
Automated SOAR remediation script and incident response playbook generator.
Synthesizes platform-specific containment commands for M365, Google Workspace, EDR, and Firewalls.
"""

import json
from typing import Optional

from phishguard.models.report import ScanResult
from phishguard.soar.models import PlatformType, RemediationAction, RemediationPackage


class RemediationEngine:
    """
    Generates actionable, production-ready remediation scripts from forensic scan results.
    """

    def generate_package(
        self,
        result: ScanResult,
        platforms: Optional[list[PlatformType]] = None,
    ) -> RemediationPackage:
        """Constructs an integrated multi-platform containment package."""
        target_platforms = platforms or [PlatformType.ALL]
        include_all = PlatformType.ALL in target_platforms

        subject = result.metadata.subject.replace('"', '\\"')
        sender = result.metadata.from_email or result.metadata.from_raw
        sender_domain = result.metadata.from_domain or (sender.split("@")[-1] if "@" in sender else "")
        orig_ip = result.headers.originating_ip
        scan_id = result.scan_id

        # Collect unique defanged/raw URLs and domains
        raw_urls = [u.raw_url for u in result.urls if u.threat_intel_flagged or u.risk_score >= 25]
        malicious_domains = list(dict.fromkeys([u.domain for u in result.urls if u.domain]))
        attachment_hashes = [a.sha256 for a in result.attachments if a.sha256]

        actions: list[RemediationAction] = []

        # 1. Microsoft 365 / Exchange Online
        if include_all or PlatformType.M365 in target_platforms:
            # A. Compliance Purge Search
            purge_script = f"""# Microsoft 365 Compliance Search & Hard-Delete Purge Playbook
# Incident: {scan_id} | Target: {sender}
Connect-IPPSSession

$SearchName = "PG-Purge-{scan_id}"
$Query = '(Subject:"{subject}") AND (From:"{sender}")'

Write-Host "Creating Compliance Search: $SearchName..." -ForegroundColor Cyan
New-ComplianceSearch -Name $SearchName -ExchangeLocation All -ContentMatchQuery $Query
Start-ComplianceSearch -Identity $SearchName

# Wait for search completion and execute hard-purge
do {{
    Start-Sleep -Seconds 5
    $Search = Get-ComplianceSearch -Identity $SearchName
    Write-Host "Search Status: $($Search.Status)..."
}} while ($Search.Status -ne "Completed")

Write-Host "Purging malicious messages from all recipient mailboxes..." -ForegroundColor Yellow
New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete -Confirm:$false
Write-Host "Purge action initiated successfully." -ForegroundColor Green
"""
            actions.append(
                RemediationAction(
                    name="M365 Exchange Online Hard-Delete Purge",
                    platform=PlatformType.M365,
                    category="purge",
                    language="powershell",
                    description="Searches all organization mailboxes and permanently purges matching phishing messages.",
                    code=purge_script.strip(),
                )
            )

            # B. Tenant Allow/Block List (TABL) Block
            tabl_blocks = []
            if sender:
                tabl_blocks.append(
                    f'New-TenantAllowBlockListItems -ListType Sender -Block -Entries "{sender}" '
                    f'-ExpirationDate (Get-Date).AddDays(90) -Notes "PhishGuard {scan_id}"'
                )
            for u in raw_urls[:5]:
                tabl_blocks.append(
                    f'New-TenantAllowBlockListItems -ListType Url -Block -Entries "{u}" '
                    f'-ExpirationDate (Get-Date).AddDays(90) -Notes "PhishGuard {scan_id}"'
                )

            if tabl_blocks:
                tabl_code = "# Microsoft 365 Tenant Allow/Block List (TABL) Enforcement\n" + "\n".join(tabl_blocks)
                actions.append(
                    RemediationAction(
                        name="M365 Tenant Allow/Block List (TABL) Ingestion",
                        platform=PlatformType.M365,
                        category="blocklist",
                        language="powershell",
                        description="Injects sender address and malicious URLs into Microsoft 365 Defender global block list.",
                        code=tabl_code.strip(),
                    )
                )

        # 2. Google Workspace (GAM)
        if include_all or PlatformType.GOOGLE_WORKSPACE in target_platforms:
            msg_id_clause = f'rfc822msgid:{result.metadata.message_id}' if result.metadata.message_id else f'from:{sender} subject:"{subject}"'
            gam_script = f"""#!/usr/bin/env bash
# Google Workspace GAM Mailbox Purge Script
# Incident: {scan_id}

echo "[*] Purging phishing message across all Google Workspace accounts..."
gam all users delete messages query '{msg_id_clause}' doit

echo "[+] GAM purge sequence completed."
"""
            actions.append(
                RemediationAction(
                    name="Google Workspace GAM Global Message Purge",
                    platform=PlatformType.GOOGLE_WORKSPACE,
                    category="purge",
                    language="bash",
                    description="Uses Google Apps Manager (GAM) to locate and delete the phishing email from all domain inboxes.",
                    code=gam_script.strip(),
                )
            )

        # 3. EDR Threat Hunting (Defender KQL & CrowdStrike)
        if include_all or PlatformType.EDR_HUNTING in target_platforms:
            kql_hashes = json.dumps(attachment_hashes)
            kql_domains = json.dumps(malicious_domains)

            defender_kql = f"""// Microsoft Defender 365 Advanced Hunting Query
// Incident: {scan_id} | Threat Detection & Lateral Movement
let MaliciousHashes = dynamic({kql_hashes});
let TargetDomains = dynamic({kql_domains});

// 1. Process Execution matching weaponized attachments
DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in (MaliciousHashes)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine

// 2. Outbound Network Connections to Phishing Domains
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (TargetDomains)
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
"""
            actions.append(
                RemediationAction(
                    name="Microsoft Defender Advanced Hunting (KQL)",
                    platform=PlatformType.EDR_HUNTING,
                    category="hunting",
                    language="kql",
                    description="Queries Defender telemetry for endpoint execution of attachment SHA256 hashes or connections to attacker domains.",
                    code=defender_kql.strip(),
                )
            )

            crowdstrike_hashes = " ".join([f'"{h}"' for h in attachment_hashes]) or '""'
            crowdstrike_domains = " ".join([f'"{d}"' for d in malicious_domains]) or '""'
            crowdstrike_query = f"""# CrowdStrike Falcon LogScale / Event Search
# Incident: {scan_id}
event_simpleName IN (ProcessRollup2, NetworkConnectIP4) 
(SHA256HashData IN ({crowdstrike_hashes}) OR DomainName IN ({crowdstrike_domains}))
| table _time ComputerName UserName ImageFileName CommandLine RemoteAddress RemoteUrl
"""
            actions.append(
                RemediationAction(
                    name="CrowdStrike Falcon Event Query",
                    platform=PlatformType.EDR_HUNTING,
                    category="hunting",
                    language="text",
                    description="Searches Falcon endpoint telemetry for process creation or network connection to detected indicators.",
                    code=crowdstrike_query.strip(),
                )
            )

        # 4. Perimeter Firewalls & DNS Sinkhole
        if include_all or PlatformType.PERIMETER_FIREWALL in target_platforms:
            fw_commands = []
            if orig_ip:
                fw_commands.append(f"# Palo Alto Networks CLI Block")
                fw_commands.append(f'set address "PHISH_SRC_{orig_ip.replace(".", "_")}" ip-netmask {orig_ip}/32 description "PhishGuard {scan_id}"')
                fw_commands.append(f'set address-group "PHISHGUARD_BLOCKLIST" static "PHISH_SRC_{orig_ip.replace(".", "_")}"')
                fw_commands.append(f"commit\n")

                fw_commands.append(f"# Cisco ASA CLI Drop Rule")
                fw_commands.append(f"access-list OUTSIDE_IN deny ip host {orig_ip} any")

            if malicious_domains:
                fw_commands.append(f"\n# BIND9 / DNS Response Policy Zone (RPZ) Sinkhole Records")
                for d in malicious_domains:
                    fw_commands.append(f"{d} CNAME .\n*.{d} CNAME .")

            if fw_commands:
                actions.append(
                    RemediationAction(
                        name="Perimeter Firewall & DNS Sinkhole Block Rules",
                        platform=PlatformType.PERIMETER_FIREWALL,
                        category="sinkhole",
                        language="text",
                        description="Applies perimeter firewall drop rules for attacker IP and DNS sinkhole records for target domains.",
                        code="\n".join(fw_commands).strip(),
                    )
                )

        return RemediationPackage(
            scan_id=scan_id,
            timestamp=result.timestamp.isoformat(),
            verdict=result.verdict.value,
            severity=result.severity.value,
            target_subject=result.metadata.subject,
            sender_email=sender,
            sender_domain=sender_domain,
            originating_ip=orig_ip,
            malicious_urls=raw_urls,
            attachment_hashes=attachment_hashes,
            actions=actions,
        )
