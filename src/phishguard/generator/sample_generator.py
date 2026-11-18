"""
Synthetic Phishing & Benign Email Generator for Detection Engineering and Red Teaming.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid


class SampleGenerator:
    """
    Generates synthetic RFC 5322 compliant .eml files across multiple threat scenarios:
    - credential-harvest: Deceptive hyperlink mismatch and domain typosquatting
    - bec: Executive wire transfer lure with Display Name & Reply-To mismatch
    - quishing: QR code authentication lure with embedded image tag
    - macro-invoice: Weaponized double-extension attachment payload
    - benign: Clean transactional newsletter with valid authentication
    """

    SUPPORTED_LURES = ["credential-harvest", "bec", "quishing", "macro-invoice", "benign"]

    def generate(
        self,
        lure_type: str,
        recipient: str = "target-employee@enterprise.corp",
        output_path: Optional[Path] = None,
    ) -> str:
        """Generate synthetic .eml raw text string."""
        lure = lure_type.lower().strip()
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a, %d %b %Y %H:%M:%S +0000")
        msg_id = f"<{uuid.uuid4().hex[:12]}.gen@phishguard-sim.local>"

        if lure in ("credential-harvest", "cred"):
            content = self._generate_credential_harvest(recipient, date_str, msg_id)
        elif lure == "bec":
            content = self._generate_bec(recipient, date_str, msg_id)
        elif lure == "quishing":
            content = self._generate_quishing(recipient, date_str, msg_id)
        elif lure in ("macro-invoice", "invoice", "attachment"):
            content = self._generate_macro_invoice(recipient, date_str, msg_id)
        elif lure == "benign":
            content = self._generate_benign(recipient, date_str, msg_id)
        else:
            raise ValueError(f"Unsupported lure type '{lure_type}'. Supported: {', '.join(self.SUPPORTED_LURES)}")

        if output_path:
            p = Path(output_path).resolve()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")

        return content

    def _generate_credential_harvest(self, to_addr: str, date_str: str, msg_id: str) -> str:
        boundary = f"----=_Part_{uuid.uuid4().hex[:12]}"
        return f"""From: "Microsoft Security Office" <security-alert@micros0ft-support.com>
To: {to_addr}
Subject: CRITICAL: Unauthorized login attempt detected on your Office 365 account
Date: {date_str}
Message-ID: {msg_id}
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="{boundary}"
Reply-To: harvest-receiver@external-stealer.xyz
Return-Path: <bounce@micros0ft-support.com>
Authentication-Results: mx.enterprise.corp;
    spf=fail (sender IP is 195.123.45.67) smtp.mailfrom=bounce@micros0ft-support.com;
    dkim=neutral;
    dmarc=fail action=none header.from=micros0ft-support.com
Received: from relay.micros0ft-support.com (195.123.45.67)
    by mx.enterprise.corp with ESMTPS id 9K8812; {date_str}

--{boundary}
Content-Type: text/plain; charset=UTF-8

Dear User,

We detected an unauthorized sign-in attempt from an unrecognized IP address.
Your account access has been restricted.

Please verify your credentials immediately within 24 hours to prevent permanent account suspension:
https://login.microsoftonline.com/common/oauth2/v2.0/authorize

Microsoft 365 Security Team

--{boundary}
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <h2>Urgent: Account Limited</h2>
  <p>An unauthorized login was detected from Russia on your corporate account.</p>
  <p>To prevent suspension, please confirm your identity immediately:</p>
  <!-- Deceptive Link -->
  <p><a href="http://195.123.45.67/owa/auth/login.php?user={to_addr}">https://login.microsoftonline.com/common/oauth2/v2.0/authorize</a></p>
  <p>Or verify via mirror: <a href="http://bit.ly/msft-auth-token">http://bit.ly/msft-auth-token</a></p>
</body>
</html>
--{boundary}--
"""

    def _generate_bec(self, to_addr: str, date_str: str, msg_id: str) -> str:
        return f"""From: "Tim Cook <CEO>" <ceo-urgent-dispatch@gmail-external-relay.com>
To: {to_addr}
Subject: URGENT & CONFIDENTIAL: Time-Sensitive Wire Transfer Required
Date: {date_str}
Message-ID: {msg_id}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Reply-To: executive-finance-liaison@stealth-acquisitions.xyz
Authentication-Results: mx.enterprise.corp;
    spf=softfail;
    dkim=none;
    dmarc=none

Are you available at your desk right now?

I am in a closed-door acquisition meeting and need an urgent wire transfer processed before 3:00 PM today for our escrow reserve.

Please confirm receipt immediately so I can provide the settlement beneficiary details. Do not contact me by phone as I am speaking to regulators.

Regards,
Tim Cook
Chief Executive Officer
"""

    def _generate_quishing(self, to_addr: str, date_str: str, msg_id: str) -> str:
        boundary = f"----=_Part_{uuid.uuid4().hex[:12]}"
        return f"""From: "IT Identity Protection" <mfa-upgrade@corp-identity-sync.com>
To: {to_addr}
Subject: Action Required: Mandatory Authenticator QR Code Sync
Date: {date_str}
Message-ID: {msg_id}
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="{boundary}"
Reply-To: tokens@bad-phish.xyz
Authentication-Results: mx.enterprise.corp;
    spf=fail;
    dkim=none;
    dmarc=fail

--{boundary}
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <h3>Corporate MFA Token Expiration</h3>
  <p>Your Multi-Factor Authentication token expires today. To avoid being locked out of enterprise services, scan this QR code immediately with your mobile authenticator app:</p>
  <img src="cid:qr_auth.png" id="auth-qr-code" alt="Scan QR Code to Update MFA" />
  <p>Failure to scan within 24 hours will result in account lockout.</p>
</body>
</html>
--{boundary}--
"""

    def _generate_macro_invoice(self, to_addr: str, date_str: str, msg_id: str) -> str:
        boundary = f"----=_Part_{uuid.uuid4().hex[:12]}"
        return f"""From: "Global Logistics Billing" <billing@logistics-freight.com>
To: {to_addr}
Subject: FINAL NOTICE: Past Due Invoice #89218 Attached
Date: {date_str}
Message-ID: {msg_id}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"
Authentication-Results: mx.enterprise.corp;
    spf=fail;
    dkim=none;
    dmarc=fail

--{boundary}
Content-Type: text/plain; charset=UTF-8

Please find attached the past due invoice statement. Remit payment immediately to avoid collection action.

--{boundary}
Content-Type: application/octet-stream; name="Overdue_Invoice_Statement.pdf.exe"
Content-Disposition: attachment; filename="Overdue_Invoice_Statement.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAsAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g
RE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--{boundary}--
"""

    def _generate_benign(self, to_addr: str, date_str: str, msg_id: str) -> str:
        boundary = f"----=_Part_{uuid.uuid4().hex[:12]}"
        return f"""From: "Engineering Weekly" <newsletter@devweekly.org>
To: {to_addr}
Subject: Developer Weekly Digest #88: System Architecture Best Practices
Date: {date_str}
Message-ID: {msg_id}
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="{boundary}"
Reply-To: feedback@devweekly.org
Return-Path: <bounces@devweekly.org>
Authentication-Results: mx.enterprise.corp;
    spf=pass (sender IP is 198.51.100.40) smtp.mailfrom=bounces@devweekly.org;
    dkim=pass header.i=@devweekly.org;
    dmarc=pass action=none header.from=devweekly.org
Received: from mail.devweekly.org (198.51.100.40)
    by mx.enterprise.corp with ESMTPS id 33A19; {date_str}

--{boundary}
Content-Type: text/plain; charset=UTF-8

Welcome to Developer Weekly #88!
Read articles on our portal: https://devweekly.org/issues/88

To unsubscribe, visit https://devweekly.org/unsubscribe

--{boundary}
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <h2>Developer Weekly #88</h2>
  <p>Here are this week's top engineering insights and architecture guides.</p>
  <p><a href="https://devweekly.org/issues/88">Read Issue #88</a></p>
  <p><small><a href="https://devweekly.org/unsubscribe">Unsubscribe</a></small></p>
</body>
</html>
--{boundary}--
"""
