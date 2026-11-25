"""Unit and integration tests for DNS SPF and DMARC policy validation."""

import pytest
from phishguard.forensics.dns_validator import (
    DnsPolicyValidator,
    DomainDnsInspection,
    DmarcValidationResult,
    SpfValidationResult,
)


def test_evaluate_spf_authorized_ip4():
    """Verify SPF authorization when originating IP matches CIDR network."""
    domain = "enterprise.corp"
    mock_db = {
        domain: ["v=spf1 ip4:198.51.100.0/24 include:_spf.google.com -all"]
    }
    res = DnsPolicyValidator.evaluate_spf(domain, originating_ip="198.51.100.23", mock_records=mock_db)

    assert res.has_spf is True
    assert res.ip_authorized is True
    assert res.qualifier == "+"
    assert "ip4:198.51.100.0/24" in res.mechanism_matched


def test_evaluate_spf_unauthorized_ip4():
    """Verify SPF failure when originating IP is outside authorized range."""
    domain = "secure-bank.com"
    mock_db = {
        domain: ["v=spf1 ip4:192.0.2.0/24 -all"]
    }
    res = DnsPolicyValidator.evaluate_spf(domain, originating_ip="203.0.113.5", mock_records=mock_db)

    assert res.has_spf is True
    assert res.ip_authorized is False
    assert res.qualifier == "-"


def test_evaluate_spf_permissive_warning():
    """Verify warning generated on dangerous '+all' SPF mechanism."""
    domain = "vulnerable-domain.xyz"
    mock_db = {
        domain: ["v=spf1 +all"]
    }
    res = DnsPolicyValidator.evaluate_spf(domain, originating_ip="1.2.3.4", mock_records=mock_db)

    assert res.has_spf is True
    assert any("+all" in w for w in res.warnings)


def test_evaluate_spf_missing():
    """Verify missing SPF handling."""
    res = DnsPolicyValidator.evaluate_spf("nonexistent-domain.xyz", originating_ip="1.2.3.4", mock_records={})
    assert res.has_spf is False
    assert len(res.warnings) > 0


def test_evaluate_dmarc_reject_policy():
    """Verify parsing of strict DMARC reject policy."""
    domain = "enterprise.corp"
    mock_db = {
        f"_dmarc.{domain}": ["v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@enterprise.corp"]
    }
    res = DnsPolicyValidator.evaluate_dmarc(domain, mock_records=mock_db)

    assert res.has_dmarc is True
    assert res.policy == "reject"
    assert res.subdomain_policy == "reject"
    assert res.percentage == 100
    assert "mailto:dmarc-reports@enterprise.corp" in res.rua
    assert len(res.warnings) == 0


def test_evaluate_dmarc_none_policy_warning():
    """Verify warning generated when DMARC policy is set to monitoring-only (none)."""
    domain = "unprotected-domain.com"
    mock_db = {
        f"_dmarc.{domain}": ["v=DMARC1; p=none; rua=mailto:test@unprotected-domain.com"]
    }
    res = DnsPolicyValidator.evaluate_dmarc(domain, mock_records=mock_db)

    assert res.has_dmarc is True
    assert res.policy == "none"
    assert any("p=none" in w for w in res.warnings)


def test_evaluate_dmarc_missing():
    """Verify missing DMARC handling."""
    res = DnsPolicyValidator.evaluate_dmarc("missing-dmarc.org", mock_records={})
    assert res.has_dmarc is False
    assert res.policy == "none"
    assert len(res.warnings) > 0


def test_inspect_domain_end_to_end_mock():
    """Verify overall DomainDnsInspection scoring and risk reasoning."""
    domain = "spoof-target.com"
    mock_db = {
        domain: ["v=spf1 ip4:10.0.0.0/8 -all"],
        f"_dmarc.{domain}": ["v=DMARC1; p=none"],
        f"MX:{domain}": ["mail.spoof-target.com"],
    }
    # Originating IP outside SPF range, DMARC is none
    inspection = DnsPolicyValidator.inspect_domain(
        domain,
        originating_ip="198.51.100.99",
        mock_records=mock_db,
    )

    assert isinstance(inspection, DomainDnsInspection)
    assert inspection.risk_score > 30.0
    assert len(inspection.risk_reasons) > 0
    assert any("SPF" in r for r in inspection.risk_reasons)
