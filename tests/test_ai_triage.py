"""Unit and integration tests for AI intent triage and cognitive heuristics."""

from pathlib import Path
import pytest

from phishguard.ai.models import (
    AiTriageResult,
    EmailIntentEnum,
    PsychologicalTacticEnum,
)
from phishguard.ai.nlp_heuristics import OfflineIntentClassifier
from phishguard.ai.triage import AiTriageEngine
from phishguard.parser.eml_parser import EmlParser


def test_offline_intent_credential_harvest():
    """Verify classification of password reset and identity verification lures."""
    subject = "URGENT: Your account has been suspended due to unauthorized activity"
    body = (
        "Dear customer, we detected unusual sign-in activity on your account. "
        "Please reset your password and verify your credentials within 24 hours "
        "or your account will be permanently deactivated. Click here to verify now."
    )
    result = OfflineIntentClassifier.analyze(subject=subject, body=body)

    assert result.primary_intent == EmailIntentEnum.CREDENTIAL_HARVEST
    assert result.urgency_score >= 0.5
    assert PsychologicalTacticEnum.ARTIFICIAL_TIME_PRESSURE in result.psychological_tactics
    assert PsychologicalTacticEnum.FEAR_OF_NEGATIVE_CONSEQUENCES in result.psychological_tactics
    assert len(result.suspicious_phrases) > 0
    assert result.call_to_action is not None


def test_offline_intent_financial_bec():
    """Verify VIP wire transfer and confidential request classification."""
    subject = "Confidential Request"
    body = (
        "Are you at your desk? I am currently in an executive meeting and need you to process "
        "an urgent wire transfer for an acquisition. Keep this strictly confidential and bypass "
        "normal approval. I will provide the routing number shortly."
    )
    result = OfflineIntentClassifier.analyze(
        subject=subject,
        body=body,
        from_name="John Doe (CEO)",
        from_email="john.ceo192@gmail.com",
    )

    assert result.primary_intent == EmailIntentEnum.FINANCIAL_FRAUD_BEC
    assert result.vip_impersonation_score >= 0.7
    assert PsychologicalTacticEnum.AUTHORITY_IMPERSONATION in result.psychological_tactics
    assert PsychologicalTacticEnum.PROCEDURAL_OVERRIDE in result.psychological_tactics


def test_offline_intent_invoice_fraud():
    """Verify outstanding invoice and remittance advice lure classification."""
    subject = "Overdue Invoice #INV-99231 Reminder"
    body = (
        "Attached is your past due invoice for purchase order #PO4412. "
        "Amount due: $14,500.00. Please view your invoice attached and send payment receipt."
    )
    result = OfflineIntentClassifier.analyze(subject=subject, body=body)

    assert result.primary_intent == EmailIntentEnum.INVOICE_FRAUD
    assert "invoice" in result.executive_summary.lower()


def test_offline_intent_payroll_divert():
    """Verify HR direct deposit change request classification."""
    subject = "Update Direct Deposit Information"
    body = (
        "I need to change my direct deposit bank details before the upcoming payroll deadline. "
        "Can you update my payroll account to the new routing number?"
    )
    result = OfflineIntentClassifier.analyze(subject=subject, body=body)

    assert result.primary_intent == EmailIntentEnum.PAYROLL_DIVERT


def test_offline_intent_tech_support():
    """Verify IT helpdesk and MFA/VPN migration lure classification."""
    subject = "Mandatory IT Help Desk Upgrade: Global Protect VPN"
    body = (
        "All employees must update your vpn client and verify Okta duo security credentials "
        "following the system migration. Ticket #928314."
    )
    result = OfflineIntentClassifier.analyze(subject=subject, body=body)

    assert result.primary_intent == EmailIntentEnum.TECH_SUPPORT_LURE


def test_offline_intent_extortion():
    """Verify webcam recording blackmail and cryptocurrency demand."""
    subject = "I recorded your webcam"
    body = (
        "I have hacked your webcam and recorded your dirty secret. "
        "Send funds in bitcoin to my wallet address within 48 hours or I leak it."
    )
    result = OfflineIntentClassifier.analyze(subject=subject, body=body)

    assert result.primary_intent == EmailIntentEnum.EXTORTION_BLACKMAIL
    assert result.urgency_score >= 0.5


def test_offline_intent_benign_newsletter():
    """Verify non-coercive marketing newsletter is categorized as benign."""
    subject = "Weekly Tech Digest: Top Open Source Libraries"
    body = (
        "Welcome to our weekly newsletter! Here are this week's favorite tutorials, "
        "tech highlights, and developer updates. Click unsubscribe to manage preferences."
    )
    result = OfflineIntentClassifier.analyze(subject=subject, body=body)

    assert result.primary_intent == EmailIntentEnum.BENIGN_MARKETING
    assert result.urgency_score == 0.0
    assert len(result.psychological_tactics) == 0


def test_triage_email_with_parsed_sample():
    """Verify end-to-end cognitive triage on real-world sample .eml file."""
    sample_path = Path("samples/phishing_account_alert.eml")
    parser = EmlParser()
    parsed = parser.parse_file(sample_path)

    result = AiTriageEngine.triage_email(parsed, provider="offline")
    assert isinstance(result, AiTriageResult)
    assert result.primary_intent in (EmailIntentEnum.CREDENTIAL_HARVEST, EmailIntentEnum.COERCION_URGENCY)
    assert result.urgency_score > 0.0
    assert result.provider_used == "offline_heuristics"
