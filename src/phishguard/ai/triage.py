"""Main AI Social Engineering & Phishing Intent Triage Engine."""

from __future__ import annotations

import json
import os
from typing import Optional
import httpx

from phishguard.ai.models import (
    AiTriageRequest,
    AiTriageResult,
    EmailIntentEnum,
    PsychologicalTacticEnum,
)
from phishguard.ai.nlp_heuristics import OfflineIntentClassifier
from phishguard.parser.eml_parser import ParsedEmail


class AiTriageEngine:
    """Orchestrates AI-driven cognitive triage across offline semantic classifiers and LLMs."""

    @classmethod
    def triage_text(
        cls,
        subject: str,
        body: str,
        from_name: Optional[str] = None,
        from_email: Optional[str] = None,
        provider: str = "offline",
        api_key: Optional[str] = None,
    ) -> AiTriageResult:
        """Categorize threat intent and psychological coercion from raw email elements."""
        key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")

        if provider.lower() in ("gemini", "llm", "online") and key:
            try:
                return cls._triage_with_llm(subject, body, from_name, from_email, key)
            except Exception:
                # Fallback to high-fidelity offline heuristic classifier
                pass

        return OfflineIntentClassifier.analyze(
            subject=subject,
            body=body,
            from_name=from_name,
            from_email=from_email,
        )

    @classmethod
    def triage_email(
        cls,
        parsed: ParsedEmail,
        provider: str = "offline",
        api_key: Optional[str] = None,
    ) -> AiTriageResult:
        """Run cognitive threat triage on a parsed RFC 5322 email message."""
        body = getattr(parsed, "plain_body", "") or getattr(parsed, "body_text", "") or getattr(parsed, "html_body", "") or getattr(parsed, "body_html", "") or ""
        from_name = parsed.metadata.from_name
        from_email = parsed.metadata.from_email or parsed.metadata.from_raw

        return cls.triage_text(
            subject=parsed.metadata.subject,
            body=body,
            from_name=from_name,
            from_email=from_email,
            provider=provider,
            api_key=api_key,
        )

    @classmethod
    def _triage_with_llm(
        cls,
        subject: str,
        body: str,
        from_name: Optional[str],
        from_email: Optional[str],
        api_key: str,
    ) -> AiTriageResult:
        """Query Gemini or OpenAI structured completion endpoint for deep NLP triage."""
        system_prompt = (
            "You are a Tier-3 SOC analyst. Analyze the following email subject and body for phishing intent, "
            "psychological manipulation, and VIP impersonation. Output strictly valid JSON."
        )
        user_prompt = (
            f"Sender Name: {from_name or 'Unknown'}\n"
            f"Sender Email: {from_email or 'Unknown'}\n"
            f"Subject: {subject}\n\n"
            f"Body Text:\n{body[:2000]}\n\n"
            "Respond with JSON matching this schema:\n"
            "{\n"
            '  "primary_intent": "CREDENTIAL_HARVEST" | "FINANCIAL_FRAUD_BEC" | "INVOICE_FRAUD" | "COERCION_URGENCY" | "PAYROLL_DIVERT" | "TECH_SUPPORT_LURE" | "LEGAL_THREAT" | "EXTORTION_BLACKMAIL" | "BENIGN_TRANSACTIONAL" | "BENIGN_MARKETING",\n'
            '  "urgency_score": float (0.0 to 1.0),\n'
            '  "vip_impersonation_score": float (0.0 to 1.0),\n'
            '  "psychological_tactics": ["ARTIFICIAL_TIME_PRESSURE", "AUTHORITY_IMPERSONATION", "FEAR_OF_NEGATIVE_CONSEQUENCES", ...],\n'
            '  "suspicious_phrases": ["phrase1", "phrase2"],\n'
            '  "call_to_action": "click here",\n'
            '  "confidence": float (0.0 to 1.0),\n'
            '  "executive_summary": "summary string"\n'
            "}"
        )

        # Dispatches via Gemini v1beta endpoint
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        }

        with httpx.Client(timeout=10.0) as client:
            resp = client.post(endpoint, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed_json = json.loads(raw_text)

                return AiTriageResult(
                    primary_intent=EmailIntentEnum(parsed_json.get("primary_intent", "CREDENTIAL_HARVEST")),
                    urgency_score=float(parsed_json.get("urgency_score", 0.8)),
                    vip_impersonation_score=float(parsed_json.get("vip_impersonation_score", 0.0)),
                    psychological_tactics=[
                        PsychologicalTacticEnum(t) for t in parsed_json.get("psychological_tactics", [])
                        if t in PsychologicalTacticEnum.__members__
                    ],
                    suspicious_phrases=parsed_json.get("suspicious_phrases", []),
                    call_to_action=parsed_json.get("call_to_action"),
                    confidence=float(parsed_json.get("confidence", 0.95)),
                    executive_summary=parsed_json.get("executive_summary", "Analyzed by LLM"),
                    provider_used="gemini_llm",
                )
            raise RuntimeError(f"LLM API error {resp.status_code}")
