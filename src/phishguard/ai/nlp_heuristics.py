"""Offline NLP and semantic heuristics engine for email intent classification."""

from __future__ import annotations

import re
from typing import Optional
from phishguard.ai.models import (
    AiTriageResult,
    EmailIntentEnum,
    PsychologicalTacticEnum,
)

# Semantic Lexicon Matrix for Adversary Lure Categories
INTENT_PATTERNS: dict[EmailIntentEnum, list[tuple[str, float]]] = {
    EmailIntentEnum.CREDENTIAL_HARVEST: [
        (r"\b(reset|change|update)\s+(your\s+)?(password|passcode|pin)\b", 4.0),
        (r"\b(verify|confirm|validate)\s+(your\s+)?(account|identity|credentials|email)\b", 4.0),
        (r"\b(account|mailbox|service)\s+(has\s+been\s+)?(suspended|locked|limited|flagged|disabled)\b", 3.5),
        (r"\b(unauthorized|unusual|suspicious)\s+(activity|sign-?in|login|access)\b", 3.5),
        (r"\b(log\s*in|sign\s*in)\s+(to\s+)?(continue|verify|restore|keep\s+access)\b", 3.0),
        (r"\bsecurity\s+alert\b", 2.0),
        (r"\bmfa|2fa|two-?factor\b", 2.5),
    ],
    EmailIntentEnum.FINANCIAL_FRAUD_BEC: [
        (r"\bwire\s+transfer\b", 4.0),
        (r"\b(bank|urgent)\s+transfer\b", 3.5),
        (r"\b(confidential|discreet|private)\s+(transaction|matter|acquisition|deal)\b", 3.5),
        (r"\bare\s+you\s+(at\s+your\s+desk|available|in\s+office)\b", 3.0),
        (r"\bprocess\s+this\s+(payment|transfer|invoice)\s+(asap|immediately|urgently)\b", 4.0),
        (r"\brouting\s+number|swift\s+code|iban\b", 3.0),
        (r"\bi\s+am\s+(in\s+a\s+meeting|traveling|unavailable\s+by\s+phone)\b", 3.0),
    ],
    EmailIntentEnum.INVOICE_FRAUD: [
        (r"\b(past\s+due|overdue|unpaid)\s+invoice\b", 4.0),
        (r"\b(remittance|payment)\s+(advice|receipt|confirmation|scheduled)\b", 3.5),
        (r"\b(invoice|statement)\s+attached\b", 3.0),
        (r"\bpurchase\s+order\s+#?\w+\b", 3.0),
        (r"\bview\s+(your\s+)?(invoice|bill)\b", 2.5),
        (r"\bamount\s+due:\s*[\$\€\£]?\d+", 3.5),
    ],
    EmailIntentEnum.PAYROLL_DIVERT: [
        (r"\b(update|change)\s+(my\s+|your\s+)?(direct\s+deposit|bank\s+details|payroll)\b", 5.0),
        (r"\bpayroll\s+(portal|account|deposit)\b", 3.5),
        (r"\bw-?2\s+(form|tax|document)\b", 3.5),
        (r"\bcompensation\s+review\b", 3.0),
    ],
    EmailIntentEnum.TECH_SUPPORT_LURE: [
        (r"\b(it\s+)?help\s*desk|tech(nical)?\s+support\b", 3.0),
        (r"\b(system|server|mailbox)\s+(upgrade|maintenance|migration)\b", 3.5),
        (r"\bupdate\s+your\s+(vpn|client|software|browser)\b", 3.5),
        (r"\bticket\s*#?\s*\d{4,}\b", 2.5),
        (r"\bduo\s+security|okta|global\s*protect\b", 3.0),
    ],
    EmailIntentEnum.LEGAL_THREAT: [
        (r"\b(subpoena|court\s+summons|legal\s+notice)\b", 4.5),
        (r"\b(copyright|trademark|dmca)\s+(infringement|violation)\b", 4.0),
        (r"\blitigation\s+(hold|notice)\b", 4.0),
        (r"\blaw\s+enforcement|federal\s+court\b", 3.5),
    ],
    EmailIntentEnum.EXTORTION_BLACKMAIL: [
        (r"\b(recorded|hacked)\s+(your\s+)?(webcam|screen|camera)\b", 5.0),
        (r"\b(bitcoin|btc|wallet)\s+address\b", 4.5),
        (r"\bdirty\s+secret|pervert|porn\b", 4.0),
        (r"\b(pay\s+me|send\s+funds)\s+(in|via)\s+(bitcoin|crypto)\b", 5.0),
    ],
    EmailIntentEnum.COERCION_URGENCY: [
        (r"\bimmediate(ly)?\s+action\s+required\b", 4.0),
        (r"\b(within\s+\d+\s+hours?|before\s+today|expires\s+in\s+\d+)\b", 3.5),
        (r"\bfinal\s+(notice|warning)\b", 3.5),
        (r"\bfailure\s+to\s+(respond|comply|act)\b", 3.5),
        (r"\bpermanent(ly)?\s+(deleted|deactivated|closed)\b", 3.5),
    ],
}

# Psychological Cognitive Biases
TACTIC_PATTERNS: dict[PsychologicalTacticEnum, list[str]] = {
    PsychologicalTacticEnum.ARTIFICIAL_TIME_PRESSURE: [
        r"\b(within\s+\d+\s+(hours?|mins?|minutes?)|immediate(ly)?|deadline|urgent(ly)?|expires\s+today|asap)\b",
        r"\b(24|48|12)\s+hours?\s+to\s+respond\b",
    ],
    PsychologicalTacticEnum.AUTHORITY_IMPERSONATION: [
        r"\b(chief\s+executive|ceo|cfo|executive\s+office|general\s+counsel|hr\s+director|it\s+admin(istrator)?)\b",
        r"\b(board\s+of\s+directors|corporate\s+security|audit\s+committee)\b",
    ],
    PsychologicalTacticEnum.FEAR_OF_NEGATIVE_CONSEQUENCES: [
        r"\b(suspended|terminated|deactivated|penalties|legal\s+action|arrest|loss\s+of\s+access|leak|dirty\s+secret)\b",
        r"\baccount\s+will\s+be\s+deleted\b",
    ],
    PsychologicalTacticEnum.GREED_FALSE_REWARD: [
        r"\b(bonus|reward|grant|refund|winner|claim\s+your|unclaimed\s+funds)\b",
    ],
    PsychologicalTacticEnum.CURIOSITY_BAIT: [
        r"\b(confidential\s+document|leaked|shared\s+a\s+file\s+with\s+you|scanned\s+image)\b",
    ],
    PsychologicalTacticEnum.HELPFULNESS_EXPLOITATION: [
        r"\b(can\s+you\s+help\s+me|need\s+a\s+quick\s+favor|do\s+me\s+a\s+favor)\b",
    ],
    PsychologicalTacticEnum.PROCEDURAL_OVERRIDE: [
        r"\b(bypass\s+standard|skip\s+the\s+normal|strictly\s+confidential|don'?t\s+mention\s+this\s+to\s+anyone)\b",
    ],
}

VIP_TITLE_KEYWORDS = [
    "ceo", "chief executive", "cfo", "chief financial", "president",
    "executive director", "general counsel", "vp", "vice president"
]


class OfflineIntentClassifier:
    """Evaluates message semantics using deterministic linguistic scoring and social engineering lexicons."""

    @classmethod
    def analyze(
        cls,
        subject: str,
        body: str,
        from_name: Optional[str] = None,
        from_email: Optional[str] = None,
    ) -> AiTriageResult:
        """Perform comprehensive offline intent categorization and cognitive triage."""
        combined_text = f"{subject}\n{body}".lower()
        matched_phrases: list[str] = []

        # 1. Calculate Intent Vector Scores
        intent_scores: dict[EmailIntentEnum, float] = {intent: 0.0 for intent in EmailIntentEnum}

        for intent, patterns in INTENT_PATTERNS.items():
            for pattern, weight in patterns:
                matches = re.findall(pattern, combined_text, re.IGNORECASE)
                if matches:
                    intent_scores[intent] += weight * len(matches)
                    for m in matches:
                        phrase = m[0] if isinstance(m, tuple) else m
                        if phrase and phrase not in matched_phrases:
                            matched_phrases.append(phrase)

        # 2. Extract Psychological Tactics
        detected_tactics: list[PsychologicalTacticEnum] = []
        for tactic, patterns in TACTIC_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, combined_text, re.IGNORECASE):
                    if tactic not in detected_tactics:
                        detected_tactics.append(tactic)

        # 3. Urgency Index (0.0 to 1.0)
        urgency_regexes = [
            r"\bwithin\s+\d+\s+(?:hours?|days?|mins?)\b",
            r"\b(?:24|48|12)\s+hours?\b",
            r"\b(urgent(?:ly)?|immediate(?:ly)?|asap|deadline|critical|action\s+required|final\s+notice|suspended|leak)\b",
        ]
        urgency_count = sum(len(re.findall(rx, combined_text, re.IGNORECASE)) for rx in urgency_regexes)
        raw_urgency = (
            (urgency_count * 0.18)
            + (0.25 if PsychologicalTacticEnum.ARTIFICIAL_TIME_PRESSURE in detected_tactics else 0.0)
            + (0.15 if (PsychologicalTacticEnum.FEAR_OF_NEGATIVE_CONSEQUENCES in detected_tactics and PsychologicalTacticEnum.ARTIFICIAL_TIME_PRESSURE in detected_tactics) else 0.0)
        )
        urgency_score = min(1.0, round(raw_urgency, 2))

        # 4. VIP Impersonation Risk Score
        vip_score = 0.0
        sender_lower = (from_name or "").lower()
        if any(re.search(r"\b" + re.escape(t) + r"\b", sender_lower) for t in VIP_TITLE_KEYWORDS):
            vip_score += 0.4
            detected_tactics.append(PsychologicalTacticEnum.AUTHORITY_IMPERSONATION)

        if from_email:
            # Free webmail used by executive
            free_webmail = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me")
            if any(from_email.lower().endswith("@" + d) for d in free_webmail) and vip_score > 0:
                vip_score += 0.45

        vip_impersonation_score = min(1.0, round(vip_score, 2))

        # 5. Determine Primary & Secondary Intents
        sorted_intents = sorted(intent_scores.items(), key=lambda item: item[1], reverse=True)
        top_intent, top_score = sorted_intents[0]

        if top_score < 2.0:
            # Default to benign classification if score is low
            if "unsubscribe" in combined_text or "newsletter" in combined_text or "sale" in combined_text:
                primary_intent = EmailIntentEnum.BENIGN_MARKETING
            else:
                primary_intent = EmailIntentEnum.BENIGN_TRANSACTIONAL
            secondary_intents = []
        else:
            primary_intent = top_intent
            secondary_intents = [
                k for k, v in sorted_intents[1:3] if v >= 2.0 and k != primary_intent
            ]

        # 6. Extract Call-to-Action
        cta_match = re.search(r"\b(click\s+here|click\s+the\s+link|download\s+attachment|sign\s*in\s+now|verify\s+now|review\s+document)\b", combined_text, re.IGNORECASE)
        call_to_action = cta_match.group(0).capitalize() if cta_match else None

        # 7. Synthesize Plain-English Executive Summary
        tactic_names = [t.value.replace("_", " ").title() for t in detected_tactics]
        tactics_summary = ", ".join(tactic_names) if tactic_names else "Standard communication"

        if primary_intent in (EmailIntentEnum.BENIGN_TRANSACTIONAL, EmailIntentEnum.BENIGN_MARKETING):
            exec_summary = f"Routine communication analyzed as {primary_intent.value}. No coercive psychological indicators detected."
        else:
            exec_summary = (
                f"Adversary exhibits high-probability {primary_intent.value} intent with an urgency rating of {urgency_score:.2f}/1.0. "
                f"Exploited cognitive biases include: {tactics_summary}. "
                f"Identified {len(matched_phrases)} suspicious trigger phrases demanding immediate recipient action."
            )

        return AiTriageResult(
            primary_intent=primary_intent,
            secondary_intents=secondary_intents,
            urgency_score=urgency_score,
            vip_impersonation_score=vip_impersonation_score,
            psychological_tactics=detected_tactics,
            suspicious_phrases=matched_phrases[:8],
            call_to_action=call_to_action,
            confidence=0.90 if top_score >= 4.0 else 0.75,
            executive_summary=exec_summary,
            provider_used="offline_heuristics",
        )
