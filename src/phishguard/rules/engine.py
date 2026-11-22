"""
SOC Detection Rule Evaluation Engine.
Loads, compiles, and evaluates YAML-based detection rules against parsed email artifacts.
"""

from pathlib import Path
import re
from typing import Any, Optional, Union
import yaml

from phishguard.models.forensics import (
    AttachmentArtifact,
    HeaderAnalysis,
    QuishingResult,
    UrlArtifact,
)
from phishguard.models.report import RuleMatch
from phishguard.parser.eml_parser import ParsedEmail
from phishguard.rules.models import RuleCondition, RuleDefinition


class RuleEngine:
    """
    Evaluates YAML detection rules against parsed email components.
    """

    def __init__(self, rules: Optional[list[RuleDefinition]] = None):
        self.rules: list[RuleDefinition] = rules or []
        self._compiled_regexes: dict[str, re.Pattern] = {}

    @classmethod
    def from_directory(cls, dir_path: Union[str, Path]) -> "RuleEngine":
        """Load all .yaml and .yml rules from a directory."""
        directory = Path(dir_path)
        if not directory.exists() or not directory.is_dir():
            return cls([])

        rules: list[RuleDefinition] = []
        for file_path in directory.glob("*.y*ml"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict) and "id" in data and "name" in data:
                        rules.append(RuleDefinition.model_validate(data))
            except Exception:
                # Gracefully skip malformed rule files
                continue

        return cls(rules)

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> "RuleEngine":
        """Load a single YAML rule file."""
        path = Path(file_path)
        if not path.exists():
            return cls([])

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict) and "id" in data:
                return cls([RuleDefinition.model_validate(data)])
        return cls([])

    def add_rule(self, rule: RuleDefinition) -> None:
        self.rules.append(rule)

    def _get_regex(self, pattern: str) -> Optional[re.Pattern]:
        """Cache compiled regexes to optimize high-throughput scanning."""
        if pattern not in self._compiled_regexes:
            try:
                self._compiled_regexes[pattern] = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            except re.error:
                return None
        return self._compiled_regexes[pattern]

    def evaluate_condition(
        self,
        cond: RuleCondition,
        parsed: ParsedEmail,
        headers: HeaderAnalysis,
        urls: list[UrlArtifact],
        attachments: list[AttachmentArtifact],
        quishing: Optional[QuishingResult],
    ) -> tuple[bool, Optional[str]]:
        """
        Evaluates a single condition and returns (is_matched, evidence_string).
        """
        field = cond.field.lower()
        op = cond.operator.lower()

        # Extract target field value
        target_val: Any = None

        if field == "subject":
            target_val = parsed.metadata.subject or ""
        elif field == "from":
            target_val = parsed.metadata.from_address or ""
        elif field == "reply_to":
            target_val = parsed.metadata.reply_to or ""
        elif field == "body":
            target_val = f"{parsed.plain_body}\n{parsed.html_body}"
        elif field == "headers":
            if cond.header_name:
                h_name = cond.header_name.lower()
                if isinstance(parsed.headers, dict):
                    target_val = parsed.headers.get(h_name, "")
                elif isinstance(parsed.headers, list):
                    target_val = "\n".join([v for k, v in parsed.headers if k.lower() == h_name])
                else:
                    target_val = ""
            else:
                if isinstance(parsed.headers, dict):
                    target_val = "\n".join(f"{k}: {v}" for k, v in parsed.headers.items())
                elif isinstance(parsed.headers, list):
                    target_val = "\n".join(f"{k}: {v}" for k, v in parsed.headers)
                else:
                    target_val = ""
        elif field == "url_count":
            target_val = len(urls)
        elif field == "url_domains":
            target_val = [u.domain for u in urls if u.domain]
        elif field == "attachment_names":
            target_val = [a.filename for a in attachments if a.filename]
        elif field == "attachment_types":
            target_val = [a.detected_mime or a.original_mime for a in attachments if (a.detected_mime or a.original_mime)]
        elif field == "attachment_has_macros":
            target_val = any(a.has_macros for a in attachments)
        elif field == "attachment_is_executable":
            target_val = any(a.is_executable or a.is_double_extension for a in attachments)
        elif field == "auth_spf":
            target_val = headers.auth.spf_status.value.lower()
        elif field == "auth_dkim":
            target_val = headers.auth.dkim_status.value.lower()
        elif field == "auth_dmarc":
            target_val = headers.auth.dmarc_status.value.lower()
        elif field == "quishing_detected":
            target_val = bool(quishing and quishing.found)
        else:
            return False, None

        # Operator evaluation
        if op == "regex_search":
            patterns = cond.patterns or ([cond.pattern] if cond.pattern else [])
            for pat in patterns:
                rx = self._get_regex(pat)
                if not rx:
                    continue
                if isinstance(target_val, list):
                    for item in target_val:
                        m = rx.search(str(item))
                        if m:
                            return True, f"Field '{field}' matched regex pattern '{pat}' on '{m.group(0)[:80]}'"
                else:
                    m = rx.search(str(target_val))
                    if m:
                        return True, f"Field '{field}' matched regex pattern '{pat}' on '{m.group(0)[:80]}'"
            return False, None

        elif op == "regex_match":
            pattern = cond.pattern or (cond.patterns[0] if cond.patterns else "")
            rx = self._get_regex(pattern)
            if rx and rx.match(str(target_val)):
                return True, f"Field '{field}' matched regex pattern '{pattern}'"
            return False, None

        elif op in ("contains", "icontains"):
            pat = (cond.pattern or str(cond.value or "")).lower()
            if isinstance(target_val, list):
                for item in target_val:
                    if pat in str(item).lower():
                        return True, f"Field '{field}' element '{item}' contains '{pat}'"
            else:
                if pat in str(target_val).lower():
                    return True, f"Field '{field}' contains substring '{pat}'"
            return False, None

        elif op in ("contains_any", "in_any"):
            patterns = cond.patterns or []
            if cond.pattern:
                patterns.append(cond.pattern)
            lowered_pats = [p.lower() for p in patterns]

            if isinstance(target_val, list):
                for item in target_val:
                    item_low = str(item).lower()
                    for p in lowered_pats:
                        if p in item_low:
                            return True, f"Field '{field}' element '{item}' matched '{p}'"
            else:
                target_low = str(target_val).lower()
                for p in lowered_pats:
                    if p in target_low:
                        return True, f"Field '{field}' contains indicator '{p}'"
            return False, None

        elif op in ("equals", "eq"):
            expected = str(cond.value if cond.value is not None else (cond.pattern or "")).lower()
            actual = str(target_val).lower()
            if actual == expected:
                return True, f"Field '{field}' equals '{expected}'"
            return False, None

        elif op == "in":
            allowed = [str(x).lower() for x in (cond.patterns or cond.value or [])]
            if str(target_val).lower() in allowed:
                return True, f"Field '{field}' is in allowed set {allowed}"
            return False, None

        elif op in ("gt", "gte", "lt", "lte"):
            try:
                num_val = float(target_val)
                comp_val = float(cond.value)
                if op == "gt" and num_val > comp_val:
                    return True, f"Field '{field}' ({num_val}) > {comp_val}"
                elif op == "gte" and num_val >= comp_val:
                    return True, f"Field '{field}' ({num_val}) >= {comp_val}"
                elif op == "lt" and num_val < comp_val:
                    return True, f"Field '{field}' ({num_val}) < {comp_val}"
                elif op == "lte" and num_val <= comp_val:
                    return True, f"Field '{field}' ({num_val}) <= {comp_val}"
            except (ValueError, TypeError):
                return False, None

        return False, None

    def evaluate_rule(
        self,
        rule: RuleDefinition,
        parsed: ParsedEmail,
        headers: HeaderAnalysis,
        urls: list[UrlArtifact],
        attachments: list[AttachmentArtifact],
        quishing: Optional[QuishingResult],
    ) -> Optional[RuleMatch]:
        """Evaluates a single rule's conditions with all/any/none logic."""
        matched_fields: list[str] = []
        evidence_list: list[str] = []

        conditions = rule.conditions

        # 1. 'all' conditions (conjunction)
        all_conds = conditions.get("all", [])
        for c in all_conds:
            matched, evidence = self.evaluate_condition(c, parsed, headers, urls, attachments, quishing)
            if not matched:
                return None
            matched_fields.append(c.field)
            if evidence:
                evidence_list.append(evidence)

        # 2. 'any' conditions (disjunction)
        any_conds = conditions.get("any", [])
        if any_conds:
            any_matched = False
            for c in any_conds:
                matched, evidence = self.evaluate_condition(c, parsed, headers, urls, attachments, quishing)
                if matched:
                    any_matched = True
                    matched_fields.append(c.field)
                    if evidence:
                        evidence_list.append(evidence)
                    break
            if not any_matched:
                return None

        # 3. 'none' conditions (negation)
        none_conds = conditions.get("none", [])
        for c in none_conds:
            matched, _ = self.evaluate_condition(c, parsed, headers, urls, attachments, quishing)
            if matched:
                return None

        # If rule had no conditions at all, do not match
        if not all_conds and not any_conds:
            return None

        return RuleMatch(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity.value,
            score_impact=rule.score_impact,
            description=rule.description,
            mitre_technique_id=rule.mitre.technique_id if rule.mitre else None,
            mitre_technique_name=rule.mitre.technique_name if rule.mitre else None,
            matched_fields=list(dict.fromkeys(matched_fields)),
            evidence=evidence_list,
        )

    def evaluate_all(
        self,
        parsed: ParsedEmail,
        headers: HeaderAnalysis,
        urls: list[UrlArtifact],
        attachments: list[AttachmentArtifact],
        quishing: Optional[QuishingResult],
    ) -> list[RuleMatch]:
        """Evaluates all registered rules against the email artifacts."""
        matches: list[RuleMatch] = []
        for rule in self.rules:
            res = self.evaluate_rule(rule, parsed, headers, urls, attachments, quishing)
            if res:
                matches.append(res)
        return matches
