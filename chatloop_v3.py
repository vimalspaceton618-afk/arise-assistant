import ast
import json
import math
import operator
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv


SYSTEM_RULES = """
You are ARISE, an agentic AI assistant built for Vimal Kumar.

Identity:
- You are more than a basic chatbot: you can reason, plan, remember useful facts,
  use local deterministic tools, and keep long conversations organized.
- You are precise, practical, and direct.
- You can support enterprise cyber defense, incident response, governance, and
  safe threat modeling inside a strict review-only sandbox.

Behavior:
- Ask a clarifying question only when the task is truly ambiguous.
- For coding tasks, give runnable steps and call out assumptions.
- For plans, break work into clear phases and next actions.
- Never invent facts. If you do not know, say so and explain what would verify it.
- Do not provide malware, credential theft, phishing, DDoS, keylogging, or other
  offensive cyber instructions.
- Do not execute or recommend destructive production actions without backups,
  dry-runs, rollback planning, scoped authorization, and human approval.
""".strip()


SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

SAFE_FUNCTIONS = {
    "abs": abs,
    "round": round,
    "sqrt": math.sqrt,
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "log": math.log,
    "log10": math.log10,
    "ceil": math.ceil,
    "floor": math.floor,
}

SAFE_CONSTANTS = {
    "pi": math.pi,
    "e": math.e,
}


class ToolError(ValueError):
    pass


@dataclass
class SafetyAssessment:
    verdict: str
    category: str
    risk_score: int
    reasons: List[str] = field(default_factory=list)
    safeguards: List[str] = field(default_factory=list)

    def format(self) -> str:
        lines = [
            f"Verdict: {self.verdict}",
            f"Category: {self.category}",
            f"Risk score: {self.risk_score}/10",
        ]
        if self.reasons:
            lines.append("Reasons:")
            lines.extend(f"- {reason}" for reason in self.reasons)
        if self.safeguards:
            lines.append("Required safeguards:")
            lines.extend(f"- {safeguard}" for safeguard in self.safeguards)
        return "\n".join(lines)


@dataclass
class CyberSafetyLayer:
    audit_path: Path
    sandbox_mode: str = "review_only"
    require_approval: bool = True

    @classmethod
    def from_env(cls) -> "CyberSafetyLayer":
        return cls(
            audit_path=Path(os.getenv("ARISE_AUDIT_LOG", "arise_audit.jsonl")),
            sandbox_mode=os.getenv("ARISE_SANDBOX_MODE", "review_only"),
            require_approval=os.getenv("ARISE_REQUIRE_APPROVAL", "true").lower() == "true",
        )

    def is_cyber_related(self, text: str) -> bool:
        lowered = text.lower()
        keywords = [
            "attack",
            "audit",
            "breach",
            "cve",
            "cyber",
            "defend",
            "defense",
            "delete database",
            "drop database",
            "exploit",
            "firewall",
            "incident",
            "malware",
            "nmap",
            "phishing",
            "ransomware",
            "sandbox",
            "secret",
            "siem",
            "soc",
            "threat",
            "vulnerability",
        ]
        return any(keyword in lowered for keyword in keywords)

    def assess(self, text: str, strict_action: bool = False) -> SafetyAssessment:
        lowered = text.lower()
        defensive_context = self.has_defensive_context(lowered) and not strict_action

        blocked_checks = [
            (r"\b(ddos|botnet|flood)\b", "DDoS or traffic flooding request"),
            (r"\b(phishing kit|credential theft|steal password|steal token)\b", "Credential theft or phishing enablement"),
            (r"\b(keylogger|ransomware|malware|persistence|backdoor)\b", "Malware or persistence request"),
            (r"\b(exfiltrate|dump credentials|dump tokens|bypass mfa)\b", "Data exfiltration or access bypass request"),
            (r"\b(sqlmap|metasploit|exploit)\b.*\b(public|external|internet|target)\b", "Offensive exploitation against external targets"),
        ]
        destructive_checks = [
            (r"\brm\s+(-[a-z]*r[a-z]*f|-rf|-fr)\b", "Recursive force delete"),
            (r"\b(drop|truncate)\s+(database|schema|table)\b", "Destructive database mutation"),
            (r"\bdelete\s+from\b.*\bwhere\b\s*(1\s*=\s*1|true)\b", "Broad SQL delete"),
            (r"\bterraform\s+destroy\b", "Infrastructure destroy operation"),
            (r"\bkubectl\s+delete\b", "Kubernetes delete operation"),
            (r"\baws\b.*\bdelete-|\baz\b.*\bdelete\b|\bgcloud\b.*\bdelete\b", "Cloud delete operation"),
            (r"\bformat\b.*\b(drive|disk|volume)\b", "Disk format operation"),
        ]
        approval_checks = [
            (r"\bnmap\b|\bmasscan\b|\bport scan\b", "Network scanning needs written authorization and scope"),
            (r"\bvulnerability scan\b|\bpentest\b|\bred team\b", "Security testing needs approved scope"),
            (r"\bchange firewall\b|\biptables\b|\bsecurity group\b", "Network control change can cause outage"),
            (r"\bmigrate database\b|\balter table\b|\brestart service\b", "Production operation needs rollback planning"),
            (r"\bansible-playbook\b|\bterraform apply\b|\bkubectl apply\b", "Automation can change many systems"),
        ]

        reasons = self.match_reasons(lowered, blocked_checks)
        if reasons and not defensive_context:
            return SafetyAssessment(
                verdict="blocked",
                category="offensive_or_abusive_cyber",
                risk_score=10,
                reasons=reasons,
                safeguards=[
                    "Use ARISE for authorized defense, detection, hardening, and incident response only.",
                    "Reframe the request as a safe defensive analysis or recovery task.",
                ],
            )

        destructive_reasons = self.match_reasons(lowered, destructive_checks)
        if destructive_reasons and "dry-run" not in lowered and "--dry-run" not in lowered:
            verdict = "blocked" if strict_action or not defensive_context else "allowed"
            return SafetyAssessment(
                verdict=verdict,
                category="destructive_operation",
                risk_score=9 if verdict == "blocked" else 4,
                reasons=destructive_reasons,
                safeguards=[
                    "Require backup or snapshot verification before any mutation.",
                    "Use dry-run or read-only preview first.",
                    "Require explicit human approval with target, environment, rollback, and blast radius.",
                    "Block production execution from the AI session.",
                ],
            )

        approval_reasons = self.match_reasons(lowered, approval_checks)
        if approval_reasons:
            return SafetyAssessment(
                verdict="approval_required" if self.require_approval else "allowed",
                category="enterprise_security_operation",
                risk_score=7,
                reasons=approval_reasons,
                safeguards=[
                    "Confirm written authorization and exact scope.",
                    "Prefer read-only mode, rate limits, and maintenance windows.",
                    "Log the action, expected impact, and rollback plan.",
                    "Run in a lab or staging environment before production.",
                ],
            )

        if self.is_cyber_related(text):
            return SafetyAssessment(
                verdict="allowed",
                category="defensive_cyber_intelligence",
                risk_score=2,
                reasons=["Request appears defensive, educational, or governance-focused."],
                safeguards=[
                    "Keep outputs focused on prevention, detection, response, and recovery.",
                    "Do not include exploit automation, stealth, persistence, or credential theft steps.",
                ],
            )

        return SafetyAssessment(
            verdict="allowed",
            category="general",
            risk_score=1,
            reasons=["No cyber or destructive operation risk detected."],
            safeguards=[],
        )

    def guard_action(self, action: str) -> str:
        assessment = self.assess(action, strict_action=True)
        self.audit("guard_action", action, assessment)
        return assessment.format()

    def classify_request(self, request: str) -> str:
        assessment = self.assess(request)
        self.audit("classify_request", request, assessment)
        return assessment.format()

    def incident_plan(self, scenario: str) -> str:
        lowered = scenario.lower()
        if "database" in lowered or "delete" in lowered or "drop" in lowered:
            focus = [
                "Freeze write access for affected systems.",
                "Identify last known-good backup, snapshot, or point-in-time recovery target.",
                "Export current logs before rotation removes evidence.",
                "Restore into staging first, validate integrity, then plan production recovery.",
                "Add guardrails: least privilege, change tickets, dry-run migrations, and delete protection.",
            ]
        elif "ransomware" in lowered or "malware" in lowered:
            focus = [
                "Isolate affected hosts from the network.",
                "Preserve volatile evidence and collect endpoint telemetry.",
                "Block known indicators across EDR, DNS, email, and firewall controls.",
                "Restore from clean backups after root-cause validation.",
                "Rotate credentials exposed on affected hosts.",
            ]
        elif "phishing" in lowered or "credential" in lowered:
            focus = [
                "Disable suspicious sessions and rotate affected credentials.",
                "Search mailboxes and logs for related indicators.",
                "Block sender infrastructure, URLs, and attachment hashes.",
                "Review MFA events and impossible-travel signals.",
                "Notify affected users with clear reporting steps.",
            ]
        else:
            focus = [
                "Triage severity, affected assets, and business impact.",
                "Contain the incident before eradication.",
                "Preserve logs and evidence with timestamps.",
                "Recover through tested rollback or restore procedures.",
                "Document lessons learned and control improvements.",
            ]
        assessment = self.assess(scenario)
        self.audit("incident_plan", scenario, assessment)
        return "Incident response plan:\n" + "\n".join(f"{index}. {step}" for index, step in enumerate(focus, start=1))

    def policy_context(self) -> str:
        return "\n".join(
            [
                "Cyber sandbox policy:",
                f"- Mode: {self.sandbox_mode}",
                f"- Human approval required: {self.require_approval}",
                "- Block offensive automation, credential theft, malware, DDoS, and destructive production actions.",
                "- Prefer read-only analysis, dry-runs, backups, rollback plans, scoped authorization, and audit logging.",
                "- Treat attacker thinking as high-level threat modeling for defense, not execution guidance.",
            ]
        )

    def status(self) -> str:
        return "\n".join(
            [
                f"Sandbox mode: {self.sandbox_mode}",
                f"Human approval required: {self.require_approval}",
                f"Audit log: {self.audit_path}",
            ]
        )

    def audit(self, event_type: str, text: str, assessment: SafetyAssessment) -> None:
        event = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "event_type": event_type,
            "verdict": assessment.verdict,
            "category": assessment.category,
            "risk_score": assessment.risk_score,
            "text_preview": text[:240],
        }
        try:
            with self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
        except OSError:
            pass

    def has_defensive_context(self, lowered: str) -> bool:
        defensive_terms = [
            "analyze",
            "audit",
            "defend",
            "defense",
            "detect",
            "harden",
            "incident",
            "monitor",
            "prevent",
            "recover",
            "restore",
            "review",
            "sandbox",
            "secure",
            "simulate",
            "threat model",
        ]
        return any(term in lowered for term in defensive_terms)

    def match_reasons(self, lowered: str, checks: List[tuple[str, str]]) -> List[str]:
        return [reason for pattern, reason in checks if re.search(pattern, lowered)]


@dataclass
class ModelProfile:
    name: str
    api_key: str
    base_url: str
    model: str
    free_tier: bool = False

    @property
    def chat_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/chat/completions"

    @property
    def label(self) -> str:
        badge = "free" if self.free_tier else "paid/custom"
        return f"{self.name}:{self.model} ({badge})"


@dataclass
class ModelRouter:
    profiles: List[ModelProfile]
    task_models: Dict[str, str] = field(default_factory=dict)
    free_only: bool = True
    active_model: Optional[str] = None
    active_provider: Optional[str] = None

    @classmethod
    def from_env(cls) -> "ModelRouter":
        profiles: List[ModelProfile] = []
        openrouter_key = os.getenv("OPENROUTER_API_KEY")
        groq_key = os.getenv("GROQ_API_KEY")

        if openrouter_key:
            model = (
                os.getenv("OPENROUTER_MODEL")
                or os.getenv("ARISE_MODEL")
                or os.getenv("MODEL_NAME")
                or "meta-llama/llama-3.1-8b-instruct:free"
            )
            profiles.append(
                ModelProfile(
                    name="openrouter",
                    api_key=openrouter_key,
                    base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
                    model=model,
                    free_tier=model.endswith(":free"),
                )
            )

        if groq_key:
            model = os.getenv("GROQ_MODEL") or os.getenv("ARISE_MODEL") or "llama-3.3-70b-versatile"
            profiles.append(
                ModelProfile(
                    name="groq",
                    api_key=groq_key,
                    base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
                    model=model,
                    free_tier=os.getenv("GROQ_FREE_TIER", "true").lower() == "true",
                )
            )

        custom_key = os.getenv("CUSTOM_OPENAI_API_KEY")
        custom_url = os.getenv("CUSTOM_OPENAI_BASE_URL")
        custom_model = os.getenv("CUSTOM_OPENAI_MODEL")
        if custom_key and custom_url and custom_model:
            profiles.append(
                ModelProfile(
                    name=os.getenv("CUSTOM_OPENAI_NAME", "custom"),
                    api_key=custom_key,
                    base_url=custom_url,
                    model=custom_model,
                    free_tier=os.getenv("CUSTOM_OPENAI_FREE_TIER", "false").lower() == "true",
                )
            )

        for item in os.getenv("ARISE_FREE_MODELS", "").split(","):
            parsed = item.strip()
            if not parsed:
                continue
            provider, _, model = parsed.partition(":")
            if not provider or not model:
                continue
            template = next((profile for profile in profiles if profile.name == provider), None)
            if template:
                profiles.append(
                    ModelProfile(
                        name=template.name,
                        api_key=template.api_key,
                        base_url=template.base_url,
                        model=model,
                        free_tier=True,
                    )
                )

        free_only = os.getenv("ARISE_FREE_ONLY", "true").lower() == "true"
        task_models = {
            "default": os.getenv("ARISE_DEFAULT_MODEL", ""),
            "fast": os.getenv("ARISE_FAST_MODEL", ""),
            "code": os.getenv("ARISE_CODE_MODEL", ""),
            "reasoning": os.getenv("ARISE_REASONING_MODEL", ""),
            "creative": os.getenv("ARISE_CREATIVE_MODEL", ""),
        }
        return cls(profiles=profiles, task_models=task_models, free_only=free_only)

    def choose(self, task: str) -> List[ModelProfile]:
        pool = self.profiles
        if self.free_only:
            free_pool = [profile for profile in pool if profile.free_tier]
            if free_pool:
                pool = free_pool

        preferred = self.active_model or self.task_models.get(task) or self.task_models.get("default")
        ordered = self.order_by_preference(pool, preferred)
        return ordered or pool

    def order_by_preference(self, pool: List[ModelProfile], preferred: Optional[str]) -> List[ModelProfile]:
        if not preferred:
            return list(pool)
        provider, model = self.parse_model_ref(preferred)

        def score(profile: ModelProfile) -> int:
            if provider and profile.name != provider:
                return 2
            if profile.model == model:
                return 0
            if model and model in profile.model:
                return 1
            return 2

        return sorted(pool, key=score)

    def parse_model_ref(self, ref: str) -> tuple[Optional[str], str]:
        provider, sep, model = ref.partition(":")
        if sep and provider in {profile.name for profile in self.profiles}:
            return provider, model
        return self.active_provider, ref

    def set_active(self, ref: str) -> str:
        provider, model = self.parse_model_ref(ref.strip())
        matches = [
            profile
            for profile in self.profiles
            if (not provider or profile.name == provider) and profile.model == model
        ]
        if not matches and provider:
            template = next((profile for profile in self.profiles if profile.name == provider), None)
            if template:
                self.profiles.insert(
                    0,
                    ModelProfile(
                        name=template.name,
                        api_key=template.api_key,
                        base_url=template.base_url,
                        model=model,
                        free_tier=model.endswith(":free"),
                    ),
                )
        self.active_provider = provider
        self.active_model = model
        label = f"{provider}:{model}" if provider else model
        return f"Active model set to {label}."

    def detect_task(self, text: str) -> str:
        lowered = text.lower()
        if any(word in lowered for word in ["code", "python", "javascript", "bug", "debug", "error", "function"]):
            return "code"
        if any(word in lowered for word in ["plan", "analyze", "reason", "compare", "architecture", "strategy"]):
            return "reasoning"
        if any(word in lowered for word in ["write", "story", "creative", "poem", "caption", "rewrite"]):
            return "creative"
        if len(text) < 80:
            return "fast"
        return "default"

    def list_models(self) -> str:
        if not self.profiles:
            return "No model providers configured."
        lines = ["Configured models:"]
        for index, profile in enumerate(self.profiles, start=1):
            marker = "* " if profile.model == self.active_model else "  "
            lines.append(f"{marker}{index}. {profile.label}")
        lines.append(f"Free-only routing: {self.free_only}")
        return "\n".join(lines)

    def call(self, messages: List[Dict[str, str]], temperature: float, task: str) -> tuple[str, ModelProfile]:
        profiles = self.choose(task)
        if not profiles:
            raise RuntimeError("No model provider configured. Add OPENROUTER_API_KEY, GROQ_API_KEY, or CUSTOM_OPENAI_* to .env.")

        errors = []
        for profile in profiles:
            try:
                response = requests.post(
                    profile.chat_url,
                    headers=self.headers(profile),
                    json={
                        "model": profile.model,
                        "messages": messages,
                        "temperature": temperature,
                    },
                    timeout=60,
                )
                if response.status_code in {401, 403, 404, 429, 500, 502, 503, 504}:
                    errors.append(f"{profile.label}: HTTP {response.status_code}")
                    continue
                response.raise_for_status()
                payload = response.json()
                reply = payload["choices"][0]["message"]["content"].strip()
                if reply:
                    self.active_provider = profile.name
                    self.active_model = profile.model
                    return reply, profile
                errors.append(f"{profile.label}: empty response")
            except Exception as exc:
                errors.append(f"{profile.label}: {exc}")

        raise RuntimeError("All model routes failed: " + " | ".join(errors))

    def headers(self, profile: ModelProfile) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {profile.api_key}",
            "Content-Type": "application/json",
        }
        if profile.name == "openrouter":
            headers["HTTP-Referer"] = os.getenv("OPENROUTER_SITE_URL", "http://localhost")
            headers["X-Title"] = os.getenv("OPENROUTER_APP_NAME", "ARISE")
        return headers


@dataclass
class LocalMemory:
    path: Path
    data: Dict[str, Any] = field(default_factory=dict)

    def load(self) -> None:
        if not self.path.exists():
            self.data = {}
            return

        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            self.data = {}

    def save(self) -> None:
        self.path.write_text(
            json.dumps(self.data, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def remember(self, key: str, value: str) -> str:
        cleaned_key = key.strip().lower().replace(" ", "_")
        if not cleaned_key:
            raise ToolError("Memory key cannot be empty.")
        self.data[cleaned_key] = {
            "value": value.strip(),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
        self.save()
        return f"Remembered {cleaned_key}."

    def recall(self, key: Optional[str] = None) -> str:
        if not self.data:
            return "No memory saved yet."

        if key:
            cleaned_key = key.strip().lower().replace(" ", "_")
            item = self.data.get(cleaned_key)
            if not item:
                return f"No memory found for {cleaned_key}."
            return f"{cleaned_key}: {item['value']}"

        lines = [f"- {name}: {item['value']}" for name, item in self.data.items()]
        return "\n".join(lines)

    def forget(self, key: str) -> str:
        cleaned_key = key.strip().lower().replace(" ", "_")
        if cleaned_key in self.data:
            del self.data[cleaned_key]
            self.save()
            return f"Forgot {cleaned_key}."
        return f"No memory found for {cleaned_key}."

    def context(self, limit: int = 12) -> str:
        if not self.data:
            return "No saved memory."
        items = list(self.data.items())[:limit]
        return "\n".join(f"- {name}: {item['value']}" for name, item in items)


@dataclass
class AriseAgent:
    creator_name: str = "Vimal Kumar"
    temperature: float = 0.25
    max_history_messages: int = 16

    router: ModelRouter = field(init=False)
    conversation: List[Dict[str, str]] = field(default_factory=list, init=False)
    memory: LocalMemory = field(init=False)
    cyber_safety: CyberSafetyLayer = field(init=False)

    def __post_init__(self) -> None:
        load_dotenv()

        try:
            self.temperature = float(os.getenv("ARISE_TEMPERATURE", self.temperature))
        except ValueError:
            self.temperature = 0.25
        memory_path = Path(os.getenv("ARISE_MEMORY_FILE", "arise_memory.json"))
        self.memory = LocalMemory(memory_path)
        self.memory.load()
        self.cyber_safety = CyberSafetyLayer.from_env()

        self.router = ModelRouter.from_env()
        if not self.router.profiles:
            print("ERROR: No model provider configured in .env")
            print("Add OPENROUTER_API_KEY, GROQ_API_KEY, or CUSTOM_OPENAI_* settings.")
            sys.exit(1)

        self.conversation.append({"role": "system", "content": SYSTEM_RULES})

    def run(self) -> None:
        print("=" * 44)
        print(f"ARISE Agent Online - Creator: {self.creator_name}")
        print("Type /help for tools, /exit to quit.")
        print("=" * 44)

        while True:
            try:
                user_input = input("\nYou: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nARISE: Session closed.")
                break

            if not user_input:
                continue

            if user_input.lower() in {"/exit", "exit", "quit", "bye"}:
                print("ARISE: Goodbye, Creator.")
                break

            start = time.time()
            reply = self.respond(user_input)
            elapsed = time.time() - start
            print(f"\nARISE: {reply}")
            print(f"[{elapsed:.2f}s]")

    def respond(self, user_input: str) -> str:
        command_reply = self.try_command(user_input)
        if command_reply is not None:
            return command_reply

        safety_assessment = self.cyber_safety.assess(user_input)
        if safety_assessment.verdict == "blocked":
            self.cyber_safety.audit("blocked_prompt", user_input, safety_assessment)
            return (
                safety_assessment.format()
                + "\n\nARISE can help reframe this into authorized defense, detection, recovery, or hardening."
            )

        tool_context = self.auto_tool_context(user_input)
        prompt = user_input
        if tool_context:
            prompt = f"{user_input}\n\nLocal tool context:\n{tool_context}"
        if safety_assessment.verdict == "approval_required":
            prompt = f"{prompt}\n\nSafety gate:\n{safety_assessment.format()}"

        self.conversation.append({"role": "user", "content": prompt})
        self.trim_history()
        task = self.router.detect_task(user_input)

        try:
            reply, profile = self.router.call(
                messages=self.conversation,
                temperature=self.temperature,
                task=task,
            )
            if os.getenv("ARISE_SHOW_ROUTE", "false").lower() == "true":
                reply = f"{reply}\n\n[route: {task} -> {profile.label}]"
        except Exception as exc:
            reply = f"System error while contacting model router: {exc}"

        if not reply:
            reply = "No response received from the model."

        self.conversation.append({"role": "assistant", "content": reply})
        self.trim_history()
        return reply

    def try_command(self, text: str) -> Optional[str]:
        if not text.startswith("/"):
            return None

        command, _, rest = text.partition(" ")
        command = command.lower()
        rest = rest.strip()

        try:
            if command == "/help":
                return self.help_text()
            if command == "/clear":
                self.conversation = [{"role": "system", "content": SYSTEM_RULES}]
                return "Conversation history cleared."
            if command == "/memory":
                return self.memory.recall()
            if command == "/remember":
                key, sep, value = rest.partition("=")
                if not sep:
                    return "Use: /remember key = value"
                return self.memory.remember(key, value)
            if command == "/recall":
                return self.memory.recall(rest or None)
            if command == "/forget":
                if not rest:
                    return "Use: /forget key"
                return self.memory.forget(rest)
            if command == "/calc":
                if not rest:
                    return "Use: /calc 12 * (4 + 3)"
                return str(self.safe_eval(rest))
            if command == "/plan":
                if not rest:
                    return "Use: /plan your goal"
                return self.make_plan(rest)
            if command == "/guard":
                if not rest:
                    return "Use: /guard command-or-action"
                return self.cyber_safety.guard_action(rest)
            if command == "/cyber":
                if not rest:
                    return "Use: /cyber request-to-classify"
                return self.cyber_safety.classify_request(rest)
            if command == "/incident":
                if not rest:
                    return "Use: /incident scenario"
                return self.cyber_safety.incident_plan(rest)
            if command == "/sandbox":
                return self.cyber_safety.status()
            if command == "/models":
                return self.router.list_models()
            if command == "/model":
                if not rest:
                    return "Use: /model provider:model-name or /model model-name"
                return self.router.set_active(rest)
            if command == "/route":
                if not rest:
                    return "Use: /route your prompt"
                task = self.router.detect_task(rest)
                candidates = self.router.choose(task)
                if not candidates:
                    return f"Route: {task}\nNo candidate models configured."
                lines = [f"Route: {task}", "Candidate order:"]
                lines.extend(f"- {profile.label}" for profile in candidates)
                return "\n".join(lines)
            if command == "/status":
                return self.status()
        except ToolError as exc:
            return f"Tool error: {exc}"

        return "Unknown command. Type /help for available tools."

    def auto_tool_context(self, text: str) -> str:
        lowered = text.lower()
        blocks = [f"Saved memory:\n{self.memory.context()}"]

        if self.cyber_safety.is_cyber_related(text):
            blocks.append(self.cyber_safety.policy_context())

        if any(word in lowered for word in ["time", "date", "today"]):
            blocks.append(f"Local datetime: {datetime.now().isoformat(timespec='seconds')}")

        if lowered.startswith(("calculate ", "calc ")) or " calculate " in lowered:
            if lowered.startswith("calc "):
                expression = text[5:].strip()
            else:
                expression = text.lower().split("calculate", 1)[-1].strip()
            if expression:
                try:
                    blocks.append(f"Calculation result: {self.safe_eval(expression)}")
                except ToolError:
                    pass

        return "\n\n".join(blocks)

    def make_plan(self, goal: str) -> str:
        steps = [
            "1. Define the exact outcome and constraints.",
            "2. Break the work into the smallest useful milestones.",
            "3. Identify tools, files, data, and risks before execution.",
            "4. Execute one milestone at a time and verify the result.",
            "5. Summarize what changed and what remains.",
        ]
        return f"Goal: {goal}\n" + "\n".join(steps)

    def safe_eval(self, expression: str) -> Any:
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError as exc:
            raise ToolError("Invalid math expression.") from exc
        return self._eval_node(tree.body)

    def _eval_node(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.Name) and node.id in SAFE_CONSTANTS:
            return SAFE_CONSTANTS[node.id]
        if isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPERATORS:
            left = self._eval_node(node.left)
            right = self._eval_node(node.right)
            return SAFE_OPERATORS[type(node.op)](left, right)
        if isinstance(node, ast.UnaryOp) and type(node.op) in SAFE_OPERATORS:
            return SAFE_OPERATORS[type(node.op)](self._eval_node(node.operand))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            func = SAFE_FUNCTIONS.get(node.func.id)
            if not func:
                raise ToolError("Function is not allowed.")
            args = [self._eval_node(arg) for arg in node.args]
            return func(*args)
        raise ToolError("Only safe math expressions are allowed.")

    def trim_history(self) -> None:
        system = self.conversation[:1]
        history = self.conversation[1:]
        if len(history) > self.max_history_messages:
            history = history[-self.max_history_messages :]
        self.conversation = system + history

    def status(self) -> str:
        active = self.router.active_model or "auto"
        provider = self.router.active_provider or "auto"
        return "\n".join(
            [
                f"Provider: {provider}",
                f"Model: {active}",
                f"Temperature: {self.temperature}",
                f"Free-only routing: {self.router.free_only}",
                f"Configured routes: {len(self.router.profiles)}",
                self.cyber_safety.status(),
                f"Memory file: {self.memory.path}",
                f"Saved memories: {len(self.memory.data)}",
                f"History messages: {len(self.conversation) - 1}",
            ]
        )

    def help_text(self) -> str:
        return "\n".join(
            [
                "Available ARISE tools:",
                "/help - show this menu",
                "/status - show model, memory, and history status",
                "/remember key = value - save a memory",
                "/recall key - recall one memory",
                "/memory - list saved memories",
                "/forget key - delete one memory",
                "/calc expression - run a safe calculator",
                "/plan goal - create an execution plan",
                "/guard action - review a risky command/action before use",
                "/cyber request - classify a cyber request safely",
                "/incident scenario - create a defensive response checklist",
                "/sandbox - show cyber sandbox status",
                "/models - list configured model routes",
                "/model provider:model - switch active model",
                "/route prompt - preview routing for a prompt",
                "/clear - clear chat history",
                "/exit - quit ARISE",
            ]
        )


if __name__ == "__main__":
    AriseAgent().run()
