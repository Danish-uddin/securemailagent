import json
import re

MAX_OUTPUT_LENGTH = 2000
FORBIDDEN_PATTERNS = [
    r"delete all",
    r"forward to external",
    r"ignore all",
    r"disable security",
    r"system override"
]

def validate_orchestration_output(output: dict) -> dict:
    violations = []

    for field in ["containment", "escalation", "evidence", "intelligence", "alert"]:
        if field not in output:
            violations.append(f"Missing required field: {field}")

    full_text = json.dumps(output).lower()
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, full_text):
            violations.append(f"Forbidden pattern detected: {pattern}")

    if len(full_text) > MAX_OUTPUT_LENGTH:
        violations.append("Output exceeds max length")

    event = None
    if violations:
        event = {
            "type": "security_event",
            "layer": "OUTPUT",
            "tool": "Guardrails AI",
            "detail": f"Output blocked — violations: {', '.join(violations)}",
            "target": "Orchestration Agent output"
        }

    return {
        "valid": len(violations) == 0,
        "violations": violations,
        "output": output if len(violations) == 0 else None,
        "event": event
    }

def validate_agent_reasoning(reasoning: str, agent_name: str) -> dict:
    violations = []

    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, reasoning.lower()):
            violations.append(f"Forbidden pattern in {agent_name}: {pattern}")

    if len(reasoning) > MAX_OUTPUT_LENGTH:
        reasoning = reasoning[:MAX_OUTPUT_LENGTH] + "... [truncated by Guardrails]"

    event = None
    if violations:
        event = {
            "type": "security_event",
            "layer": "OUTPUT",
            "tool": "Guardrails AI",
            "detail": f"Reasoning blocked — violations: {', '.join(violations)}",
            "target": f"{agent_name} reasoning output"
        }

    return {
        "valid": len(violations) == 0,
        "violations": violations,
        "reasoning": reasoning,
        "event": event
    }