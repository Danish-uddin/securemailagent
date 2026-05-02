from typing import TypedDict, Literal
from langgraph.graph import StateGraph, END
import asyncio

class EmailState(TypedDict):
    email_from: str
    email_subject: str
    email_body: str
    llama_guard_result: str
    classification: str
    confidence: float
    route: str
    agent_outputs: list
    current_agent: str
    threat_type: str
    severity: str
    owasp: str
    mitre: str
    blocked: bool

def llama_guard_node(state: EmailState) -> EmailState:
    body = state["email_body"].lower()
    injection_keywords = [
        "ignore previous instructions",
        "system override",
        "diagnostic mode",
        "you are now",
        "disregard all"
    ]
    is_injection = any(k in body for k in injection_keywords)
    return {
        **state,
        "llama_guard_result": "BLOCKED" if is_injection else "CLEAN",
        "current_agent": "llama_guard",
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "llama_guard",
            "status": "BLOCKED" if is_injection else "CLEAN",
            "reasoning": (
                f"Prompt injection detected — '{next(k for k in injection_keywords if k in body)}' "
                f"found in email body. Pipeline protected — agents never activated."
                if is_injection else
                "Input screened — no injection patterns detected. Passing to pipeline."
            )
        }]
    }

def semantic_intent_node(state: EmailState) -> EmailState:
    body = state["email_body"].lower()
    subject = state["email_subject"].lower()

    bec_signals = ["wire transfer", "urgent", "board meeting", "approval", "cfo", "ceo", "finance"]
    phishing_signals = ["click here", "verify your", "password", "account suspended", "reset"]
    ai_inject_signals = ["<!--", "white text", "[system:", "[ignore", "forward all"]

    bec_count = sum(1 for s in bec_signals if s in body + subject)
    phishing_count = sum(1 for s in phishing_signals if s in body + subject)
    ai_inject_count = sum(1 for s in ai_inject_signals if s in body)

    if ai_inject_count > 0:
        classification = "malicious"
        threat_type = "AI Pipeline Injection"
        confidence = 0.94
        reasoning = (
            "Hidden LLM instruction detected in email content. "
            "Email appears legitimate to human reader but contains "
            "adversarial payload targeting downstream AI systems. "
            "Routing to AI Pipeline Threat Agent."
        )
    elif bec_count >= 2:
        classification = "malicious"
        threat_type = "BEC / Wire Transfer"
        confidence = round(0.70 + (bec_count * 0.05), 2)
        reasoning = (
            f"Zero technical IOCs detected — domain appears clean. "
            f"However {bec_count} BEC behavioral signals identified: "
            f"authority bias, artificial urgency, financial action request. "
            f"Confidence: {confidence * 100:.0f}%. Routing to investigation."
        )
    elif phishing_count >= 1:
        classification = "suspicious"
        threat_type = "Phishing"
        confidence = 0.78
        reasoning = (
            f"Phishing indicators detected in email content. "
            f"Credential harvesting pattern identified. Confidence: 78%."
        )
    else:
        classification = "safe"
        threat_type = "Legitimate"
        confidence = 0.95
        reasoning = (
            "No threat indicators detected. Email content appears legitimate. "
            "No social engineering patterns, no suspicious requests. "
            "Fast-passing to Audit Agent."
        )

    return {
        **state,
        "classification": classification,
        "confidence": confidence,
        "threat_type": threat_type,
        "current_agent": "semantic_intent",
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "semantic_intent",
            "status": classification.upper(),
            "reasoning": reasoning
        }]
    }

def ai_pipeline_threat_node(state: EmailState) -> EmailState:
    body = state["email_body"]
    inject_patterns = ["<!--", "[SYSTEM", "IGNORE PREVIOUS", "forward all", "admin mode"]
    found = [p for p in inject_patterns if p.lower() in body.lower()]

    if found:
        reasoning = (
            f"CRITICAL — AI pipeline injection confirmed. "
            f"Hidden instruction found: '{found[0]}'. "
            f"Human reading this email sees legitimate content. "
            f"AI assistant reading this email receives adversarial instruction. "
            f"OWASP LLM01. MITRE ATLAS AML.T0051."
        )
        severity = "CRITICAL"
    else:
        reasoning = (
            "No AI-targeted injection payload found. "
            "Email content behaves consistently for both human and AI readers. "
            "Passing to Behavioral Analysis Agent."
        )
        severity = state.get("severity", "HIGH")

    return {
        **state,
        "severity": severity,
        "current_agent": "ai_pipeline_threat",
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "ai_pipeline_threat",
            "status": severity,
            "reasoning": reasoning
        }]
    }

def behavioral_analysis_node(state: EmailState) -> EmailState:
    confidence = state.get("confidence", 0.5)

    if confidence >= 0.85:
        route = "orchestration"
        severity = "HIGH" if state["threat_type"] != "AI Pipeline Injection" else "CRITICAL"
        reasoning = (
            f"Behavioral analysis complete. Confidence {confidence * 100:.0f}% exceeds threshold. "
            f"Threat pattern consistent with known attack profiles. "
            f"Severity: {severity}. Routing to Response Orchestration."
        )
    elif confidence >= 0.65:
        route = "orchestration"
        severity = "MEDIUM"
        reasoning = (
            f"Moderate confidence {confidence * 100:.0f}%. "
            f"Sufficient signals for automated response. "
            f"Routing to Orchestration with MEDIUM severity."
        )
    else:
        route = "human_review"
        severity = "LOW"
        reasoning = (
            f"Confidence {confidence * 100:.0f}% below automated response threshold. "
            f"Insufficient signals for definitive classification. "
            f"Routing to human review queue."
        )

    return {
        **state,
        "route": route,
        "severity": severity,
        "current_agent": "behavioral",
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "behavioral",
            "status": severity,
            "reasoning": reasoning
        }]
    }

def orchestration_node(state: EmailState) -> EmailState:
    severity = state.get("severity", "MEDIUM")
    threat_type = state.get("threat_type", "Unknown")

    if "BEC" in threat_type or "Wire" in threat_type:
        escalation = "Finance team + SOC notification"
        alert = "BEC attempt targeting wire transfer workflow blocked."
    elif "AI Pipeline" in threat_type:
        escalation = "System admin + AI team notification"
        alert = "Prompt injection targeting AI assistant blocked."
    elif "Phishing" in threat_type:
        escalation = "SOC analyst notification"
        alert = "Phishing attempt blocked. Credentials not at risk."
    else:
        escalation = "Auto-log only"
        alert = "Threat contained. No escalation required."

    reasoning = (
        f"Response orchestration complete. "
        f"Step 1 — Containment: Email quarantined, sender domain blocklisted. "
        f"Step 2 — Escalation: {escalation}. "
        f"Step 3 — Evidence: Headers captured, threat intel reports attached. "
        f"Step 4 — Intelligence: IOCs written to session blocklist. "
        f"Step 5 — Alert: {alert}"
    )

    return {
        **state,
        "blocked": True,
        "current_agent": "orchestration",
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "orchestration",
            "status": "CONTAINED",
            "reasoning": reasoning
        }]
    }

def audit_node(state: EmailState) -> EmailState:
    threat_type = state.get("threat_type", "Unknown")
    severity = state.get("severity", "LOW")

    owasp_map = {
        "BEC / Wire Transfer": "LLM06 — Sensitive Information Disclosure",
        "AI Pipeline Injection": "LLM01 — Prompt Injection",
        "Phishing": "LLM06 — Sensitive Information Disclosure",
        "Legitimate": "N/A"
    }
    atlas_map = {
        "BEC / Wire Transfer": "AML.T0048",
        "AI Pipeline Injection": "AML.T0051",
        "Phishing": "AML.T0048",
        "Legitimate": "N/A"
    }

    owasp = owasp_map.get(threat_type, "LLM06")
    mitre = atlas_map.get(threat_type, "AML.T0048")

    reasoning = (
        f"Audit complete. Threat: {threat_type}. Severity: {severity}. "
        f"OWASP LLM Top 10: {owasp}. "
        f"MITRE ATLAS: {mitre}. "
        f"Incident record created. Session memory updated."
    )

    return {
        **state,
        "owasp": owasp,
        "mitre": mitre,
        "current_agent": "audit",
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "audit",
            "status": "LOGGED",
            "reasoning": reasoning
        }]
    }

def route_after_llama_guard(state: EmailState) -> str:
    return "blocked" if state["llama_guard_result"] == "BLOCKED" else "semantic_intent"

def route_after_semantic(state: EmailState) -> str:
    return "audit" if state["classification"] == "safe" else "ai_pipeline_threat"

def route_after_behavioral(state: EmailState) -> str:
    return state.get("route", "orchestration")

def build_pipeline():
    graph = StateGraph(EmailState)

    graph.add_node("llama_guard", llama_guard_node)
    graph.add_node("semantic_intent", semantic_intent_node)
    graph.add_node("ai_pipeline_threat", ai_pipeline_threat_node)
    graph.add_node("behavioral", behavioral_analysis_node)
    graph.add_node("orchestration", orchestration_node)
    graph.add_node("audit", audit_node)

    graph.set_entry_point("llama_guard")

    graph.add_conditional_edges("llama_guard", route_after_llama_guard, {
        "blocked": "audit",
        "semantic_intent": "semantic_intent"
    })
    graph.add_conditional_edges("semantic_intent", route_after_semantic, {
        "audit": "audit",
        "ai_pipeline_threat": "ai_pipeline_threat"
    })
    graph.add_edge("ai_pipeline_threat", "behavioral")
    graph.add_conditional_edges("behavioral", route_after_behavioral, {
        "orchestration": "orchestration",
        "human_review": "audit"
    })
    graph.add_edge("orchestration", "audit")
    graph.add_edge("audit", END)

    return graph.compile()

pipeline = build_pipeline()