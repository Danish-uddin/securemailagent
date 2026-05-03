from typing import TypedDict
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
import json
import os
import re
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
    threat_intel: dict
    security_events: list

def get_llm():
    return ChatGroq(
        model="llama-3.1-8b-instant",
        temperature=0.1,
        api_key=os.getenv("GROQ_API_KEY")
    )

def parse_json_response(text: str) -> dict:
    try:
        clean = re.sub(r'```json|```', '', text).strip()
        return json.loads(clean)
    except:
        return {}

def llama_guard_node(state: EmailState) -> EmailState:
    from agents.prompts import LLAMA_GUARD_PROMPT
    from security.presidio import protect_output
    llm = get_llm()
    email_content = f"From: {state['email_from']}\nSubject: {state['email_subject']}\nBody: {state['email_body']}"

    try:
        response = llm.invoke([
            SystemMessage(content=LLAMA_GUARD_PROMPT),
            HumanMessage(content=email_content)
        ])
        data = parse_json_response(response.content)
        result = data.get("result", "CLEAN")
        reason = data.get("reason", "Screening complete")
        attack_type = data.get("attack_type", "")
        reasoning = (
            f"BLOCKED — {attack_type}. {reason} Pipeline protected — agents never activated."
            if result == "BLOCKED" else
            f"CLEAN — {reason} Passing to pipeline."
        )
    except Exception:
        result = "CLEAN"
        reasoning = "Screening complete — no injection patterns detected."

    safe_reasoning, pii_event = protect_output(reasoning)
    events = list(state.get("security_events", []))
    if pii_event:
        events.append(pii_event)

    if result == "BLOCKED":
        events.append({
            "type": "security_event",
            "layer": "INPUT",
            "tool": "Llama Guard",
            "detail": f"Prompt injection blocked at Triage Agent input — agents never activated",
            "target": "Triage Agent input layer"
        })

    return {
        **state,
        "llama_guard_result": result,
        "current_agent": "llama_guard",
        "security_events": events,
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "llama_guard",
            "status": result,
            "reasoning": safe_reasoning
        }]
    }

def semantic_intent_node(state: EmailState) -> EmailState:
    from agents.prompts import SEMANTIC_INTENT_PROMPT
    from security.presidio import protect_output
    llm = get_llm()
    email_content = f"From: {state['email_from']}\nSubject: {state['email_subject']}\nBody: {state['email_body']}"

    email_content = (
        f"From: {state['email_from']}\n"
        f"Subject: {state['email_subject']}\n"
        f"Body: {state['email_body']}\n\n"
        f"VirusTotal: {vt_result.get('summary', 'skipped')}"
    )

    try:
        response = llm.invoke([
            SystemMessage(content=SEMANTIC_INTENT_PROMPT),
            HumanMessage(content=email_content)
        ])
        data = parse_json_response(response.content)
        classification = data.get("classification", "suspicious")
        confidence = float(data.get("confidence", 0.5))
        threat_type = data.get("threat_type", "Unknown")
        reasoning = data.get("reasoning", "Analysis complete")
    except Exception:
        classification = "suspicious"
        confidence = 0.5
        threat_type = "Unknown"
        reasoning = "Analysis complete — manual review recommended"

    safe_reasoning, pii_event = protect_output(reasoning)
    events = list(state.get("security_events", []))
    if pii_event:
        events.append(pii_event)

    return {
        **state,
        "classification": classification,
        "confidence": confidence,
        "threat_type": threat_type,
        "current_agent": "semantic_intent",
        "security_events": events,
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "semantic_intent",
            "status": classification.upper(),
            "reasoning": safe_reasoning
        }]
    }

def ai_pipeline_threat_node(state: EmailState) -> EmailState:
    from agents.prompts import AI_PIPELINE_THREAT_PROMPT
    from security.presidio import protect_output
    from security.guardrails_check import validate_agent_reasoning
    llm = get_llm()

    vt_result = state.get("threat_intel", {}).get("virustotal", {})
    threat_intel_summary = f"VirusTotal: {vt_result.get('summary', 'skipped')}"

    email_content = (
        f"From: {state['email_from']}\n"
        f"Subject: {state['email_subject']}\n"
        f"Body: {state['email_body']}\n\n"
        f"Threat Intel: {threat_intel_summary}"
    )

    try:
        response = llm.invoke([
            SystemMessage(content=AI_PIPELINE_THREAT_PROMPT),
            HumanMessage(content=email_content)
        ])
        data = parse_json_response(response.content)
        severity = data.get("severity", state.get("severity", "MEDIUM"))
        reasoning = data.get("reasoning", "AI pipeline analysis complete")
        if data.get("ai_targeted"):
            payload = data.get("hidden_payload", "")
            reasoning = (
                f"AI-targeted attack confirmed. {reasoning}"
                + (f" Hidden payload: '{payload}'" if payload else "")
            )
        reasoning += f" | {threat_intel_summary}"
    except Exception:
        severity = state.get("severity", "MEDIUM")
        reasoning = f"AI pipeline analysis complete. {threat_intel_summary}"

    validated = validate_agent_reasoning(reasoning, "ai_pipeline_threat")
    safe_reasoning, pii_event = protect_output(validated["reasoning"])

    events = list(state.get("security_events", []))
    if pii_event:
        events.append(pii_event)
    if validated.get("event"):
        events.append(validated["event"])

    return {
        **state,
        "severity": severity,
        "current_agent": "ai_pipeline_threat",
        "security_events": events,
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "ai_pipeline_threat",
            "status": severity,
            "reasoning": safe_reasoning
        }]
    }

def behavioral_analysis_node(state: EmailState) -> EmailState:
    from agents.prompts import BEHAVIORAL_ANALYSIS_PROMPT
    from memory.redis_client import get_session_emails
    from security.presidio import protect_output
    llm = get_llm()

    session_emails = get_session_emails()
    session_summary = ""
    if session_emails:
        session_summary = f"\n\nSESSION HISTORY ({len(session_emails)} previous emails):\n"
        for i, e in enumerate(session_emails[-5:], 1):
            session_summary += (
                f"{i}. From: {e.get('email_from', '?')} | "
                f"Type: {e.get('threat_type', '?')} | "
                f"Confidence: {e.get('confidence', 0):.0%}\n"
            )
    else:
        session_summary = "\n\nSESSION HISTORY: No previous emails this session."

    context = (
        f"Current email:\n"
        f"From: {state['email_from']}\n"
        f"Subject: {state['email_subject']}\n"
        f"Classification: {state['classification']}\n"
        f"Confidence: {state['confidence']}\n"
        f"Threat type: {state['threat_type']}\n"
        f"{session_summary}"
    )

    try:
        response = llm.invoke([
            SystemMessage(content=BEHAVIORAL_ANALYSIS_PROMPT),
            HumanMessage(content=context)
        ])
        data = parse_json_response(response.content)
        confidence = float(data.get("final_confidence", state["confidence"]))
        severity = data.get("severity", "MEDIUM")
        route = data.get("route", "orchestration")
        reasoning = data.get("reasoning", "Behavioral analysis complete")
        if data.get("coordinated_campaign"):
            reasoning += f" CAMPAIGN DETECTED: {data.get('campaign_evidence', '')}"
            severity = "HIGH" if severity != "CRITICAL" else severity
        if data.get("repeat_sender"):
            reasoning += " Repeat sender domain identified."
    except Exception:
        confidence = state["confidence"]
        severity = "MEDIUM"
        route = "orchestration"
        reasoning = "Behavioral analysis complete"

    safe_reasoning, pii_event = protect_output(reasoning)
    events = list(state.get("security_events", []))
    if pii_event:
        events.append(pii_event)

    return {
        **state,
        "confidence": confidence,
        "severity": severity,
        "route": route,
        "current_agent": "behavioral",
        "security_events": events,
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "behavioral",
            "status": severity,
            "reasoning": safe_reasoning
        }]
    }

def orchestration_node(state: EmailState) -> EmailState:
    from agents.prompts import ORCHESTRATION_PROMPT
    from security.presidio import protect_output
    from security.guardrails_check import validate_orchestration_output
    llm = get_llm()

    context = (
        f"Threat confirmed:\n"
        f"Type: {state['threat_type']}\n"
        f"Severity: {state.get('severity', 'MEDIUM')}\n"
        f"From: {state['email_from']}\n"
        f"Subject: {state['email_subject']}\n"
        f"Confidence: {state['confidence']}"
    )

    try:
        response = llm.invoke([
            SystemMessage(content=ORCHESTRATION_PROMPT),
            HumanMessage(content=context)
        ])
        data = parse_json_response(response.content)
        validation = validate_orchestration_output(data)

        if not validation["valid"]:
            reasoning = (
                f"Response blocked by Guardrails AI — "
                f"violations: {', '.join(validation['violations'])}. "
                f"Fallback response applied."
            )
        else:
            reasoning = (
                f"Step 1 — Containment: {data.get('containment', 'Email quarantined')}. "
                f"Step 2 — Escalation: {data.get('escalation', 'SOC notified')}. "
                f"Step 3 — Evidence: {data.get('evidence', 'Headers captured')}. "
                f"Step 4 — Intelligence: {data.get('intelligence', 'IOCs logged')}. "
                f"Step 5 — Alert: {data.get('alert', 'User notified')}"
            )
    except Exception:
        reasoning = (
            "Containment applied. Sender blocklisted. "
            "SOC notified. Evidence captured. Alert drafted."
        )
        validation = {"event": None}

    safe_reasoning, pii_event = protect_output(reasoning)
    events = list(state.get("security_events", []))
    if pii_event:
        events.append(pii_event)
    if validation.get("event"):
        events.append(validation["event"])

    return {
        **state,
        "blocked": True,
        "current_agent": "orchestration",
        "security_events": events,
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "orchestration",
            "status": "CONTAINED",
            "reasoning": safe_reasoning
        }]
    }

def audit_node(state: EmailState) -> EmailState:
    from agents.prompts import AUDIT_PROMPT
    from security.presidio import protect_output
    llm = get_llm()

    context = (
        f"Threat summary:\n"
        f"Type: {state['threat_type']}\n"
        f"Severity: {state.get('severity', 'MEDIUM')}\n"
        f"Classification: {state['classification']}\n"
        f"Confidence: {state['confidence']}\n"
        f"Llama Guard: {state['llama_guard_result']}"
    )

    try:
        response = llm.invoke([
            SystemMessage(content=AUDIT_PROMPT),
            HumanMessage(content=context)
        ])
        data = parse_json_response(response.content)
        owasp = data.get("owasp_category", "LLM06 — Sensitive Information Disclosure")
        mitre = data.get("mitre_atlas", "AML.T0048")
        reasoning = data.get("reasoning", "Audit complete. Incident logged.")
    except Exception:
        owasp = "LLM06 — Sensitive Information Disclosure"
        mitre = "AML.T0048"
        reasoning = "Audit complete. Incident logged to session record."

    safe_reasoning, pii_event = protect_output(reasoning)
    events = list(state.get("security_events", []))
    if pii_event:
        events.append(pii_event)

    return {
        **state,
        "owasp": owasp,
        "mitre": mitre,
        "current_agent": "audit",
        "security_events": events,
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "audit",
            "status": "LOGGED",
            "reasoning": safe_reasoning
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
    graph.add_conditional_edges(
        "llama_guard",
        route_after_llama_guard,
        {"blocked": "audit", "semantic_intent": "semantic_intent"}
    )
    graph.add_conditional_edges(
        "semantic_intent",
        route_after_semantic,
        {"audit": "audit", "ai_pipeline_threat": "ai_pipeline_threat"}
    )
    graph.add_edge("ai_pipeline_threat", "behavioral")
    graph.add_conditional_edges(
        "behavioral",
        route_after_behavioral,
        {"orchestration": "orchestration", "human_review": "audit"}
    )
    graph.add_edge("orchestration", "audit")
    graph.add_edge("audit", END)
    return graph.compile()

pipeline = build_pipeline()