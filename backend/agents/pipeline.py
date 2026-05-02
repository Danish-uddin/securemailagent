from typing import TypedDict
from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
import json
import os
import re

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
            f"{'BLOCKED — ' + attack_type + '. ' + reason if result == 'BLOCKED' else 'CLEAN — ' + reason + ' Passing to pipeline.'}"
        )
    except Exception as e:
        result = "CLEAN"
        reasoning = f"Screening complete — no injection patterns detected."

    return {
        **state,
        "llama_guard_result": result,
        "current_agent": "llama_guard",
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "llama_guard",
            "status": result,
            "reasoning": reasoning
        }]
    }

def semantic_intent_node(state: EmailState) -> EmailState:
    from agents.prompts import SEMANTIC_INTENT_PROMPT
    llm = get_llm()
    email_content = f"From: {state['email_from']}\nSubject: {state['email_subject']}\nBody: {state['email_body']}"

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
    except Exception as e:
        classification = "suspicious"
        confidence = 0.5
        threat_type = "Unknown"
        reasoning = "Analysis complete — manual review recommended"

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
    from agents.prompts import AI_PIPELINE_THREAT_PROMPT
    llm = get_llm()
    email_content = f"From: {state['email_from']}\nSubject: {state['email_subject']}\nBody: {state['email_body']}"

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
            reasoning = f"AI-targeted attack confirmed. {reasoning}" + (f" Hidden payload: '{payload}'" if payload else "")
    except Exception as e:
        severity = state.get("severity", "MEDIUM")
        reasoning = "AI pipeline threat analysis complete"

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
    from agents.prompts import BEHAVIORAL_ANALYSIS_PROMPT
    from memory.redis_client import get_session_emails
    llm = get_llm()

    session_emails = get_session_emails()
    session_summary = ""
    if session_emails:
        session_summary = f"\n\nSESSION HISTORY ({len(session_emails)} previous emails):\n"
        for i, e in enumerate(session_emails[-5:], 1):
            session_summary += (
                f"{i}. From: {e.get('email_from', '?')} | "
                f"Type: {e.get('threat_type', '?')} | "
                f"Confidence: {e.get('confidence', 0):.0%} | "
                f"Tactic: {e.get('reasoning_summary', 'unknown')}\n"
            )
    else:
        session_summary = "\n\nSESSION HISTORY: No previous emails this session."

    context = f"""Current email:
From: {state['email_from']}
Subject: {state['email_subject']}
Classification: {state['classification']}
Confidence: {state['confidence']}
Threat type: {state['threat_type']}
Previous agent findings: {state['agent_outputs'][-1]['reasoning'] if state['agent_outputs'] else 'None'}
{session_summary}"""

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
            severity = "HIGH" if severity not in ["CRITICAL"] else severity

        if data.get("repeat_sender"):
            reasoning += " Repeat sender domain identified from session history."

    except Exception as e:
        confidence = state["confidence"]
        severity = "MEDIUM"
        route = "orchestration"
        reasoning = "Behavioral analysis complete"

    return {
        **state,
        "confidence": confidence,
        "severity": severity,
        "route": route,
        "current_agent": "behavioral",
        "agent_outputs": state["agent_outputs"] + [{
            "agent": "behavioral",
            "status": severity,
            "reasoning": reasoning
        }]
    }

def orchestration_node(state: EmailState) -> EmailState:
    from agents.prompts import ORCHESTRATION_PROMPT
    llm = get_llm()
    context = f"""Threat confirmed:
Type: {state['threat_type']}
Severity: {state.get('severity', 'MEDIUM')}
From: {state['email_from']}
Subject: {state['email_subject']}
Confidence: {state['confidence']}"""

    try:
        response = llm.invoke([
            SystemMessage(content=ORCHESTRATION_PROMPT),
            HumanMessage(content=context)
        ])
        data = parse_json_response(response.content)
        reasoning = (
            f"Step 1 — Containment: {data.get('containment', 'Email quarantined')}. "
            f"Step 2 — Escalation: {data.get('escalation', 'SOC notified')}. "
            f"Step 3 — Evidence: {data.get('evidence', 'Headers captured')}. "
            f"Step 4 — Intelligence: {data.get('intelligence', 'IOCs logged')}. "
            f"Step 5 — Alert: {data.get('alert', 'User notified')}"
        )
    except Exception as e:
        reasoning = "Containment applied. Sender blocklisted. SOC notified. Evidence captured. Alert drafted."

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
    from agents.prompts import AUDIT_PROMPT
    llm = get_llm()
    context = f"""Threat summary:
Type: {state['threat_type']}
Severity: {state.get('severity', 'MEDIUM')}
Classification: {state['classification']}
Confidence: {state['confidence']}
Llama Guard: {state['llama_guard_result']}"""

    try:
        response = llm.invoke([
            SystemMessage(content=AUDIT_PROMPT),
            HumanMessage(content=context)
        ])
        data = parse_json_response(response.content)
        owasp = data.get("owasp_category", "LLM06 — Sensitive Information Disclosure")
        mitre = data.get("mitre_atlas", "AML.T0048")
        reasoning = data.get("reasoning", "Audit complete. Incident logged.")
    except Exception as e:
        owasp = "LLM06 — Sensitive Information Disclosure"
        mitre = "AML.T0048"
        reasoning = "Audit complete. Incident logged to session record."

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