from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

provider = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
})
nlp_engine = provider.create_engine()
analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
anonymizer = AnonymizerEngine()

# Add SSN pattern recognizer
ssn_recognizer = PatternRecognizer(
    supported_entity="US_SSN",
    patterns=[Pattern(
        name="ssn",
        regex=r"\b\d{3}-\d{2}-\d{4}\b",
        score=0.9
    )]
)

# Add Credit Card pattern recognizer
cc_recognizer = PatternRecognizer(
    supported_entity="CREDIT_CARD",
    patterns=[Pattern(
        name="credit_card",
        regex=r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        score=0.9
    )]
)

# Add phone pattern recognizer
phone_recognizer = PatternRecognizer(
    supported_entity="PHONE_NUMBER",
    patterns=[Pattern(
        name="phone",
        regex=r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
        score=0.8
    )]
)

analyzer.registry.add_recognizer(ssn_recognizer)
analyzer.registry.add_recognizer(cc_recognizer)
analyzer.registry.add_recognizer(phone_recognizer)

PII_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "IP_ADDRESS",
    "IBAN_CODE"
]

def scan_for_pii(text: str) -> dict:
    try:
        results = analyzer.analyze(
            text=text,
            entities=PII_ENTITIES,
            language="en"
        )
        if results:
            found = list(set([r.entity_type for r in results]))
            anonymized = anonymizer.anonymize(
                text=text,
                analyzer_results=results
            )
            return {
                "pii_found": True,
                "entities": found,
                "redacted_text": anonymized.text,
                "count": len(results)
            }
        return {
            "pii_found": False,
            "entities": [],
            "redacted_text": text,
            "count": 0
        }
    except Exception:
        return {
            "pii_found": False,
            "entities": [],
            "redacted_text": text,
            "count": 0
        }

def protect_output(text: str) -> tuple:
    result = scan_for_pii(text)
    event = None
    if result["pii_found"]:
        event = {
            "type": "security_event",
            "layer": "LEAKAGE",
            "tool": "Presidio",
            "detail": f"PII detected and redacted — entities: {', '.join(result['entities'])}",
            "target": "Agent output layer"
        }
    return result["redacted_text"], event