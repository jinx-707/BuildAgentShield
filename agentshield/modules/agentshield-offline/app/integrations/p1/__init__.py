"""
AgentShield — P1 ↔ P2 Integration Package.

Bridges Person 1's penetration-prevention security engine with
Person 2's offline security module via the existing ContentInspectionPort
and DataInspectionPort interfaces defined in app/integrations/ports.py.

To activate:
    pip install -e ".[p1]"                     # installs presidio + spacy
    python -m spacy download en_core_web_lg    # NLP model for PII detection

    Set in .env:
        AGENTSHIELD_P1_ENABLED=true
        AGENTSHIELD_P1_MODULE_PATH=../../penetration-prevention--main  # or installed pkg
"""
