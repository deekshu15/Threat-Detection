import pytest


@pytest.fixture
def sample_incident():

    return {

        "incident_id": "INC-1001",

        "title": "Credential Attack",

        "description": "Credential compromise detected.",

        "severity": "Critical",

        "priority": "P1",

        "status": "Open",

        "owner": "SOC",

        "confidence": 0.95,

        "average_risk_score": 88,

        "maximum_risk_score": 97,

        "total_events": 14,

        "affected_hosts": [

            "SERVER-01",

            "SERVER-02",

        ],

        "affected_users": [

            "administrator",

        ],

        "mitre_tactics": [

            "Initial Access",

            "Credential Access",

            "Persistence",

        ],

        "mitre_techniques": [

            "T1078",

            "T1110",

            "T1053",

        ],

        "event_ids": [

            "EV-1",

            "EV-2",

        ],

        "attack_chains": [],

        "graph": {},

        "correlations": [],

        "metadata": {}

    }