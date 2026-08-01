"""
permissions.py

Enterprise IAM Permission Analysis

Responsibilities
----------------
• Effective permission analysis
• Policy simulation
• Least privilege validation
• Access Analyzer helpers
• Compliance checks
• Permission reports
"""

from __future__ import annotations

import logging

from typing import Any

from aws.utils.aws_utils import get_client

logger = logging.getLogger(__name__)


###########################################################################
# Client
###########################################################################

def iam():

    return get_client(

        "iam",

    )


###########################################################################
# Permission Service
###########################################################################

class PermissionService:

    """
    High-level IAM Permission Analysis.
    """

    def __init__(

        self,

    ):

        self.client = iam()


    #######################################################################
    # Simulate Principal Policy
    #######################################################################

    def simulate_principal(

        self,

        policy_source_arn: str,

        actions: list[str],

        resources: list[str],

    ) -> list[dict[str, Any]]:

        response = self.client.simulate_principal_policy(

            PolicySourceArn=policy_source_arn,

            ActionNames=actions,

            ResourceArns=resources,

        )

        return response.get(

            "EvaluationResults",

            [],

        )


    #######################################################################
    # Simulate Custom Policy
    #######################################################################

    def simulate_custom(

        self,

        policy_document: str,

        actions: list[str],

        resources: list[str],

    ) -> list[dict[str, Any]]:

        response = self.client.simulate_custom_policy(

            PolicyInputList=[

                policy_document,

            ],

            ActionNames=actions,

            ResourceArns=resources,

        )

        return response.get(

            "EvaluationResults",

            [],

        )


    #######################################################################
    # Check Action Allowed
    #######################################################################

    def is_allowed(

        self,

        policy_source_arn: str,

        action: str,

        resource: str,

    ) -> bool:

        results = self.simulate_principal(

            policy_source_arn,

            [

                action,

            ],

            [

                resource,

            ],

        )

        if not results:

            return False

        return (

            results[0].get(

                "EvalDecision",

            )

            == "allowed"

        )


    #######################################################################
    # Allowed Actions
    #######################################################################

    def allowed_actions(

        self,

        policy_source_arn: str,

        actions: list[str],

        resource: str,

    ) -> list[str]:

        allowed = []

        results = self.simulate_principal(

            policy_source_arn,

            actions,

            [

                resource,

            ],

        )

        for result in results:

            if (

                result.get(

                    "EvalDecision",

                )

                == "allowed"

            ):

                allowed.append(

                    result["EvalActionName"]

                )

        return allowed


    #######################################################################
    # Denied Actions
    #######################################################################

    def denied_actions(

        self,

        policy_source_arn: str,

        actions: list[str],

        resource: str,

    ) -> list[str]:

        denied = []

        results = self.simulate_principal(

            policy_source_arn,

            actions,

            [

                resource,

            ],

        )

        for result in results:

            if (

                result.get(

                    "EvalDecision",

                )

                != "allowed"

            ):

                denied.append(

                    result["EvalActionName"]

                )

        return denied


    #######################################################################
    # Permission Summary
    #######################################################################

    def summary(

        self,

        policy_source_arn: str,

        actions: list[str],

        resource: str,

    ) -> dict[str, Any]:

        allowed = self.allowed_actions(

            policy_source_arn,

            actions,

            resource,

        )

        denied = self.denied_actions(

            policy_source_arn,

            actions,

            resource,

        )

        return {

            "principal":

            policy_source_arn,

            "allowed":

            allowed,

            "denied":

            denied,

            "allowed_count":

            len(

                allowed,

            ),

            "denied_count":

            len(

                denied,

            ),

        }
        
    #######################################################################
    # Least Privilege Analysis
    #######################################################################

    def least_privilege_score(

        self,

        policy_source_arn: str,

        actions: list[str],

        resource: str,

    ) -> dict[str, Any]:

        summary = self.summary(

            policy_source_arn,

            actions,

            resource,

        )

        total = len(

            actions,

        )

        allowed = summary["allowed_count"]

        score = 100

        if total:

            score = int(

                ((total - allowed) / total)

                * 100

            )

        return {

            "score": score,

            "allowed": allowed,

            "requested": total,

        }


    #######################################################################
    # Detect Wildcard Permissions
    #######################################################################

    def has_wildcard_permissions(

        self,

        policy_document: dict[str, Any],

    ) -> bool:

        for statement in policy_document.get(

            "Statement",

            [],

        ):

            actions = statement.get(

                "Action",

                [],

            )

            resources = statement.get(

                "Resource",

                [],

            )

            if isinstance(

                actions,

                str,

            ):

                actions = [

                    actions,

                ]

            if isinstance(

                resources,

                str,

            ):

                resources = [

                    resources,

                ]

            if "*" in actions:

                return True

            if "*" in resources:

                return True

        return False


    #######################################################################
    # Detect Administrator Access
    #######################################################################

    def has_admin_access(

        self,

        policy_document: dict[str, Any],

    ) -> bool:

        for statement in policy_document.get(

            "Statement",

            [],

        ):

            actions = statement.get(

                "Action",

                [],

            )

            if isinstance(

                actions,

                str,

            ):

                actions = [

                    actions,

                ]

            if (

                "*" in actions

                or

                "iam:*" in actions

            ):

                return True

        return False


    #######################################################################
    # Sensitive Actions
    #######################################################################

    def sensitive_actions(

        self,

        policy_document: dict[str, Any],

    ) -> list[str]:

        sensitive = [

            "iam:*",

            "kms:*",

            "sts:AssumeRole",

            "lambda:InvokeFunction",

            "ec2:*",

            "organizations:*",

        ]

        found = []

        for statement in policy_document.get(

            "Statement",

            [],

        ):

            actions = statement.get(

                "Action",

                [],

            )

            if isinstance(

                actions,

                str,

            ):

                actions = [

                    actions,

                ]

            for action in actions:

                if action in sensitive:

                    found.append(

                        action,

                    )

        return sorted(

            set(

                found,

            )

        )


    #######################################################################
    # Privilege Escalation Indicators
    #######################################################################

    def privilege_escalation_risk(

        self,

        policy_document: dict[str, Any],

    ) -> bool:

        escalation_actions = {

            "iam:PassRole",

            "iam:CreatePolicyVersion",

            "iam:AttachRolePolicy",

            "iam:PutRolePolicy",

            "sts:AssumeRole",

        }

        for statement in policy_document.get(

            "Statement",

            [],

        ):

            actions = statement.get(

                "Action",

                [],

            )

            if isinstance(

                actions,

                str,

            ):

                actions = [

                    actions,

                ]

            if escalation_actions.intersection(

                actions,

            ):

                return True

        return False


    #######################################################################
    # Basic Risk Score
    #######################################################################

    def risk_score(

        self,

        policy_document: dict[str, Any],

    ) -> dict[str, Any]:

        score = 0

        findings = []

        if self.has_wildcard_permissions(

            policy_document,

        ):

            score += 40

            findings.append(

                "Wildcard permissions",

            )

        if self.has_admin_access(

            policy_document,

        ):

            score += 40

            findings.append(

                "Administrator access",

            )

        if self.privilege_escalation_risk(

            policy_document,

        ):

            score += 20

            findings.append(

                "Privilege escalation",

            )

        return {

            "score":

            min(

                score,

                100,

            ),

            "findings":

            findings,

        }


    #######################################################################
    # Compliance Summary
    #######################################################################

    def compliance(

        self,

        policy_document: dict[str, Any],

    ) -> dict[str, Any]:

        return {

            "wildcards":

            self.has_wildcard_permissions(

                policy_document,

            ),

            "administrator":

            self.has_admin_access(

                policy_document,

            ),

            "privilege_escalation":

            self.privilege_escalation_risk(

                policy_document,

            ),

            "risk":

            self.risk_score(

                policy_document,

            ),

            "sensitive_actions":

            self.sensitive_actions(

                policy_document,

            ),

        }
        
    #######################################################################
    # Access Analyzer Status
    #######################################################################

    def access_analyzer_status(

        self,

    ) -> dict[str, Any]:

        try:

            analyzer = get_client(

                "accessanalyzer",

            )

            response = analyzer.list_analyzers()

            analyzers = response.get(

                "analyzers",

                [],

            )

            return {

                "enabled":

                len(

                    analyzers,

                ) > 0,

                "analyzers":

                analyzers,

            }

        except Exception:

            logger.exception(

                "Unable to retrieve Access Analyzer information",

            )

            return {

                "enabled": False,

                "analyzers": [],

            }


    #######################################################################
    # Permission Inventory
    #######################################################################

    def inventory(

        self,

        principals: list[str],

        actions: list[str],

        resource: str,

    ) -> list[dict[str, Any]]:

        inventory = []

        for principal in principals:

            inventory.append(

                self.summary(

                    principal,

                    actions,

                    resource,

                )

            )

        return inventory


    #######################################################################
    # Metrics
    #######################################################################

    def metrics(

        self,

        policy_documents: list[dict[str, Any]],

    ) -> dict[str, Any]:

        wildcard = 0

        admin = 0

        escalation = 0

        high_risk = 0

        for document in policy_documents:

            if self.has_wildcard_permissions(

                document,

            ):

                wildcard += 1

            if self.has_admin_access(

                document,

            ):

                admin += 1

            if self.privilege_escalation_risk(

                document,

            ):

                escalation += 1

            if self.risk_score(

                document,

            )["score"] >= 60:

                high_risk += 1

        return {

            "policies":

            len(

                policy_documents,

            ),

            "wildcards":

            wildcard,

            "administrator":

            admin,

            "privilege_escalation":

            escalation,

            "high_risk":

            high_risk,

        }


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

        policy_documents: list[dict[str, Any]],

    ) -> dict[str, Any]:

        return {

            "metrics":

            self.metrics(

                policy_documents,

            ),

            "access_analyzer":

            self.access_analyzer_status(),

        }


    #######################################################################
    # Permission Report
    #######################################################################

    def report(

        self,

        policy_documents: list[dict[str, Any]],

    ) -> dict[str, Any]:

        return {

            "metrics":

            self.metrics(

                policy_documents,

            ),

            "compliance":

            [

                self.compliance(

                    document,

                )

                for document

                in policy_documents

            ],

            "access_analyzer":

            self.access_analyzer_status(),

        }


###########################################################################
# Permission Manager
###########################################################################

class PermissionManager:

    """
    High-level IAM Permission Manager.
    """

    def __init__(

        self,

    ):

        self.service = PermissionService()


    def permissions(

        self,

    ) -> PermissionService:

        return self.service


    def report(

        self,

        policy_documents: list[dict[str, Any]],

    ) -> dict[str, Any]:

        return self.service.report(

            policy_documents,

        )


    def diagnostics(

        self,

        policy_documents: list[dict[str, Any]],

    ) -> dict[str, Any]:

        return self.service.diagnostics(

            policy_documents,

        )


###########################################################################
# Global Instances
###########################################################################

PERMISSION_SERVICE = PermissionService()

PERMISSION_MANAGER = PermissionManager()


###########################################################################
# Convenience Functions
###########################################################################

def permissions(

) -> PermissionService:

    return PERMISSION_SERVICE


def report(

    policy_documents: list[dict[str, Any]],

) -> dict[str, Any]:

    return PERMISSION_SERVICE.report(

        policy_documents,

    )


def diagnostics(

    policy_documents: list[dict[str, Any]],

) -> dict[str, Any]:

    return PERMISSION_SERVICE.diagnostics(

        policy_documents,

    )


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "iam.permissions",

        "status":

        "ready",

        "access_analyzer":

        PERMISSION_SERVICE.access_analyzer_status(),

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "PermissionService",

    "PermissionManager",

    "PERMISSION_SERVICE",

    "PERMISSION_MANAGER",

    "permissions",

    "report",

    "diagnostics",

    "self_test",

]


###########################################################################
# Main
###########################################################################

if __name__ == "__main__":

    logging.basicConfig(

        level=logging.INFO,

        format="%(levelname)s %(message)s",

    )

    print("=" * 80)

    print("IAM Permission Service")

    print("=" * 80)

    print()

    print(

        self_test(),

    )

    print()

    print("IAM Permission Service Ready")