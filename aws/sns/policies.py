"""
policies.py

Enterprise SNS Topic Policy Management

Responsibilities
----------------
• Get topic policies
• Set topic policies
• Validate policies
• Public access detection
• Cross-account access analysis
• Least privilege analysis
"""

from __future__ import annotations

import json
import logging

from typing import Any

from botocore.exceptions import ClientError

from aws.utils.aws_utils import get_client

logger = logging.getLogger(__name__)


###########################################################################
# Client
###########################################################################

def sns():

    return get_client(

        "sns",

    )


###########################################################################
# Policy Service
###########################################################################

class PolicyService:

    """
    High-level SNS Policy Management.
    """

    def __init__(

        self,

    ):

        self.client = sns()


    #######################################################################
    # Get Topic Policy
    #######################################################################

    def get_policy(

        self,

        topic_arn: str,

    ) -> dict[str, Any]:

        response = self.client.get_topic_attributes(

            TopicArn=topic_arn,

        )

        policy = response.get(

            "Attributes",

            {},

        ).get(

            "Policy",

            "{}",

        )

        return json.loads(

            policy,

        )


    #######################################################################
    # Set Topic Policy
    #######################################################################

    def set_policy(

        self,

        topic_arn: str,

        policy_document: dict[str, Any],

    ) -> bool:

        self.client.set_topic_attributes(

            TopicArn=topic_arn,

            AttributeName="Policy",

            AttributeValue=json.dumps(

                policy_document,

            ),

        )

        logger.info(

            "Updated topic policy for %s",

            topic_arn,

        )

        return True


    #######################################################################
    # Remove Topic Policy
    #######################################################################

    def remove_policy(

        self,

        topic_arn: str,

    ) -> bool:

        return self.set_policy(

            topic_arn,

            {},

        )


    #######################################################################
    # Validate Policy
    #######################################################################

    def validate_policy(

        self,

        policy_document: dict[str, Any],

    ) -> bool:

        if "Version" not in policy_document:

            raise ValueError(

                "Policy missing Version."

            )

        if "Statement" not in policy_document:

            raise ValueError(

                "Policy missing Statement."

            )

        return True


    #######################################################################
    # Policy Exists
    #######################################################################

    def policy_exists(

        self,

        topic_arn: str,

    ) -> bool:

        policy = self.get_policy(

            topic_arn,

        )

        return bool(

            policy,

        )


    #######################################################################
    # Policy Summary
    #######################################################################

    def summary(

        self,

        topic_arn: str,

    ) -> dict[str, Any]:

        policy = self.get_policy(

            topic_arn,

        )

        statements = policy.get(

            "Statement",

            [],

        )

        return {

            "topic":

            topic_arn,

            "version":

            policy.get(

                "Version",

            ),

            "statement_count":

            len(

                statements,

            ),

        }


    #######################################################################
    # Detect Public Access
    #######################################################################

    def is_public(

        self,

        policy_document: dict[str, Any],

    ) -> bool:

        for statement in policy_document.get(

            "Statement",

            [],

        ):

            principal = statement.get(

                "Principal",

            )

            if principal == "*":

                return True

            if (

                isinstance(

                    principal,

                    dict,

                )

                and principal.get(

                    "AWS",

                )

                == "*"

            ):

                return True

        return False


    #######################################################################
    # Detect Cross Account Access
    #######################################################################

    def has_cross_account_access(

        self,

        policy_document: dict[str, Any],

        account_id: str,

    ) -> bool:

        for statement in policy_document.get(

            "Statement",

            [],

        ):

            principal = statement.get(

                "Principal",

                {},

            )

            if not isinstance(

                principal,

                dict,

            ):

                continue

            aws_principal = principal.get(

                "AWS",

            )

            if not aws_principal:

                continue

            if isinstance(

                aws_principal,

                str,

            ):

                aws_principal = [

                    aws_principal,

                ]

            for arn in aws_principal:

                if account_id not in arn:

                    return True

        return False


    #######################################################################
    # Least Privilege Score
    #######################################################################

    def least_privilege_score(

        self,

        policy_document: dict[str, Any],

    ) -> dict[str, Any]:

        score = 100

        findings = []

        if self.is_public(

            policy_document,

        ):

            score -= 50

            findings.append(

                "Public access",

            )

        if "*" in json.dumps(

            policy_document,

        ):

            score -= 25

            findings.append(

                "Wildcard detected",

            )

        return {

            "score":

            max(

                score,

                0,

            ),

            "findings":

            findings,

        }
        
    #######################################################################
    # Policy Inventory
    #######################################################################

    def inventory(

        self,

        topic_arns: list[str],

    ) -> list[dict[str, Any]]:

        inventory = []

        for arn in topic_arns:

            try:

                inventory.append(

                    self.summary(

                        arn,

                    )

                )

            except Exception:

                logger.exception(

                    "Failed reading policy for %s",

                    arn,

                )

        return inventory


    #######################################################################
    # Policy Metrics
    #######################################################################

    def metrics(

        self,

        topic_arns: list[str],

        account_id: str | None = None,

    ) -> dict[str, Any]:

        total = 0

        public = 0

        cross_account = 0

        wildcard = 0

        for arn in topic_arns:

            try:

                policy = self.get_policy(

                    arn,

                )

            except Exception:

                continue

            total += 1

            if self.is_public(

                policy,

            ):

                public += 1

            if (

                account_id

                and

                self.has_cross_account_access(

                    policy,

                    account_id,

                )

            ):

                cross_account += 1

            if "*" in json.dumps(

                policy,

            ):

                wildcard += 1

        return {

            "total_policies":

            total,

            "public":

            public,

            "cross_account":

            cross_account,

            "wildcards":

            wildcard,

        }


    #######################################################################
    # Compliance
    #######################################################################

    def compliance(

        self,

        topic_arn: str,

        account_id: str | None = None,

    ) -> dict[str, Any]:

        policy = self.get_policy(

            topic_arn,

        )

        return {

            "public":

            self.is_public(

                policy,

            ),

            "cross_account":

            self.has_cross_account_access(

                policy,

                account_id,

            )

            if account_id

            else False,

            "least_privilege":

            self.least_privilege_score(

                policy,

            ),

        }


    #######################################################################
    # Risk Score
    #######################################################################

    def risk_score(

        self,

        topic_arn: str,

        account_id: str | None = None,

    ) -> dict[str, Any]:

        compliance = self.compliance(

            topic_arn,

            account_id,

        )

        score = compliance[

            "least_privilege"

        ][

            "score"

        ]

        findings = list(

            compliance[

                "least_privilege"

            ][

                "findings"

            ]

        )

        if compliance["public"]:

            findings.append(

                "Public topic access",

            )

        if compliance["cross_account"]:

            findings.append(

                "Cross-account access",

            )

        return {

            "score":

            score,

            "findings":

            findings,

        }


    #######################################################################
    # Bulk Apply Policy
    #######################################################################

    def bulk_set_policy(

        self,

        topic_arns: list[str],

        policy_document: dict[str, Any],

    ) -> dict[str, bool]:

        results = {}

        for arn in topic_arns:

            try:

                self.set_policy(

                    arn,

                    policy_document,

                )

                results[arn] = True

            except Exception:

                logger.exception(

                    "Failed updating %s",

                    arn,

                )

                results[arn] = False

        return results


    #######################################################################
    # Diagnostics
    #######################################################################

    def diagnostics(

        self,

        topic_arns: list[str],

        account_id: str | None = None,

    ) -> dict[str, Any]:

        return {

            "metrics":

            self.metrics(

                topic_arns,

                account_id,

            ),

            "inventory":

            self.inventory(

                topic_arns,

            ),

        }


    #######################################################################
    # Report
    #######################################################################

    def report(

        self,

        topic_arns: list[str],

        account_id: str | None = None,

    ) -> dict[str, Any]:

        return {

            "metrics":

            self.metrics(

                topic_arns,

                account_id,

            ),

            "inventory":

            self.inventory(

                topic_arns,

            ),

            "compliance":

            [

                self.compliance(

                    arn,

                    account_id,

                )

                for arn

                in topic_arns

            ],

        }
        
###########################################################################
# Policy Manager
###########################################################################

class PolicyManager:

    """
    High-level SNS Policy Manager.
    """

    def __init__(

        self,

    ):

        self.service = PolicyService()


    def policies(

        self,

    ) -> PolicyService:

        return self.service


    def diagnostics(

        self,

        topic_arns: list[str],

        account_id: str | None = None,

    ) -> dict[str, Any]:

        return self.service.diagnostics(

            topic_arns,

            account_id,

        )


    def report(

        self,

        topic_arns: list[str],

        account_id: str | None = None,

    ) -> dict[str, Any]:

        return self.service.report(

            topic_arns,

            account_id,

        )


###########################################################################
# Global Instances
###########################################################################

POLICY_SERVICE = PolicyService()

POLICY_MANAGER = PolicyManager()


###########################################################################
# Convenience Functions
###########################################################################

def policies(

) -> PolicyService:

    return POLICY_SERVICE


def diagnostics(

    topic_arns: list[str],

    account_id: str | None = None,

) -> dict[str, Any]:

    return POLICY_SERVICE.diagnostics(

        topic_arns,

        account_id,

    )


def report(

    topic_arns: list[str],

    account_id: str | None = None,

) -> dict[str, Any]:

    return POLICY_SERVICE.report(

        topic_arns,

        account_id,

    )


###########################################################################
# Self Test
###########################################################################

def self_test(

) -> dict[str, Any]:

    return {

        "module":

        "sns.policies",

        "status":

        "ready",

    }


###########################################################################
# Public Exports
###########################################################################

__all__ = [

    "PolicyService",

    "PolicyManager",

    "POLICY_SERVICE",

    "POLICY_MANAGER",

    "policies",

    "diagnostics",

    "report",

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

    print("SNS Policy Service")

    print("=" * 80)

    print()

    print(

        self_test(),

    )

    print()

    print("SNS Policy Service Ready")