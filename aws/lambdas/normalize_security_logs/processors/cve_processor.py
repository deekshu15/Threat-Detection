"""
CVE Processor

Processes official NVD JSON 2.0 feeds into
normalized VulnerabilityEvent records.
"""

from utils.schema import VulnerabilityEvent


class CVEProcessor:

    SOURCE_NAME = "cve"

    def normalize(self, data):

        normalized = []

        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:

            cve = item.get("cve", {})

            # ---------------------------------------------------
            # Description
            # ---------------------------------------------------

            description = ""

            for desc in cve.get("descriptions", []):

                if desc.get("lang") == "en":

                    description = desc.get("value")

                    break

            # ---------------------------------------------------
            # Vendor / Product
            # ---------------------------------------------------

            vendor = ""

            product = ""

            affected = cve.get("affected", [])

            if affected:

                affected_data = affected[0].get("affectedData", [])

                if affected_data:

                    vendor = affected_data[0].get("vendor", "")

                    product = affected_data[0].get("product", "")

            # ---------------------------------------------------
            # CVSS
            # ---------------------------------------------------

            severity = "UNKNOWN"

            score = 0.0

            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:

                cvss = metrics["cvssMetricV31"][0]["cvssData"]

                severity = cvss.get("baseSeverity", "UNKNOWN")

                score = cvss.get("baseScore", 0.0)

            # ---------------------------------------------------
            # CWE
            # ---------------------------------------------------

            cwe = ""

            weaknesses = cve.get("weaknesses", [])

            if weaknesses:

                desc = weaknesses[0].get("description", [])

                if desc:

                    cwe = desc[0].get("value", "")

            # ---------------------------------------------------
            # References
            # ---------------------------------------------------

            references = []

            for ref in cve.get("references", []):

                references.append(ref.get("url"))

            normalized.append(

                VulnerabilityEvent(

                    event_id=cve.get("id"),

                    timestamp=cve.get("published"),

                    severity=severity,

                    cvss_score=score,

                    cwe=cwe,

                    vendor=vendor,

                    product=product,

                    description=description,

                    references=references

                )

            )

        return normalized