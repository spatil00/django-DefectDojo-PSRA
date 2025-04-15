import hashlib
import re
from urllib.parse import urlparse

import environ
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

from dojo.models import Endpoint, Finding, Risk_Assessment


class PhilipsRMMSheetParser:

    """Philips Risk Management Matrix Parser that supports Excel formats"""

    def __init__(self):
        self.excel_handlers = {
            ".xlsx": pd.read_excel,
            ".xls": pd.read_excel,
        }

    def get_scan_types(self):
        return ["Philips Risk Management Matrix"]

    def get_label_for_scan_types(self, scan_type):
        return "Philips Risk Management Matrix"

    def get_description_for_scan_types(self, scan_type):
        return "Philips Risk Management Matrix report can be imported in Excel (.xlsx, .xls)"

    def _detect_file_type(self, filename):
        """Detect file type based on file extension"""
        if not hasattr(filename, "name"):
            msg = "Invalid file object - missing 'name' attribute"
            raise ValueError(msg)

        file_ext = "." + filename.name.split(".")[-1].lower()

        if file_ext in self.excel_handlers:
            return "excel", self.excel_handlers[file_ext]
        msg = f"Unsupported file format: {file_ext}. Supported formats are: {', '.join(self.excel_handlers.keys())}"
        raise ValueError(msg)

    def get_findings(self, filename, test):
        if filename is None:
            return []

        try:
            _, handler = self._detect_file_type(filename)

            risk_data = handler(filename, sheet_name="RMM", skiprows=2)

            if risk_data.empty:
                return []

            risk_data.columns = [col.strip().replace("\n", " ") if isinstance(col, str) else col for col in risk_data.columns]

            root_path = environ.Path(__file__) - 4
            template_path = root_path("uploads", "PSRA/PSRA template.xlsx")
            template_df = pd.read_excel(template_path, sheet_name="RMM", skiprows=2)
            template_df.columns = [col.strip().replace("\n", " ") if isinstance(col, str) else col for col in template_df.columns]

            if set(risk_data.columns) != set(template_df.columns):
                return "Column mismatch error"

            try:
                mitigations_df = handler(filename, sheet_name="Mitigations")
                mitigations_df.columns = [col.strip().replace("\n", " ") if isinstance(col, str) else col for col in mitigations_df.columns]

                id_col = next((col for col in mitigations_df.columns if col and "ID" in col), None)
                ref_col = next((col for col in mitigations_df.columns if col and "Reference" in col), None)
                desc_col = next((col for col in mitigations_df.columns if col and ("Description" in col or "Desc" in col)), None)

                mitigation_lookup = {}
                if id_col:
                    mitigation_lookup = {
                        str(row[id_col]): {
                            "reference": str(row.get(ref_col, "")) if ref_col and not pd.isna(row.get(ref_col)) else "",
                            "description": str(row.get(desc_col, "")) if desc_col and not pd.isna(row.get(desc_col)) else "",
                        }
                        for _, row in mitigations_df.iterrows() if not pd.isna(row.get(id_col))
                    }
            except Exception:
                mitigation_lookup = {}

            risk_data = risk_data .dropna(subset=["RiskID"])

            return self._process_findings(risk_data, test, mitigation_lookup)

        except Exception as e:
            return e

    def _process_findings(self, df, test, mitigation_lookup):
        findings = []
        dupes = set()

        records = df.to_dict("records")

        vulnerabilities = []
        for record in records:
            vulnerability = self._process_vulnerability_record(record)
            if vulnerability:
                mitigation_id = vulnerability.get("mitigation", {}).get("id")
                if mitigation_id and str(mitigation_id) in mitigation_lookup:
                    mitigation_data = mitigation_lookup[str(mitigation_id)]
                    vulnerability["mitigation"]["mitigation_reference"] = mitigation_data["reference"]

                    if mitigation_data["description"]:
                        vulnerability["mitigation"]["description"] += f"\n\n{mitigation_data['description']}"

                vulnerabilities.append(vulnerability)

        for vulnerability in vulnerabilities:
            try:
                finding = self._convert_vulnerability_to_finding(vulnerability, test)

                if finding and finding.title.strip():
                    key = hashlib.sha256((finding.title + "|" + finding.description).encode("utf-8")).hexdigest()

                    if key not in dupes:
                        dupes.add(key)
                        findings.append(finding)
            except Exception as e:
                return e

        return findings

    def _process_vulnerability_record(self, record):
        """Process a single vulnerability record from the Excel sheet - optimized version"""
        risk_id = self._safe_get(record, "RiskID")
        if not risk_id:
            return None

        columns_to_check = [
            "Vulnerability ID", "Vulnerability Description",
            "Vulnerability Causes or Contributing Factor(s) Consider listing Not Implemented or Conflicting  requirement tags that directly relate to this vulnerability.",
            "Ease Of Exploit", "Ease Of Discovery", "Awareness", "Detectability",
        ]

        if all(pd.isna(record.get(col)) or record.get(col) in {None, ""} for col in columns_to_check):
            return None

        return {
            "risk_id": risk_id,
            "vulnerability": {
                "id": self._safe_get(record, "Vulnerability ID"),
                "description": self._safe_get(record, "Vulnerability Description"),
                "causes": self._safe_get(record, "Vulnerability Causes or Contributing Factor(s) Consider listing Not Implemented or Conflicting  requirement tags that directly relate to this vulnerability."),
                "score": self._safe_get(record, "V.Score"),
                "level": self._safe_get(record, "V.Level"),
                "metrics": {
                    "ease_of_exploit": self._safe_get(record, "Ease Of Exploit"),
                    "ease_of_discovery": self._safe_get(record, "Ease Of Discovery"),
                    "awareness": self._safe_get(record, "Awareness"),
                    "detectability": self._safe_get(record, "Detectability"),
                },
            },
            "threat": {
                "description": self._safe_get(record, "Threat Description"),
                "score": self._safe_get(record, "T.Score"),
                "actors": self._get_threat_actors(record),
                "stride": self._get_stride_threats(record),
            },
            "risk": {
                "statement": self._safe_get(record, "Risk Statement"),
            },
            "impact": {
                "assets": self._get_impact_assets(record),
                "cia": {
                    "confidentiality": {
                        "impact": self._safe_get(record, "C Impact"),
                        "score": self._safe_get(record, "C"),
                    },
                    "integrity": {
                        "impact": self._safe_get(record, "I Impact"),
                        "score": self._safe_get(record, "I"),
                    },
                    "availability": {
                        "impact": self._safe_get(record, "A Impact"),
                        "score": self._safe_get(record, "A"),
                    },
                },
                "business": {
                    "score": self._safe_get(record, "B.Score"),
                    "likelihood": self._safe_get(record, "B.Likelihood"),
                    "impact": self._safe_get(record, "B.Impact"),
                    "risk": self._safe_get(record, "B.RISK"),
                    "categories": self._get_business_impact_categories(record),
                },
                "initial": {
                    "likelihood_score": self._safe_get(record, "I.LScore"),
                    "impact_score": self._safe_get(record, "I.IScore"),
                    "likelihood": self._safe_get(record, "I.Likelihood"),
                    "impact": self._safe_get(record, "I.Impact"),
                    "risk": self._safe_get(record, "I.RISK"),
                },
                "residual": {
                    "likelihood_score": self._safe_get(record, "R.LScore"),
                    "impact_score": self._safe_get(record, "R.IScore"),
                    "likelihood": self._safe_get(record, "R.Likelihood"),
                    "impact": self._safe_get(record, "R.Impact"),
                    "risk": self._safe_get(record, "R.RISK"),
                    "changes": {
                        "threat": self._safe_get(record, "T Δ"),
                        "vulnerability": self._safe_get(record, "V Δ"),
                        "confidentiality": self._safe_get(record, "C Δ"),
                        "integrity": self._safe_get(record, "I Δ"),
                        "availability": self._safe_get(record, "A Δ"),
                    },
                },
            },
            "mitigation": {
                "id": self._safe_get(record, "Mitigation ID"),
                "description": self._safe_get(record, "Mitigation Description"),
            },
            "acceptance": {
                "accepted": self._safe_get(record, "Accepted?"),
                "rationale": self._safe_get(record, "Rationale and actions"),
            },
            "related_hazard": self._safe_get(record, "Related Hazard item or N/A  When N/A include rationale"),
        }

    def get_vulnerability_name(self, description, top_n=3):
        """Generate a meaningful vulnerability name using TF-IDF"""
        if not description or not description.strip():
            return "Unnamed Vulnerability"

        if not hasattr(self, "_tfidf_vectorizer"):
            self._tfidf_vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)

        cleaned_description = description.lower()
        cleaned_description = re.sub(r"[^a-zA-Z0-9\s]", "", cleaned_description)
        cleaned_description = re.sub(r"\s+", " ", cleaned_description).strip()

        tfidf_matrix = self._tfidf_vectorizer.fit_transform([cleaned_description])

        feature_names = self._tfidf_vectorizer.get_feature_names_out()
        tfidf_scores = tfidf_matrix.toarray().flatten()
        top_indices = tfidf_scores.argsort()[-top_n:][::-1]
        top_keywords = [feature_names[i] for i in top_indices]

        return " ".join(top_keywords).title()

    def _convert_vulnerability_to_finding(self, vulnerability, test):
        """Convert a vulnerability record to a Finding object and link it to a Risk Assessment."""
        finding = Finding(test=test)

        risk_id = vulnerability.get("risk_id", "Unknown")
        vuln_data = vulnerability.get("vulnerability", {})
        vuln_id = vuln_data.get("id", "Unknown")
        vuln_desc = vuln_data.get("description", "")

        if vuln_desc:
            if not hasattr(self, "_title_cache"):
                self._title_cache = {}

            # Use cached title if available
            desc_hash = hash(vuln_desc)
            if desc_hash in self._title_cache:
                finding.title = self._title_cache[desc_hash]
            else:
                title = self.get_vulnerability_name(vuln_desc)
                finding.title = title or (vuln_desc[:100] + "..." if len(vuln_desc) > 100 else vuln_desc)
                self._title_cache[desc_hash] = finding.title
        else:
            finding.title = "Philips Risk Management Matrix Vulnerability"

        finding.description = f"{vuln_id}\n\n{vuln_desc}"

        residual_risk = vuln_data.get("level", "L")
        finding.severity = self._convert_risk_to_severity(residual_risk)
        finding.numerical_severity = Finding.get_numerical_severity(finding.severity)

        mit_data = vulnerability.get("mitigation", {})
        mit_id = mit_data.get("id", "")
        mit_desc = mit_data.get("description", "")
        mit_ref = mit_data.get("mitigation_reference", "")

        mit_desc = f"{mit_id}\n\n{mit_desc}".strip()

        finding.mitigation = mit_desc

        impact = vulnerability.get("impact", {})
        cia = impact.get("cia", {})
        conf = cia.get("confidentiality", {})
        integ = cia.get("integrity", {})
        avail = cia.get("availability", {})

        finding.impact = f"""
Confidentiality Impact: {conf.get('impact', '')} (Score: {conf.get('score', '')})
Integrity Impact: {integ.get('impact', '')} (Score: {integ.get('score', '')})
Availability Impact: {avail.get('impact', '')} (Score: {avail.get('score', '')})
Business Impact: {impact.get('business', {}).get('impact', '')} (Score: {impact.get('business', {}).get('score', '')})
        """.strip()

        stride_threats = vulnerability.get("threat", {}).get("stride", {})
        stride_tags = [key for key, value in stride_threats.items() if value and value.lower() != "no"]
        finding.tags = ",".join(stride_tags)

        stride_tags_list = list(stride_threats.values())
        finding.risk_assessed = True

        if ((vulnerability.get("acceptance", {}).get("accepted", "")).lower().strip()) == "yes":
            finding.risk_accepted = True

        finding.save()

        mit_type_code = "N"  # Default to "No Mitigation"
        if mit_id.startswith("D"):
            mit_type_code = "D"
        elif mit_id.startswith("P"):
            mit_type_code = "P"
        elif mit_id.startswith("M"):
            mit_type_code = "M"
        elif mit_id.startswith("I"):
            mit_type_code = "I"

        vuln_metrics = vuln_data.get("metrics", {})
        threat_actors = vulnerability.get("threat", {}).get("actors", {})
        impact_assets = impact.get("assets", {})
        residual = impact.get("residual", {}).get("changes", {})
        business = impact.get("business", {})
        business_categories = business.get("categories", {})

        factor_values = {
            "EE": vuln_metrics.get("ease_of_exploit", "0"),
            "ED": vuln_metrics.get("ease_of_discovery", "0"),
            "AW": vuln_metrics.get("awareness", "0"),
            "DT": vuln_metrics.get("detectability", "0"),
            "CI": conf.get("score", 0),
            "IT": integ.get("score", 0),
            "AV": avail.get("score", 0),

            "SR": threat_actors.get("security_researcher", ""),
            "AT": threat_actors.get("advanced_network_threat", ""),
            "OS": threat_actors.get("outsider", ""),
            "HD": threat_actors.get("hardware_defects", ""),
            "SF": threat_actors.get("software_defects", ""),
            "IN": threat_actors.get("intruder", ""),
            "MC": threat_actors.get("malicious_code", ""),
            "IO": threat_actors.get("infrastructure_outage", ""),
            "IS": threat_actors.get("insider", ""),
            "TI": threat_actors.get("trusted_insider", ""),
            "CU": threat_actors.get("clinical_users", ""),
            "SA": threat_actors.get("system_admins", ""),
            "ND": threat_actors.get("natural_or_man_made_disaster", ""),
            "EN": threat_actors.get("engineer", ""),
            "AA": threat_actors.get("automated_or_remote_access", ""),
            "AG": threat_actors.get("none", ""),

            "SD": impact_assets.get("sensitive_data", ""),
            "PD": impact_assets.get("personal_data", ""),
            "HN": impact_assets.get("hospital_network", ""),
            "ATD": impact_assets.get("audit_trail_data", ""),
            "CF": impact_assets.get("configuration_data", ""),
            "SS": impact_assets.get("system_software", ""),
            "HW": impact_assets.get("hardware", ""),
            "RE": impact_assets.get("removable_media_with_ephi", ""),
            "RM": impact_assets.get("removable_media_without_ephi", ""),
            "LD": impact_assets.get("logging_data", ""),
            "PDN": impact_assets.get("product_documentation", ""),
            "PS": impact_assets.get("personal", ""),
            "PR": impact_assets.get("product", ""),
            "NW": impact_assets.get("network", ""),
            "AD": impact_assets.get("all_data", ""),

            "DL": residual.get("threat", 0),
            "DV": residual.get("vulnerability", 0),
            "DC": residual.get("confidentiality", 0),
            "DI": residual.get("integrity", 0),
            "DA": residual.get("availability", 0),
            "BL": business.get("likelihood", ""),

            "FD": business_categories.get("financial", "0"),
            "RD": business_categories.get("reputation", ""),
            "RN": business_categories.get("regulatory_non_compliance", "0"),
            "CN": business_categories.get("customer_non_compliance", "0"),
            "PV": business_categories.get("privacy", "0"),
        }

        # vector_components = [f"{code}:{value}" for code, value in factor_values.items() if value]
        # vector_string = f"PSRA:1.0 {'/'.join(vector_components)}" if vector_components else "PSRA:1.0"

        vector_components = [
            f"{code}:{value}" for code, value in factor_values.items()
            if not (isinstance(value, str) and value == "")
        ]
        vector_string = f"PSRA:1.0 {'/'.join(vector_components)}" if vector_components else "PSRA:1.0"

        risk_assessment_name = f"Risk Assessment {risk_id}"

        try:
            # Use select_related to minimize DB queries
            risk_assessment = Risk_Assessment.objects.select_related().get(
                name=risk_assessment_name,
                assessed_findings=finding,
            )
        except Risk_Assessment.DoesNotExist:
            risk_assessment = Risk_Assessment.objects.create(
                name=risk_assessment_name,
                threat_types=stride_tags_list,
                mitigation_types=mit_type_code,
                vector_string=vector_string,
                vulnerability_cause=vuln_data.get("causes", ""),
                threat_description=vulnerability.get("threat", {}).get("description", ""),
                risk_statement=vulnerability.get("risk", {}).get("statement", ""),
                related_hazard_item=vulnerability.get("related_hazard", ""),
                rational_and_actions=vulnerability.get("acceptance", {}).get("rationale", ""),
                mitigation_reference=mit_ref,
            )
        else:
            # Update existing risk assessment
            risk_assessment.threat_types = stride_tags_list
            risk_assessment.mitigation_types = mit_type_code
            risk_assessment.vector_string = vector_string
            risk_assessment.vulnerability_cause = vuln_data.get("causes", "")
            risk_assessment.threat_description = vulnerability.get("threat", {}).get("description", "")
            risk_assessment.risk_statement = vulnerability.get("risk", {}).get("statement", "")
            risk_assessment.related_hazard_item = vulnerability.get("related_hazard", "")
            risk_assessment.rational_and_actions = vulnerability.get("acceptance", {}).get("rationale", "")
            risk_assessment.mitigation_reference = mit_ref
            risk_assessment.save()

        # Add the finding to the risk assessment
        risk_assessment.assessed_findings.add(finding)
        # finding.notes.add(Notes.objects.create(
        #         entry=(
        #             "Finding to the risk assessment: "
        #             f'"{risk_assessment.name}" ({(risk_assessment)})'
        #         ),
        #         author=user,
        #     ))

        return finding

    def _convert_risk_to_severity(self, risk):
        """Convert risk level to severity"""
        risk_map = {
            "VH": "Critical",
            "H": "High",
            "M": "Medium",
            "L": "Low",
            "VL": "Info",
        }

        return risk_map.get(risk, "Medium")

    def _get_stride_threats(self, record):
        """Extract STRIDE threat categories from the record with 'X' values only"""
        stride_categories = {
            "spoofing": "S" if "X" in self._safe_get(record, "Spoofing") else "",
            "tampering": "T" if "X" in self._safe_get(record, "Tampering") else "",
            "repudiation": "R" if "X" in self._safe_get(record, "Repudiation") else "",
            "information_disclosure": "I" if "X" in self._safe_get(record, "Information Disclosure") else "",
            "denial_of_service": "D" if "X" in self._safe_get(record, "Denial of Service") else "",
            "elevation_of_privilege": "E" if "X" in self._safe_get(record, "Elevation of privilege") else "",
        }
        return {key: value for key, value in stride_categories.items() if value}

    def _get_threat_actors(self, record):
        """Extract threat actor categories from the record with 'X' values only"""
        threat_actors = {
            "security_researcher": "SR" if "X" in self._safe_get(record, "Security Researcher") else "",
            "advanced_network_threat": "ANT" if "X" in self._safe_get(record, "Advanced Network Threat") else "",
            "outsider": "OS" if "X" in self._safe_get(record, "Outsider") else "",
            "hardware_defects": "HD" if "X" in self._safe_get(record, "Hardware defects") else "",
            "software_defects": "SD" if "X" in self._safe_get(record, "Software defects") else "",
            "intruder": "IR" if "X" in self._safe_get(record, "Intruder") else "",
            "malicious_code": "MC" if "X" in self._safe_get(record, "Malicious code") else "",
            "infrastructure_outage": "IO" if "X" in self._safe_get(record, "Infrastructure outage") else "",
            "insider": "IS" if "X" in self._safe_get(record, "Insider") else "",
            "trusted_insider": "TIS" if "X" in self._safe_get(record, "Trusted Insider") else "",
            "clinical_users": "CU" if "X" in self._safe_get(record, "Clinical Users") else "",
            "system_admins": "SA" if "X" in self._safe_get(record, "System Admins") else "",
            "natural_or_man_made_disaster": "ND" if "X" in self._safe_get(record, "Natural  or man-made disaster") else "",
            "engineer": "ENG" if "X" in self._safe_get(record, "Engineer") else "",
            "automated_or_remote_access": "ARA" if "X" in self._safe_get(record, "Automated or Remote access") else "",
        }
        return {key: value for key, value in threat_actors.items() if value}

    def _get_impact_assets(self, record):
        """Extract impacted assets from the record with 'X' values only"""
        assets = {
            "sensitive_data": "SD" if "X" in self._safe_get(record, "Sensitive data") else "",
            "personal_data": "PD" if "X" in self._safe_get(record, "Personal data") else "",
            "hospital_network": "HN" if "X" in self._safe_get(record, "Hospital network") else "",
            "audit_trail_data": "ATD" if "X" in self._safe_get(record, "Audit trail data") else "",
            "configuration_data": "CFG" if "X" in self._safe_get(record, "Configuration / calibration / customization data") else "",
            "system_software": "SS" if "X" in self._safe_get(record, "System software") else "",
            "hardware": "HD" if "X" in self._safe_get(record, "Hardware") else "",
            "removable_media_with_ephi": "RMP" if "X" in self._safe_get(record, "Removable media with ePHI") else "",
            "removable_media_without_ephi": "RM" if "X" in self._safe_get(record, "Removable media and manuals without ePHI.") else "",
            "logging_data": "LD" if "X" in self._safe_get(record, "Logging data") else "",
            "product_documentation": "PDC" if "X" in self._safe_get(record, "Product Documentation") else "",
            "personal": "P" if "X" in self._safe_get(record, "Personal") else "",
            "product": "PRO" if "X" in self._safe_get(record, "Product") else "",
            "network": "NET" if "X" in self._safe_get(record, "Network") else "",
            "all_data": "AD" if "X" in self._safe_get(record, "All Data") else "",
        }
        return {key: value for key, value in assets.items() if value}

    def _get_business_impact_categories(self, record):
        """Extract business impact categories from the record"""
        return {
            "financial": self._safe_get(record, "Financial"),
            "reputation": self._safe_get(record, "Reputation"),
            "regulatory_non_compliance": self._safe_get(record, "Regulatory Non-compliance"),
            "customer_non_compliance": self._safe_get(record, "Customer Non-compliance"),
            "privacy": self._safe_get(record, "Privacy"),
        }

    def _safe_get(self, dict_data, key, default=""):
        """Safely get a value from a dictionary"""
        value = dict_data.get(key, default)
        if pd.isna(value) or value is None:
            return default
        return value

    def get_endpoint(self, url):
        parsedUrl = urlparse(url)
        protocol = parsedUrl.scheme
        query = parsedUrl.query[:1000]
        fragment = parsedUrl.fragment
        path = parsedUrl.path[:500]
        port = ""  # Set port to empty string by default
        host = parsedUrl.netloc

        return Endpoint(
            host=host,
            port=port,
            path=path,
            protocol=protocol,
            query=query, fragment=fragment)
