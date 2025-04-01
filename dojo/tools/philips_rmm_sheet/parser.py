import logging
import hashlib
import json
import environ
import pandas as pd
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding, VulnerabilityFinding, Risk_Assessment

logging.basicConfig(level=logging.INFO)

class PhilipsRMMSheetParser(object):
    """
    Philips RMM Parser that supports Excel formats
    """

    def __init__(self):
        self.excel_handlers = {
            '.xlsx': pd.read_excel,
            '.xls': pd.read_excel
        }

    def get_scan_types(self):
        return ["Philips RMM Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Philips RMM Scan"
 
    def get_description_for_scan_types(self, scan_type):
        return "Philips RMM report can be imported in Excel (.xlsx, .xls)"

    def _detect_file_type(self, filename):
        """Detect file type based on file extension"""
        if not hasattr(filename, 'name'):
            raise ValueError("Invalid file object - missing 'name' attribute")
            
        file_ext = '.' + filename.name.split('.')[-1].lower()
        
        if file_ext in self.excel_handlers:
            return 'excel', self.excel_handlers[file_ext]
        else:
            raise ValueError(f"Unsupported file format: {file_ext}. Supported formats are: {', '.join(self.excel_handlers.keys())}")

    def get_findings(self, filename, test):
        if filename is None:
            return []

        try:
            file_type, handler = self._detect_file_type(filename)

            # Read the file while skipping extra header rows
            df = handler(filename, sheet_name="RMM", skiprows=2)  # Adjust `skiprows` if necessary

            if df.empty:
                logging.warning("Warning: The file contains no data.")
                return []

            # Drop fully empty columns
            df = df.dropna(axis=1, how='all')
            df.columns = [col.strip().replace("\n", " ") if isinstance(col, str) else col for col in df.columns]

            root_path = environ.Path(__file__) - 4 # Three folders back
            template_path = root_path('uploads', 'PSRA/PSRA template.xlsx')

            template_df = pd.read_excel(template_path, sheet_name="RMM", skiprows=2)
            # template_df = template_df.dropna(axis=1, how='all') :  
            template_df.columns = [col.strip().replace("\n", " ") if isinstance(col, str) else col for col in template_df.columns]
            
            # Check if the columns match
            uploaded_columns = set(df.columns)
            template_columns = set(template_df.columns)

            if uploaded_columns != template_columns:
                # missing_in_uploaded = template_columns - uploaded_columns
                # extra_in_uploaded = uploaded_columns - template_columns

                # logging.error("Column mismatch detected!")
                # if missing_in_uploaded:
                #     logging.error(f"Columns missing in uploaded file: {missing_in_uploaded}")
                # if extra_in_uploaded:
                #     logging.error(f"Extra columns in uploaded file: {extra_in_uploaded}")

                return None  # Stop processing if columns do not match
        
            # # If columns are still misaligned, manually define them
            # if 'Unnamed' in df.columns[0]:
            #     logging.warning("Detected unnamed columns, manually assigning headers...")
            #     df.columns = ['Risk ID', 'Vulnerability ID', 'Vulnerability Description', 'Severity', 'Status']

            return self._process_findings(df, test)

        except Exception as e:
            logging.error(f"Error parsing file: {e}")
            return None

        
    def _process_findings(self, df, test):
        """Process findings from Excel or CSV format"""
        findings = []
        dupes = {}

        # Debug: Print first few column names
        logging.info(f"Processing file with columns: {df.columns.tolist()}")

        # Filter out rows where RiskID is NaN
        df = df.dropna(subset=['RiskID'])
        
        records = df.to_dict('records')
        logging.info(f"Found {len(records)} records in the file")

        for i, record in enumerate(records):
            try:
                vulnerability = self._process_vulnerability_record(record)
                finding = self._convert_vulnerability_to_finding(vulnerability, test)

                if finding and finding.title.strip():
                    key = hashlib.sha256((finding.title + '|' + finding.description).encode("utf-8")).hexdigest()

                    if key not in dupes:
                        dupes[key] = finding
                        findings.append(finding)

            except Exception as e:
                logging.error(f"Error processing record {i}: {e}")
        
        return findings  # Return the findings list
                  
    def _process_vulnerability_record(self, record):
        """
        Process a single vulnerability record from the Excel sheet
        
        Args:
            record (dict): Dictionary containing the record data
            
        Returns:
            dict: Structured vulnerability data
        """

        risk_id = self._safe_get(record, 'RiskID')

        if not risk_id:
            print("Skipping record: Missing RiskID")
            return None

        columns_to_check = [
            "Vulnerability ID",
            "Vulnerability Description",
            "Vulnerability Causes or Contributing Factor(s) Consider listing Not Implemented or Conflicting  requirement tags that directly relate to this vulnerability.",
            "Ease Of Exploit",
            "Ease Of Discovery",
            "Awareness",
            "Detectability"
        ]

        # Check if the columns exist in the record, and get the values
        values_to_check = [record.get(col) for col in columns_to_check]

        # If all values in the specified columns are empty (None, NaN, or ""), skip the row
        if all(pd.isna(value) or value in [None, ""] for value in values_to_check):
            print(f"Skipping record: Specified columns are empty for RiskID {risk_id}")
            return None


        vulnerability = {
            'risk_id': risk_id,
            'vulnerability': {
                'id': self._safe_get(record, 'Vulnerability ID'),
                'description': self._safe_get(record, 'Vulnerability Description'),
                'causes': self._safe_get(record, 'Vulnerability Causes or Contributing Factor(s) Consider listing Not Implemented or Conflicting  requirement tags that directly relate to this vulnerability.'),
                'score': self._safe_get(record, 'V.Score'),
                'level': self._safe_get(record, 'V.Level'),
                'metrics': {
                    'ease_of_exploit': self._safe_get(record, 'Ease Of Exploit'),
                    'ease_of_discovery': self._safe_get(record, 'Ease Of Discovery'),
                    'awareness': self._safe_get(record, 'Awareness'),
                    'detectability': self._safe_get(record, 'Detectability')
                }
            },
            'threat': {
                'description': self._safe_get(record, 'Threat Description'),
                'score': self._safe_get(record, 'T.Score'),
                'actors': self._get_threat_actors(record),
                'stride': self._get_stride_threats(record)
            },
            'risk': {
                'statement': self._safe_get(record, 'Risk Statement')
            },
            'impact': {
                'assets': self._get_impact_assets(record),
                'cia': {
                    'confidentiality': {
                        'impact': self._safe_get(record, 'C Impact'),
                        'score': self._safe_get(record, 'C')
                    },
                    'integrity': {
                        'impact': self._safe_get(record, 'I Impact'),
                        'score': self._safe_get(record, 'I')
                    },
                    'availability': {
                        'impact': self._safe_get(record, 'A Impact'),
                        'score': self._safe_get(record, 'A')
                    }
                },
                'business': {
                    'score': self._safe_get(record, 'B.Score'),
                    'likelihood': self._safe_get(record, 'B.Likelihood'),
                    'impact': self._safe_get(record, 'B.Impact'),
                    'risk': self._safe_get(record, 'B.RISK'),
                    'categories': self._get_business_impact_categories(record)
                },
                'initial': {
                    'likelihood_score': self._safe_get(record, 'I.LScore'),
                    'impact_score': self._safe_get(record, 'I.IScore'),
                    'likelihood': self._safe_get(record, 'I.Likelihood'),
                    'impact': self._safe_get(record, 'I.Impact'),
                    'risk': self._safe_get(record, 'I.RISK')
                },
                'residual': {
                    'likelihood_score': self._safe_get(record, 'R.LScore'),
                    'impact_score': self._safe_get(record, 'R.IScore'),
                    'likelihood': self._safe_get(record, 'R.Likelihood'),
                    'impact': self._safe_get(record, 'R.Impact'),
                    'risk': self._safe_get(record, 'R.RISK'),
                    'changes': {
                        'threat': self._safe_get(record, 'T Δ'),
                        'vulnerability': self._safe_get(record, 'V Δ'),
                        'confidentiality': self._safe_get(record, 'C Δ'),
                        'integrity': self._safe_get(record, 'I Δ'),
                        'availability': self._safe_get(record, 'A Δ')
                    }
                }
            },
            'mitigation': {
                'id': self._safe_get(record, 'Mitigation ID'),
                'description': self._safe_get(record, 'Mitigation Description')
            },
            'acceptance': {
                'accepted': self._safe_get(record, 'Accepted?'),
                'rationale': self._safe_get(record, 'Rationale and actions')
            },
            'related_hazard': self._safe_get(record, 'Related Hazard item or N/A  When N/A include rationale')
        }

        vuln = json.dumps(vulnerability, indent=4)
        # print("Vuln: ", vuln)

        return vulnerability


    def _convert_vulnerability_to_finding(self, vulnerability, test):
        """
        Convert a vulnerability record to a Finding object and link it to a Risk Assessment.

        Args:
            vulnerability (dict): Structured vulnerability data
            test: Test object to associate with the finding

        Returns:
            Finding: The created Finding object with an associated Risk Assessment
        """
        finding = Finding(test=test)

        risk_id = vulnerability.get('risk_id') or 'Unknown'
        vuln_id = vulnerability.get('vulnerability', {}).get('id') or 'Unknown'

        finding.title = f"Risk {risk_id}: {vuln_id}"
        if finding.title.strip() in ["Risk :", "Risk Unknown: Unknown"]:
            vuln_desc = vulnerability.get('vulnerability', {}).get('description', '').strip()
            finding.title = vuln_desc[:100] + ('...' if len(vuln_desc) > 100 else '') if vuln_desc else "Philips RMM Vulnerability"

        finding.description = f"""
            **Vulnerability Description:**
            {vulnerability.get('vulnerability', {}).get('description', '')}

            **Vulnerability Causes:**
            {vulnerability.get('vulnerability', {}).get('causes', '')}

            **Threat Description:**
            {vulnerability.get('threat', {}).get('description', '')}

            **Risk Statement:**
            {vulnerability.get('risk', {}).get('statement', '')}
        """.strip()

        residual_risk = vulnerability.get('impact', {}).get('residual', {}).get('risk', 'Medium')
        finding.severity = self._convert_risk_to_severity(residual_risk)
        finding.numerical_severity = Finding.get_numerical_severity(finding.severity)

        mit_id = vulnerability.get('mitigation', {}).get('id', '')
        mit_desc = vulnerability.get('mitigation', {}).get('description', '')
        finding.mitigation = f"**Mitigation ID:** {mit_id}\n**Mitigation Description:** {mit_desc}".strip()

        impact = vulnerability.get('impact', {})
        finding.impact = f"""
            **Confidentiality Impact:** {impact.get('cia', {}).get('confidentiality', {}).get('impact', '')} (Score: {impact.get('cia', {}).get('confidentiality', {}).get('score', '')})
            **Integrity Impact:** {impact.get('cia', {}).get('integrity', {}).get('impact', '')} (Score: {impact.get('cia', {}).get('integrity', {}).get('score', '')})
            **Availability Impact:** {impact.get('cia', {}).get('availability', {}).get('impact', '')} (Score: {impact.get('cia', {}).get('availability', {}).get('score', '')})
            **Business Impact:** {impact.get('business', {}).get('impact', '')} (Score: {impact.get('business', {}).get('score', '')})
        """.strip()

        stride_threats = vulnerability.get('threat', {}).get('stride', {})
        stride_tags = [key for key, value in stride_threats.items() if value and value.lower() != 'no']
        finding.tags = ','.join(stride_tags)

        finding.risk_assessed = True
        # Save the finding to get an ID before checking for risk assessment
        finding.save() #??????????

        mit_type_code = 'N'  # Default to "No Mitigation"
        if mit_id.startswith('D'):
            mit_type_code = 'D'
        elif mit_id.startswith('P'):
            mit_type_code = 'P'
        elif mit_id.startswith('M'):
            mit_type_code = 'M'
        elif mit_id.startswith('I'):
            mit_type_code = 'I'

        def safe_contains(value, search_term):
            return search_term in value.lower() if isinstance(value, str) else False
    
        factor_values = {    
            "EaseOfExploit": vulnerability.get('vulnerability', {}).get('metrics', {}).get('ease_of_exploit', ''),
            "EaseOfDiscovery": vulnerability.get('vulnerability', {}).get('metrics', {}).get('ease_of_discovery', ''),
            "Awareness": vulnerability.get('vulnerability', {}).get('metrics', {}).get('awareness', ''),
            "Detectability": vulnerability.get('vulnerability', {}).get('metrics', {}).get('detectability', ''),
            "Confidentiality": impact.get('cia', {}).get('confidentiality', {}).get('score', ''),
            "Integrity": impact.get('cia', {}).get('integrity', {}).get('score', ''),
            "Availability": impact.get('cia', {}).get('availability', {}).get('score', ''),
            "securityresearcher": vulnerability.get('threat', {}).get('actors', {}).get('security_researcher', ''),
            "advanced_network_threat": vulnerability.get('threat', {}).get('actors', {}).get('advanced_network_threat', ''),
            "outsider": vulnerability.get('threat', {}).get('actors', {}).get('outsider', ''),
            "hardware_defects": safe_contains(vulnerability.get('vulnerability', {}).get('causes', ''), 'hardware defects'),
            "software_defects": safe_contains(vulnerability.get('vulnerability', {}).get('causes', ''), 'software defects'),
            "intruder": vulnerability.get('threat', {}).get('actors', {}).get('intruder', ''),
            "malicious_code": vulnerability.get('threat', {}).get('actors', {}).get('malicious_code', ''),
            "infrastructure_outage": safe_contains(vulnerability.get('threat', {}).get('description', ''), 'infrastructure outage'),
            "insider": vulnerability.get('threat', {}).get('actors', {}).get('insider', ''),
            "trusted_insider": vulnerability.get('threat', {}).get('actors', {}).get('trusted_insider', ''),
            "clinical_users": vulnerability.get('threat', {}).get('actors', {}).get('clinical_users', ''),
            "system_admins": vulnerability.get('threat', {}).get('actors', {}).get('system_admins', ''),
            "natural_or_man_made_disaster": safe_contains(vulnerability.get('threat', {}).get('description', ''), 'natural or man-made disaster'),
            "engineer": vulnerability.get('threat', {}).get('actors', {}).get('engineer', ''),
            "automated_or_remote_access": safe_contains(vulnerability.get('threat', {}).get('description', ''), 'automated or remote access'),
            "agent_none": vulnerability.get('threat', {}).get('actors', {}).get('none', ''),
            "sensitive_data": safe_contains(vulnerability.get('impact', {}).get('business', {}).get('categories', ''), 'sensitive data'),
            "personal_data": safe_contains(vulnerability.get('impact', {}).get('business', {}).get('categories', ''), 'personal data'),
            "hospital_network": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'hospital network'),
            "audit_trail_data": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'audit trail data'),
            "configuration": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'configuration'),
            "system_software": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'system software'),
            "hardware": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'hardware'),
            "removable_media_with_ephi": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'removable media with ephi'),
            "removable_media": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'removable media'),
            "logging_data": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'logging data'),
            "product_documentation": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'product documentation'),
            "personal": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'personal'),
            "product": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'product'),
            "network": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'network'),
            "all_data": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'all data'),
            "asset_none": safe_contains(vulnerability.get('impact', {}).get('assets', ''), 'none'),
            
            "DeltaLikelihood": vulnerability.get('impact', {}).get('residual', {}).get('changes', {}).get('none', ''),
            "DeltaVulnerability": vulnerability.get('impact', {}).get('residual', {}).get('changes', {}).get('vulnerability', ''),
            "DeltaConfidentiality": vulnerability.get('impact', {}).get('residual', {}).get('changes', {}).get('confidentiality', ''),
            "DeltaIntegrity": vulnerability.get('impact', {}).get('residual', {}).get('changes', {}).get('integrity', ''),
            "DeltaAvailability": vulnerability.get('impact', {}).get('residual', {}).get('changes', {}).get('availability', ''),
            "BusinessLikelihood": vulnerability.get('impact', {}).get('business', {}).get('likelihood', ''),
            "FinancialDamage": safe_contains(vulnerability.get('impact', {}).get('business', {}).get('categories', ''), 'financial damage'),
            "ReputationDamage": safe_contains(vulnerability.get('impact', {}).get('business', {}).get('categories', ''), 'reputation damage'),
            "RegulatoryNonCompliance": safe_contains(vulnerability.get('impact', {}).get('business', {}).get('categories', ''), 'regulatory non-compliance'),
            "CustomerNonCompliance": safe_contains(vulnerability.get('impact', {}).get('business', {}).get('categories', ''), 'customer non-compliance'),
            "PrivacyViolation": safe_contains(vulnerability.get('impact', {}).get('business', {}).get('categories', ''), 'privacy violation'),
        }

        factor_codes = {    
            "EaseOfExploit": "EE",
            "EaseOfDiscovery": "ED",
            "Awareness": "AW",
            "Detectability": "DT",
            "Confidentiality": "CI",
            "Integrity": "IT",
            "Availability": "AV",
            "securityresearcher": "SR",
            "advanced_network_threat": "AT",
            "outsider": "OS",
            "hardware_defects": "HD",
            "software_defects": "SF",
            "intruder": "IN",
            "malicious_code": "MC",
            "infrastructure_outage": "IO",
            "insider": "IS",
            "trusted_insider": "TI",
            "clinical_users": "CU",
            "system_admins": "SA",
            "natural_or_man_made_disaster": "ND",
            "engineer": "EN",
            "automated_or_remote_access": "AA",
            "agent_none": "AG",
            "sensitive_data": "SD",
            "personal_data": "PD",
            "hospital_network": "HN",
            "audit_trail_data": "ATD",
            "configuration": "CF",
            "system_software": "SS",
            "hardware": "HW",
            "removable_media_with_ephi": "RE",
            "removable_media": "RM",
            "logging_data": "LD",
            "product_documentation": "PDN",
            "personal": "PS",
            "product": "PR",
            "network": "NW",
            "all_data": "AD",
            "asset_none": "AN",
            
            "DeltaLikelihood": "DL",
            "DeltaVulnerability": "DV",
            "DeltaConfidentiality": "DC",
            "DeltaIntegrity": "DI",
            "DeltaAvailability": "DA",
            "BusinessLikelihood": "BL",
            "FinancialDamage": "FD",
            "ReputationDamage": "RD",
            "RegulatoryNonCompliance": "RN",
            "CustomerNonCompliance": "CN",
            "PrivacyViolation": "PV"
        }

        vector_components = [f"{factor_codes[key]}:{value}" for key, value in factor_values.items() if value]
        
        vector_string = f"PSRA:1.0 {'/'.join(vector_components)}" if vector_components else "PSRA:1.0"
        
        print(f"Generated vector string: {vector_string}")

        # ---- Create or Update Risk Assessment ----
        # Check if this finding is already associated with a risk assessment
        existing_risk_assessments = Risk_Assessment.objects.filter(assessed_findings=finding)
        
        if existing_risk_assessments.exists():
            # The finding is already risk assessed, use the existing assessment
            risk_assessment = existing_risk_assessments.first()
            print(f"Found existing Risk Assessment for finding: {risk_assessment.name}")
            
            # Update the risk assessment with new data
            risk_assessment.threat_types = stride_tags
            risk_assessment.mitigation_types = mit_type_code
            risk_assessment.vector_string = vector_string
            risk_assessment.vulnerability_cause = vulnerability.get('vulnerability', {}).get('causes', '')
            risk_assessment.threat_description = vulnerability.get('threat', {}).get('description', '')
            risk_assessment.risk_statement = vulnerability.get('risk', {}).get('statement', '')
            risk_assessment.related_hazard_item = vulnerability.get('related_hazard', '')
            risk_assessment.rational_and_actions = vulnerability.get('acceptance', {}).get('rationale', '')
            risk_assessment.mitigation_reference = mit_desc
            risk_assessment.save()
            
        else:
            # Try to find a risk assessment by name
            risk_assessment_name = f"Risk Assessment {risk_id}"
            try:
                # Additionally check if this risk assessment already has this finding
                # to avoid duplicating the relationship
                risk_assessment = Risk_Assessment.objects.get(
                    name=risk_assessment_name, 
                    assessed_findings=finding
                )
                
                # Update existing risk assessment
                risk_assessment.threat_types = stride_tags
                risk_assessment.mitigation_types = mit_type_code
                risk_assessment.vector_string = vector_string
                risk_assessment.vulnerability_cause = vulnerability.get('vulnerability', {}).get('causes', '')
                risk_assessment.threat_description = vulnerability.get('threat', {}).get('description', '')
                risk_assessment.risk_statement = vulnerability.get('risk', {}).get('statement', '')
                risk_assessment.related_hazard_item = vulnerability.get('related_hazard', '')
                risk_assessment.rational_and_actions = vulnerability.get('acceptance', {}).get('rationale', '')
                risk_assessment.mitigation_reference = mit_desc
                risk_assessment.save()
                
                print(f"Updated existing Risk Assessment: {risk_assessment.name} with vector: {vector_string}")
            
            except Risk_Assessment.DoesNotExist:
                # No risk assessment exists for this finding, create a new one
                risk_assessment = Risk_Assessment.objects.create(
                    name=risk_assessment_name,
                    threat_types=stride_tags,
                    mitigation_types=mit_type_code,
                    vector_string=vector_string,
                    vulnerability_cause=vulnerability.get('vulnerability', {}).get('causes', ''),
                    threat_description=vulnerability.get('threat', {}).get('description', ''),
                    risk_statement=vulnerability.get('risk', {}).get('statement', ''),
                    related_hazard_item=vulnerability.get('related_hazard', ''),
                    rational_and_actions=vulnerability.get('acceptance', {}).get('rationale', ''),
                    mitigation_reference=mit_desc
                )
                print(f"Created new Risk Assessment: {risk_assessment.name} with vector: {vector_string}")
        
        # Add the finding to the risk assessment
        risk_assessment.assessed_findings.add(finding)

        return finding



    def _convert_risk_to_severity(self, risk):
        """Convert risk level to severity"""
        risk_map = {
            'Very High': 'Critical',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Very Low': 'Info'
        }
        
        return risk_map.get(risk, 'Medium')

    def _get_stride_threats(self, record):
        """Extract STRIDE threat categories from the record with 'X' values only"""
        stride_categories = {
            'spoofing': self._safe_get(record, 'Spoofing'),
            'tampering': self._safe_get(record, 'Tampering'),
            'repudiation': self._safe_get(record, 'Repudiation'),
            'information_disclosure': self._safe_get(record, 'Information Disclosure'),
            'denial_of_service': self._safe_get(record, 'Denial of Service'),
            'elevation_of_privilege': self._safe_get(record, 'Elevation of privilege')
        }
        return {key: value for key, value in stride_categories.items() if 'X' in value}

    def _get_threat_actors(self, record):
        """Extract threat actor categories from the record with 'X' values only"""
        threat_actors = {
            'security_researcher': self._safe_get(record, 'Security Researcher'),
            'advanced_network_threat': self._safe_get(record, 'Advanced Network Threat'),
            'outsider': self._safe_get(record, 'Outsider'),
            'hardware_defects': self._safe_get(record, 'Hardware defects'),
            'software_defects': self._safe_get(record, 'Software defects'),
            'intruder': self._safe_get(record, 'Intruder'),
            'malicious_code': self._safe_get(record, 'Malicious code'),
            'infrastructure_outage': self._safe_get(record, 'Infrastructure outage'),
            'insider': self._safe_get(record, 'Insider'),
            'trusted_insider': self._safe_get(record, 'Trusted Insider'),
            'clinical_users': self._safe_get(record, 'Clinical Users'),
            'system_admins': self._safe_get(record, 'System Admins'),
            'natural_or_man_made_disaster': self._safe_get(record, 'Natural  or man-made disaster'),
            'engineer': self._safe_get(record, 'Engineer'),
            'automated_or_remote_access': self._safe_get(record, 'Automated or Remote access')
        }
        return {key: value for key, value in threat_actors.items() if 'X' in value}

    def _get_impact_assets(self, record):
        """Extract impacted assets from the record with 'X' values only"""
        assets = {
            'sensitive_data': self._safe_get(record, 'Sensitive data'),
            'personal_data': self._safe_get(record, 'Personal data'),
            'hospital_network': self._safe_get(record, 'Hospital network'),
            'audit_trail_data': self._safe_get(record, 'Audit trail data'),
            'configuration_data': self._safe_get(record, 'Configuration / calibration / customization data'),
            'system_software': self._safe_get(record, 'System software '),
            'hardware': self._safe_get(record, 'Hardware'),
            'removable_media_with_ephi': self._safe_get(record, 'Removable media with ePHI'),
            'removable_media_without_ephi': self._safe_get(record, 'Removable media and manuals without ePHI.'),
            'logging_data': self._safe_get(record, 'Logging data'),
            'product_documentation': self._safe_get(record, 'Product Documentation'),
            'personal': self._safe_get(record, 'Personal'),
            'product': self._safe_get(record, 'Product'),
            'network': self._safe_get(record, 'Network'),
            'all_data': self._safe_get(record, 'All Data')
        }
        return {key: value for key, value in assets.items() if 'X' in value}


    def _get_business_impact_categories(self, record):
        """Extract business impact categories from the record"""
        categories = {
            'financial': self._safe_get(record, 'Financial'),
            'reputation': self._safe_get(record, 'Reputation'),
            'regulatory_non_compliance': self._safe_get(record, 'Regulatory Non-compliance'),
            'customer_non_compliance': self._safe_get(record, 'Customer Non-compliance'),
            'privacy': self._safe_get(record, 'Privacy')
        }
        return categories
    
    def _safe_get(self, dict_data, key, default=''):
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
    
    