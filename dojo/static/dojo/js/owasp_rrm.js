// Define the main object for OWASP Risk Rating Methodology
const OWASP_RRM = {
  Version: "1.0",
  VulnerabilityFactors: [10, 3, 2, 1],
  VulnerabilityFactorsSum: 16,
  severityRatingsValues: [
      { name: "VL", value: 0 },
      { name: "L", value: 1 },
      { name: "M", value: 3 },
      { name: "H", value: 6 },
      { name: "VH", value: 8 }
  ],
  threatAgentWeights: [
      { name: "SR", value: 6.6 }, { name: "ANT", value: 8 }, { name: "OS", value: 8.6 },
      { name: "HD", value: 8 }, { name: "SD", value: 8 }, { name: "IR", value: 7.6 },
      { name: "MC", value: 7.2 }, { name: "IO", value: 7.2 }, { name: "IS", value: 6.6 },
      { name: "TIS", value: 6.2 }, { name: "CU", value: 6 }, { name: "SA", value: 6 },
      { name: "ND", value: 4.2 }, { name: "ENG", value: 3.6 }, { name: "ARA", value: 3.6 }
  ],
  technicalAssetWeights: [
      { name: "SD", C: 8, I: 7, A: 7, value: 22 }, { name: "PD", C: 7, I: 7, A: 7, value: 21 },
      { name: "HN", C: 6, I: 7, A: 5, value: 18 }, { name: "ATD", C: 8, I: 7, A: 1, value: 16 },
      { name: "CFG", C: 6, I: 7, A: 7, value: 20 }, { name: "SS", C: 6, I: 9, A: 9, value: 24 },
      { name: "HD", C: 2, I: 5, A: 5, value: 12 }, { name: "RMP", C: 8, I: 7, A: 1, value: 16 },
      { name: "RM", C: 6, I: 9, A: 1, value: 16 }, { name: "LD", C: 2, I: 3, A: 1, value: 6 },
      { name: "PDC", C: 2, I: 3, A: 1, value: 6 }, { name: "P", C: 8, I: 7, A: 7, value: 22 },
      { name: "PRO", C: 6, I: 9, A: 9, value: 24 }, { name: "NET", C: 6, I: 7, A: 7, value: 20 },
      { name: "AD", C: 9, I: 9, A: 9, value: 27 }
  ],
  RRMMatrix: {
      VH: ['M', 'M', 'H', 'H', 'VH'],
      H:  ['M', 'M', 'H', 'H', 'VH'],
      M:  ['VL', 'L', 'M', 'H', 'H'],
      L:  ['VL', 'L', 'L', 'L', 'M'],
      VL: ['VL', 'VL', 'VL', 'L', 'L']
  },
  impactHeaders: ['VL', 'L', 'M', 'H', 'VH']
};

// Function to generate vector string 
OWASP_RRM.generateVectorString = function (factorValues,factorCodes) {
  
  let vectorString = "PSRA:1.0";

  for (const [key, value] of Object.entries(factorValues)) {
      // Check if the factor has a defined value and a mapped code
      if (value !== undefined && factorCodes[key]) {
          vectorString += ` ${factorCodes[key]}:${value}/`;
      }
  }

  // Remove the last slash if any factors were added
  if (vectorString.endsWith('/')) {
      vectorString = vectorString.slice(0, -1);
  }

  return vectorString;

}

// Calculate risk score from metrics
OWASP_RRM.calculateRiskScoreFromMetrics = function (factorValues,factorCodes) {
  // Validate inputs
  if (!factorValues.EaseOfExploit || !factorValues.Awareness || !factorValues.EaseOfDiscovery || !factorValues.Detectability) {
      return { success: false, errorType: "MissingBaseMetric" };
  }

  // Calculate vulnerability score
  const v_Score = OWASP_RRM.calculateVulnerabilityScore(factorValues);
  const v_Severity = OWASP_RRM.getSeverityRating(v_Score);

  // Calculate threat score
  const t_Score = OWASP_RRM.calculateThreatScore(factorValues);
  const i_LikelihoodScore = (t_Score * v_Score) / 9;
  const i_LikelihoodSeverity = OWASP_RRM.getSeverityRating(i_LikelihoodScore);

  // Calculate impact scores
  const maxC = OWASP_RRM.calculateMaxProperty("C", "Confidentiality", factorValues);
  const maxI = OWASP_RRM.calculateMaxProperty("I", "Integrity", factorValues);
  const maxA = OWASP_RRM.calculateMaxProperty("A", "Availability", factorValues);
  const i_ImpactScore = Math.max(maxC, maxI, maxA);
  const i_ImpactSeverity = OWASP_RRM.getSeverityRating(i_ImpactScore);

  // Calculate initial risk severity and score
  const i_RiskSeverity = OWASP_RRM.getRiskSeverity(i_LikelihoodSeverity, i_ImpactSeverity);
  const i_RiskScore = OWASP_RRM.getSeverityRatingValue(i_RiskSeverity);

  // Calculate residual risk
  const r_LikelihoodScore = OWASP_RRM.calculateResidualLikelihood(t_Score, factorValues.DeltaLikelihood, v_Score, factorValues.DeltaVulnerability);
  const r_ImpactScore = OWASP_RRM.calculateResidualImpact(maxC, factorValues.DeltaConfidentiality, maxI, factorValues.DeltaIntegrity, maxA, factorValues.DeltaAvailability);
  const r_likelihoodSeverity = OWASP_RRM.getSeverityRating(r_LikelihoodScore)
  const r_ImpactSeverity = OWASP_RRM.getSeverityRating(r_ImpactScore)
  const r_RiskSeverity = OWASP_RRM.getRiskSeverity(r_likelihoodSeverity, r_ImpactSeverity) 
  const r_RiskScore = OWASP_RRM.getSeverityRatingValue(r_RiskSeverity)
  
  const b_businesScore = OWASP_RRM.getBusinessScore(factorValues)
  
  const b_businessImpact = OWASP_RRM.getSeverityRating(b_businesScore)

  let b_likelihoodSeverity = r_likelihoodSeverity; // Initialize with r_likelihoodSeverity
  if (factorValues.BusinessLikelihood !== undefined) {
      b_likelihoodSeverity =factorValues.BusinessLikelihood;
  }

  
  const b_businessRiskSeverity = OWASP_RRM.getRiskSeverity(b_likelihoodSeverity,b_businessImpact)
  const b_businessRiskScore = OWASP_RRM.getSeverityRatingValue(b_businessRiskSeverity)

  const vectorString = OWASP_RRM.generateVectorString(factorValues,factorCodes);

  return {
      success: true,
      vulnerabilityScore: v_Score.toFixed(1),
      vulnerabilitySeverity:OWASP_RRM.getSeverityString(v_Severity),
      InitialLikelihoodScore: i_LikelihoodScore,
      InitialImpactScore:i_ImpactScore,
      InitialRiskScore: i_RiskScore,
      InitialRiskSeverity: OWASP_RRM.getSeverityString(i_RiskSeverity),
      residualLikelihoodRisk: r_LikelihoodScore.toFixed(1),
      residualImpactRisk: r_ImpactScore.toFixed(1),
      residualLikelihoodSeverity: r_likelihoodSeverity,
      residualImpactSeverity:r_ImpactSeverity,
      ResidualRiskSeverity: OWASP_RRM.getSeverityString(r_RiskSeverity),
      ResidualRiskScore: r_RiskScore,
      BusinessRiskScore: b_businessRiskScore,
      BusinessRiskSeverity: OWASP_RRM.getSeverityString(b_businessRiskSeverity),
      businessImpact: b_businessImpact,
      VectorString: vectorString
  };
};

// Function to calculate vulnerability score
OWASP_RRM.calculateVulnerabilityScore = function (factorValues) {

  if (!factorValues.EaseOfExploit || !factorValues.EaseOfDiscovery || !factorValues.Awareness || !factorValues.Detectability) {
      return 0;
  }

  const vInputs = [factorValues.EaseOfExploit, factorValues.EaseOfDiscovery, factorValues.Awareness, factorValues.Detectability];
  const sumProduct = vInputs.reduce((sum, value, index) => sum + value * this.VulnerabilityFactors[index], 0);
  return this.roundUp(sumProduct / this.VulnerabilityFactorsSum);
};

// Function to calculate threat score
OWASP_RRM.calculateThreatScore = function (factorValues) {

  if (!factorValues.securityresearcher && !factorValues.advanced_network_threat && !factorValues.outsider &&
      !factorValues.hardware_defects && !factorValues.software_defects && !factorValues.intruder &&
      !factorValues.malicious_code && !factorValues.infrastructure_outage && !factorValues.insider &&
      !factorValues.trusted_insider && !factorValues.clinical_users && !factorValues.system_admins &&
      !factorValues.natural_or_man_made_disaster && !factorValues.engineer && !factorValues.automated_or_remote_access &&   factorValues.agent_none) 
      {
        return 0;
      }

  const threatAgents = [
      factorValues.securityresearcher, factorValues.advanced_network_threat, factorValues.outsider,
      factorValues.hardware_defects, factorValues.software_defects, factorValues.intruder,
      factorValues.malicious_code, factorValues.infrastructure_outage, factorValues.insider,
      factorValues.trusted_insider, factorValues.clinical_users, factorValues.system_admins,
      factorValues.natural_or_man_made_disaster, factorValues.engineer, factorValues.automated_or_remote_access,
      factorValues.agent_none
  ];

  return threatAgents.reduce((maxScore, agent) => {
      if (agent) {
          const value = this.FindThreatAgentWeight(agent);
          return Math.max(maxScore, value);
      }
      return maxScore;
  }, 0);
};

// Function to calculate residual risk
OWASP_RRM.calculateResidualLikelihood = function (tScore, tDelta, vScore, vDelta) {
  return ((tScore - tDelta) > 0 && (vScore - vDelta) > 0) ? ((tScore - tDelta) * (vScore - vDelta)) / 9 : 0;
};

// Function to calculate residual impact
OWASP_RRM.calculateResidualImpact = function (c, cDelta, i, iDelta, a, aDelta) {
  return Math.max(Math.max(c - cDelta, 0), Math.max(i - iDelta, 0), Math.max(a - aDelta, 0));
};

// Function to find threat agent weight
OWASP_RRM.FindThreatAgentWeight = function (nameToFind) {
  const weight = this.threatAgentWeights.find(item => item.name === nameToFind);
  return weight ? weight.value : 0;
};

// Function to get Business Score 
OWASP_RRM.getBusinessScore = function(factorValues) {
  if(factorValues.FinancialDamage!=undefined && 
     factorValues.ReputationDamage!=undefined &&
     factorValues.RegulatoryNonCompliance!=undefined && 
     factorValues.CustomerNonCompliance!=undefined && 
     factorValues.PrivacyViolation !=undefined)
    {
        return Math.max(factorValues.FinancialDamage,factorValues.ReputationDamage,factorValues.RegulatoryNonCompliance, factorValues.CustomerNonCompliance,factorValues.PrivacyViolation)
    }
  else
    {
      return 0
    }
}

// Function to get Business Impact 


// Function to get risk severity
OWASP_RRM.getRiskSeverity = function (likelihood, impact) {
  const likelihoodRow = this.RRMMatrix[likelihood];
  const impactIndex = this.impactHeaders.indexOf(impact);
  return likelihoodRow && impactIndex !== -1 ? likelihoodRow[impactIndex] : 'Invalid';
};

OWASP_RRM.getSeverityRatingValue = function(name) {
    const severityRating = this.severityRatingsValues.find(item => item.name === name);
    return severityRating ? severityRating.value : null; // Return the value or null if not found
};

// Function to calculate max property (C, I, A)
OWASP_RRM.calculateMaxProperty = function (property, factorName, factorValues) {
  let maxValue = 0;
  const technicalAssets = [
      factorValues.sensitive_data, factorValues.personal_data, factorValues.hospital_network,
      factorValues.audit_trail_data, factorValues.configuration, factorValues.system_software,
      factorValues.hardware, factorValues.removable_media_with_ephi, factorValues.removable_media,
      factorValues.logging_data, factorValues.product_documentation, factorValues.personal,
      factorValues.product, factorValues.network, factorValues.all_data, factorValues.asset_none
  ];

  if (!factorValues[factorName] && !factorValues.asset_none) {
      technicalAssets.forEach(asset => {
          if (asset) {
              const value = this.getTechnicalAssetProperty(asset, property);
              maxValue = Math.max(maxValue, value);
          }
      });
  } else {
      maxValue = factorValues[factorName];
  }
  return maxValue;
};

// Other utility functions
OWASP_RRM.validateMetrics = function(factorValues, requiredMetrics) {
  for (const metric of requiredMetrics) {
      if (factorValues[metric] === undefined || factorValues[metric] === null) {
          return false;
      }
  }
  return true;
};

OWASP_RRM.getSeverityRating = function (score) {
  let rating = "VL";
  for (let i = 0; i < this.severityRatingsValues.length; i++) {
      const currentRating = this.severityRatingsValues[i];
      const nextRating = this.severityRatingsValues[i + 1];
      if (nextRating) {
          if (score >= currentRating.value && score < nextRating.value) {
              rating = currentRating.name;
              break;
          }
      } else if (score >= currentRating.value) {
          rating = currentRating.name;
          break;
      }
  }
  return rating;
};

OWASP_RRM.getSeverityString = function (severityCode) {
  const severityMap = {
      'VH': 'Very High', 'H': 'High', 'M': 'Medium', 'L': 'Low', 'VL': 'Very Low'
  };
  return severityMap[severityCode] || 'Invalid';
};

OWASP_RRM.getTechnicalAssetProperty = function (assetName, property) {
  const asset = this.technicalAssetWeights.find(item => item.name === assetName);
  return asset ? asset[property] : 0;
};

OWASP_RRM.roundUp = function (input) {
  return Math.ceil(input * 10) / 10;
};

/*
//For Testing Calculate risk function
function calculateRisk() {
  
    const factorValues = {
    EaseOfExploit: 5,
    EaseOfDiscovery: 4,
    Awareness: 8,
    Detectability: 9,
    securityresearcher: 'SR',
    advanced_network_threat: undefined,
    outsider: undefined,
    hardware_defects: undefined,
    software_defects: undefined,
    intruder: undefined,
    malicious_code: undefined,
    infrastructure_outage: undefined,
    insider: undefined,
    trusted_insider: undefined,
    clinical_users: undefined,
    system_admins: undefined,
    natural_or_man_made_disaster: undefined,
    engineer: undefined,
    automated_or_remote_access: undefined,
    agent_none: undefined,
    sensitive_data: 'SD',
    personal_data: undefined,
    hospital_network: undefined,
    audit_trail_data: undefined,
    configuration: undefined,
    system_software: undefined,
    hardware: undefined,
    removable_media_with_ephi: undefined,
    removable_media: undefined,
    logging_data: undefined,
    product_documentation: undefined,
    personal: undefined,
    product: undefined,
    network: undefined,
    all_data: undefined,
    asset_none: undefined,
    Confidentiality: 8,
    Integrity: 7,
    Availability: 5,
    DeltaLikelihood: 5,
    DeltaVulnerability: 4,
    DeltaConfidentiality: 3,
    DeltaIntegrity: 4,
    DeltaAvailability: 5,
    FinancialDamage: undefined,
    ReputationDamage: undefined,
    RegulatoryNonCompliance: undefined,
    CustomerNonCompliance: undefined,
    PrivacyViolation: undefined
};

    const result = OWASP_RRM.calculateRiskScoreFromMetrics(factorValues);

    if (result.success) {
        document.getElementById('vulnerabilityScore').innerText = `Vulnerability Score: ${result.vulnerabilityScore}`;
        document.getElementById('vulnerabilitySeverity').innerText = `Vulnerability Severity: ${result.vulnerabilitySeverity}`;
        document.getElementById('initiallikelihood').innerText = `Initial Likelihood: ${result.InitialLikelihoodScore}`;
        document.getElementById('initialimpact').innerText = `Initial Impact: ${result.InitialImpactScore}`;
        document.getElementById('initialRiskScore').innerText = `Initial Risk Score: ${result.InitialRiskScore}`;
        document.getElementById('initialRiskSeverity').innerText = `Initial Risk Severity: ${result.InitialRiskSeverity}`;
      document.getElementById('residualRiskScore').innerText = `Residual Risk Score: ${result.ResidualRiskScore}`;
        
    } else {
        alert('Error: ' + result.errorType);
    }
}
*/