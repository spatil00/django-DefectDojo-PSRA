var response = '<style type="text/css">' +
' #initial_risk_calculator { position: fixed; height: 70vh; width: 70%; position: absolute; background-color: #ffffff; border: 1px solid #d0d0d0 ;overflow-y:scroll; z-index: 42; padding: 10 px}' +
' #cvssReference { font-size: 100%; }' +
' fieldset { position: relative; background-color: #f2f2f2; margin-top: 50px; border:0; padding: 1em 0; }' +
' fieldset legend { background-color: rgba(32, 166, 216, 0.75);; color: #ffffff; margin: 0; width: 100%; padding: 0.5em 0px; text-indent: 1em; }' +
' fieldset div.metric { padding: 0; margin: 0.5em 0; }' +
' @media only screen and (min-width:768px) {' +
' fieldset div.column { width: 45%; margin: 0 0 0 1em; }' +
' fieldset div.column-left { float: left; height: auto; }' +
' fieldset div.column-right { float: right; height: auto; }' +
' fieldset h3 { font-size: 1em; margin: 0; padding-left: 0.1em; }' +
' fieldset input { display: none; width:auto; }' +
' fieldset input[type="checkbox"] { display: none; width:auto; }' +
' fieldset label {' +
'    background: #cccccc; display: inline-block; margin: 3px; padding: 2px 5px; border: 0; cursor: pointer; font-size: 90%;' +
'    border-radius: 5px; color: #666666; border: 1px solid #999999; '+
'    user-select: none; -webkit-user-select: none; -moz-user-select: -moz-none; -ms-user-select: none; user-select: none;' +
'  }' +
'  fieldset label:hover { background: #666666; color: #ffffff; border: 1px solid #666666 }' +
'  fieldset input:checked + label { background: rgba(32, 166, 216, 0.75);; border: 1px solid rgba(32, 166, 216, 0.75); color: #ffffff; }'+
''+ 
'  #vector         { margin: 0 1em;padding:0; }' +
'  #RiskString   { display: none; border: 0; padding: 0; margin: 0; background-color: transparent; color: #ffffff; font-weight: bold;font-size:0.8em;width:80em;max-width:100%; }'+
''+ 
'  .Initial_risk_rating { position: absolute; top:-36px; right:0; padding: 0 0.4em; margin: 0 15px; border: 2px solid #666666; background: #dddddd;' +
'    font-size:11px; border-radius: 10px; width: 100px; height: auto; line-height: 150%; text-align: center; }' +
'  .Initial_risk_rating.none,' +
'  .Initial_risk_rating.low,' +
'  .Initial_risk_rating.medium,'+ 
'  .Initial_risk_rating.high,' +
'  .Initial_risk_rating.critical { color:#ffffff;}' +
''+ 
'  .Initial_risk_rating.none     { background:#53aa33; border:2px solid #53aa33; }' +
'  .Initial_risk_rating.low      { background:#ffcb0d; border:2px solid #ffcb0d; }' +
'  .Initial_risk_rating.medium   { background:#f9a009; border:2px solid #f9a009; }' +
'  .Initial_risk_rating.high     { background:#df3d03; border:2px solid #df3d03; }' +
'  .Initial_risk_rating.critical { background:#cc0500; border:2px solid #cc0500; }' +
'  .Initial_risk_rating span     { font-size: 150%; font-weight: bold; width: 100%; }' +
'  .needBaseMetrics      { text-align:center; line-height:100%; padding-top:5px; font-size:15px; }' +
''+ 
'  #initialRiskScore { display: block; font-size: 32px; line-height: 32px; font-weight: normal; margin-top: 4px; } ' +
''+ 
'  #initialRiskSeverity { font-size: 16px; font-weight: normal; margin-bottom: 5px; display: block; }' +
''+ 
'  div#scriptWarning { border: solid red 2px; background: #f5dddd; padding: 1em 1em 1em 1em; margin: 0.4em 0; }' +
'' +
'</style>' +
''+
'<form action="#" id="initial_risk_calculator"> ' +
''+ 
'<fieldset id="InitialRiskGroup">' +
' <legend id="InitialRiskGroup_Legend"> Initial Risk</legend>'  +
'  <div class="column column-left"> ' +
'    <div class="metric_agent">' +
'      <h3 id="ThreatAgent_Heading" >Threat Agents</h3>' +
'   <input name="securityresearcher" value="SR" id="id_securityresearcher"  type="checkbox"><label for="id_securityresearcher" id="securityresearcher_label">Security Researcher</label>' +
'	<input name="advanced_network_threat" value="ANT" id="id_advanced_network_threat" type="checkbox"><label for="id_advanced_network_threat" id="advanced_network_threat_label">Advanced Network Threat</label>'	+
'	<input name="outsider" value="OS" id="id_outsider" type="checkbox"><label for="id_outsider" id="outsider_label">Outsider</label>'+
'	<input name="hardware_defects" value="HD" id="id_hardware_defects" type="checkbox"><label for="id_hardware_defects" id="hardware_defects_label">Hardware Defects</label>'+
'	<input name="software_defects" value="SD" id="id_software_defects" type="checkbox"><label for="id_software_defects" id="software_defects_label">Software Defects</label>'+
'	<input name="intruder" value="IR" id="id_intruder" type="checkbox"><label for="id_intruder" id="intruder_label">Intruder</label>'	+
'	<input name="malicious_code" value="MC" id="id_malicious_code" type="checkbox"><label for="id_malicious_code" id="malicious_code_label">Malicious Code</label>'	+
'	<input name="infrastructure_outage" value="IO" id="id_infrastructure_outage" type="checkbox"><label for="id_infrastructure_outage" id="infrastructure_outage_label">Infrastructure Outage</label>'	+
'	<input name="insider" value="IS" id="id_insider" type="checkbox"><label for="id_insider" id="insider_label">Insider</label>'	+
'	<input name="trusted_insider" value="TIS" id="id_trusted_insider" type="checkbox"><label for="id_trusted_insider" id="trusted_insider_label">Trusted Insider</label>'	+
'	<input name="clinical_users" value="CU" id="id_clinical_users" type="checkbox"><label for="id_clinical_users" id="clinical_users_label">Clinical Users</label>'+	
'	<input name="system_admins" value="SA" id="id_system_admins" type="checkbox"><label for="id_system_admins" id="system_admins_label">System Admins</label>'	+
'	<input name="natural_or_man_made_disaster" value="ND" id="id_natural_or_man_made_disaster" type="checkbox"><label for="id_natural_or_man_made_disaster" id="natural_or_man_made_disaster_label">Natural or Man-made'+
'Disaster</label>'+
'	<input name="engineer" value="ENG" id="id_engineer" type="checkbox"><label for="id_engineer" id="engineer_label">Engineer</label>'+
'	<input name="automated_or_remote_access" value="ARA" id="id_automated_or_remote_access" type="checkbox"><label for="id_automated_or_remote_access" id="automated_or_remote_access_label">Automated or Remote Access</label>'+
'   <input name="agent_none" value="NONE" id="id_agent_none" type="checkbox"><label for="id_agent_none" id="id_agent_none_label">None</label>'+
'    </div>' +
''+ 
'<div class="metric_asset">' +
'<h3 id="TechnicalAssets_Heading">Technical Assets</h3>' +
'<input name="sensitive_data" value="SD" id="id_sensitive_data" type="checkbox"><label for="id_sensitive_data" id="sensitive_data_label">Sensitive Data</label>'+
'<input name="personal_data" value="PD" id="id_personal_data" type="checkbox"><label for="id_personal_data" id="personal_data_label">Personal Data</label>'+
'<input name="hospital_network" value="HN" id="id_hospital_network" type="checkbox"><label for="id_hospital_network" id="hospital_network_label">Hospital Network</label>'+
'<input name="audit_trail_data" value="ATD" id="id_audit_trail_data" type="checkbox"><label for="id_audit_trail_data" id="audit_trail_data_label">Audit Trail Data</label>'+
'<input name="configuration" value="CFG" id="id_configuration" type="checkbox"><label for="id_configuration" id="configuration_label">Configuration </label>'+
'<input name="system_software" value="SS" id="id_system_software" type="checkbox"><label for="id_system_software" id="system_software_label">System Software</label>'+
'<input name="hardware" value="HD" id="id_hardware" type="checkbox"><label for="id_hardware" id="hardware_label">Hardware</label>' +
'<input name="removable_media_with_ephi" value="RMP" id="id_removable_media_with_ephi" type="checkbox"><label for="id_removable_media_with_ephi" id="removable_media_with_ephi_label">Removable Media with ePHI</label>' +
'<input name="removable_media" value="RM" id="id_RM" type="checkbox"><label for="id_RM" id="removable">Removable Media</label>' +
'<input name="logging_data" value="LD" id="id_logging_data" type="checkbox"><label for="id_logging_data" id="logging_data_label">Logging Data</label>' +
'<input name="product_documentation" value="PDC" id="id_product_documentation" type="checkbox"><label for="id_product_documentation" id="product_documentation_label">Product Documentation</label>' +
'<input name="personal" value="P" id="id_personal" type="checkbox"><label for="id_personal" id="personal_label">Personal</label>' +
'<input name="product" value="PRO" id="id_product" type="checkbox"><label for="id_product" id="product_label">Product</label>' +
'<input name="network" value="NET" id="id_network" type="checkbox"><label for="id_network" id="network_label">Network</label>'+
'<input name="all_data" value="AD" id="id_all_data" type="checkbox"><label for="id_all_data" id="all_data_label">All Data</label>'  +
'<input name="asset_none" value="N" id="id_asset_none" type="checkbox"><label for="id_asset_none" id="id_asset_none_label">None</label>'+
'</div>' +
'<br><br>'+
'<h3 id="TechnicalAssets_Heading">Technical Impact</h3>' +
'<div class="metric">'  +
'  <h3 id="Confidentiality_Heading">Confidentiality</h3>' +
'  <input name="Confidentiality" value="VL" id="id_confidentiality_VL" type="radio"><label for="id_confidentiality_VL" id="id_confidentiality_VL_Label">Very Low (VL)</label>' +
'  <input name="Confidentiality" value="L" id="id_confidentiality_L" type="radio"><label for="id_confidentiality_L" id="id_confidentiality_L_Label">Low (L)</label>' +
'  <input name="Confidentiality" value="M" id="id_confidentiality_M" type="radio"><label for="id_confidentiality_M" id="id_confidentiality_M_Label">Medium(M)</label>' +
'  <input name="Confidentiality" value="H" id="id_confidentiality_H" type="radio"><label for="id_confidentiality_H" id="id_confidentiality_H_Label">High (H)</label>' +
'  <input name="Confidentiality" value="VH" id="id_confidentiality_VH" type="radio"><label for="id_confidentiality_VH" id="id_confidentiality_VH_Label">Very High (VH)</label>' +
'</div>' +
'<div class="metric">'  +
'  <h3 id="Integrity_Heading">Integrity</h3>' +
'  <input name="Integrity" value="VL" id="id_integrity_VL" type="radio"><label for="id_integrity_VL" id="id_integrity_VL_Label">Very Low (VL)</label>' +
'  <input name="Integrity" value="L" id="id_integrity_L" type="radio"><label for="id_integrity_L" id="id_integrity_L_Label">Low (L)</label>' +
'  <input name="Integrity" value="M" id="id_integrity_M" type="radio"><label for="id_integrity_M" id="id_integrity_M_Label">Medium(M)</label> '+
'  <input name="Integrity" value="H" id="id_integrity_H" type="radio"><label for="id_integrity_H" id="id_integrity_H_Label">High (H)</label>' +
'  <input name="Integrity" value="VH" id="id_integrity_VH" type="radio"><label for="id_integrity_VH" id="id_integrity_VH_Label">Very High (VH)</label>' +
'</div>' +
'<div class="metric">'  +
'  <h3 id="Availability_Heading">Availability</h3>' +
'  <input name="Availability" value="VL" id="id_availability_VL" type="radio"><label for="id_availability_VL" id="id_availability_VL_Label">Very Low (VL)</label>' +
'  <input name="Availability" value="L" id="id_availability_L" type="radio"><label for="id_availability_L" id="id_availability_L_Label">Low (L)</label>' +
'  <input name="Availability" value="M" id="id_availability_M" type="radio"><label for="id_availability_M" id="id_availability_M_Label">Medium(M)</label>' +
'  <input name="Availability" value="H" id="id_availability_H" type="radio"><label for="id_availability_H" id="id_availability_H_Label">High (H)</label>' +
'  <input name="Availability" value="VH" id="id_availability_VH" type="radio"><label for="id_availability_VH" id="id_availability_VH_Label">Very High (VH)</label>' +
'</div>' +
'  </div>' +
''+ 
'  <div class="Initial_risk_rating">' +
'    <p class="needBaseMetrics">Select values for all base metrics to generate score</p>' +
'    <span id="initialRiskScore"></span>' +
'    <span id="initialRiskSeverity"></span>' +
'  </div>' +
'</fieldset>' +
'<div class="end"></div>' +
''+ 
'<fieldset style="background: rgba(32, 166, 216, 0.75); color:#ffffff; border-radius:10px">'+
'  <p id="vector">Risk String -' +
'    <span class="needBaseMetrics">select values for all base metrics to generate a vector</span>' +
'    <input id="RiskString" readonly="" type="text">' +
'  </p>' +
'</fieldset>' +
'</form>' +
'<!-- CVSS Calculator end -->'


$(".initial_risk_calculator").parent().append(response);
$(document).ready(function () {
    $("#id_initial_risk").click(function () {
        $("#initial_risk_calculator").toggle();
    });
});

$(document).ready(function() {
  $('input[name="asset_none"][value="None"]').click(function() {
    $('.metric_asset input[type="radio"]').prop('checked', false);
    $(this).prop('checked', true);
  });
});

$(document).ready(function() {
  $('input[name="agent_none"][value="None"]').click(function() {
    $('.metric_agent input[type="radio"]').prop('checked', false);
    $(this).prop('checked', true);
  });
});

$(document).mouseup(function (e) {
    var container = $("#initial_risk_calculator");
    if (!container.is(e.target) && container.has(e.target).length === 0) {
        container.hide();
    }
});

"use strict";
function updateScores_initialRisk() {    
    
    var result = OWASP_RRM.calculateRiskScoreFromMetrics(inputValue('input[type="radio"][name=EaseOfExploit]:checked'), 
                                                         inputValue('input[type="radio"][name=EaseofDiscovery]:checked'), 
                                                         inputValue('input[type="radio"][name=Awareness]:checked'), 
                                                         inputValue('input[type="radio"][name=Detectability]:checked'), 
                                                         inputValue('input[type="checkbox"][name=securityresearcher]:checked'), 
                                                         inputValue('input[type="checkbox"][name=advanced_network_threat]:checked'), 
                                                         inputValue('input[type="checkbox"][name=outsider]:checked'), 
                                                         inputValue('input[type="checkbox"][name=hardware_defects]:checked'), 
                                                         inputValue('input[type="checkbox"][name=software_defects]:checked'), 
                                                         inputValue('input[type="checkbox"][name=intruder]:checked'), 
                                                         inputValue('input[type="checkbox"][name=malicious_code]:checked'), 
                                                         inputValue('input[type="checkbox"][name=infrastructure_outage]:checked'), 
                                                         inputValue('input[type="checkbox"][name=insider]:checked'), 
                                                         inputValue('input[type="checkbox"][name=trusted_insider]:checked'), 
                                                         inputValue('input[type="checkbox"][name=clinical_users]:checked'), 
                                                         inputValue('input[type="checkbox"][name=system_admins]:checked'), 
                                                         inputValue('input[type="checkbox"][name=natural_or_man_made_disaster]:checked'), 
                                                         inputValue('input[type="checkbox"][name=engineer]:checked'), 
                                                         inputValue('input[type="checkbox"][name=automated_or_remote_access]:checked'), 
                                                         inputValue('input[type="checkbox"][name=agent_none]:checked'), 
                                                         inputValue('input[type="checkbox"][name=sensitive_data]:checked'), 
                                                         inputValue('input[type="checkbox"][name=personal_data]:checked'),
                                                         inputValue('input[type="checkbox"][name=hospital_network]:checked'), 
                                                         inputValue('input[type="checkbox"][name=audit_trail_data]:checked'),
                                                         inputValue('input[type="checkbox"][name=configuration]:checked'), 
                                                         inputValue('input[type="checkbox"][name=system_software]:checked'),
                                                         inputValue('input[type="checkbox"][name=hardware]:checked'), 
                                                         inputValue('input[type="checkbox"][name=removable_media_with_ephi]:checked'),
                                                         inputValue('input[type="checkbox"][name=removable_media]:checked'), 
                                                         inputValue('input[type="checkbox"][name=logging_data]:checked'),
                                                         inputValue('input[type="checkbox"][name=product_documentation]:checked'), 
                                                         inputValue('input[type="checkbox"][name=personal]:checked'),
                                                         inputValue('input[type="checkbox"][name=product]:checked'), 
                                                         inputValue('input[type="checkbox"][name=network]:checked'),
                                                         inputValue('input[type="checkbox"][name=all_data]:checked'), 
                                                         inputValue('input[type="checkbox"][name=asset_none]:checked'),
                                                         inputValue('input[type="radio"][name=Confidentiality]:checked'),
                                                         inputValue('input[type="radio"][name=Integrity]:checked'), 
                                                         inputValue('input[type="radio"][name=Availability]:checked'));        
    if (result.success === !0) {
        var L = document.querySelectorAll(".needBaseMetrics")
            , i = L.length;
        while (i--) {
            hide(L[i])
        }
      
        if(result.InitialRiskScore!=undefined && result.InitialRiskSeverity!=undefined)
        {
            parentNode(text("#initialRiskScore", result.InitialRiskScore), '.Initial_risk_rating').className = 'Initial_risk_rating ' + result.InitialRiskSeverity.toLowerCase();
            text("#initialRiskSeverity", "(" + result.InitialRiskSeverity + ")");
        }
        
        document.getElementById("id_initial_risk").value =  result.InitialRiskSeverity + "( " + result.InitialRiskScore +" )";
        show(inputValue("#RiskString", result.vectorString));

    } else {
        if (result.error === "Not all base metrics were given - cannot calculate scores.") {
            var L = document.querySelectorAll(".needBaseMetrics"),
                i = L.length;
            while (i--) {
                show(L[i])
            }
            hide("#RiskString")
        }
    }
}

function delayedUpdateScores() {
    setTimeout(updateScores_initialRisk, 100)
}
window.Element && function (ElementPrototype) {
    ElementPrototype.matchesSelector = ElementPrototype.matchesSelector || ElementPrototype.mozMatchesSelector || ElementPrototype.msMatchesSelector || ElementPrototype.oMatchesSelector || ElementPrototype.webkitMatchesSelector || function (selector) {
        var node = this
            , nodes = (node.parentNode || node.document).querySelectorAll(selector)
            , i = -1;
        while (nodes[++i] && nodes[i] != node)
            ;
        return !!nodes[i]
    }
}(Element.prototype);

var matchesSelector = function (node, selector) {
    if (!('parentNode' in node) || !node.parentNode)
        return !1;
    return Array.prototype.indexOf.call(node.parentNode.querySelectorAll(selector)) != -1
};
function node() {
    for (var i = 0; i < arguments.length; i++) {
        var o = arguments[i];
        if (typeof (o) == 'string' && o)
            return document.querySelector(o);
        else if ('nodeName' in o)
            return o;
        else if ('jquery' in o)
            return o.get(0)
    }
    return !1
}
function parentNode(p, q) {
    if (!p || !(p = node(p)))
        return;
    else if ((typeof (q) == 'string' && p.matchesSelector(q)) || p == q)
        return p;
    else if (p.nodeName.toLowerCase() != 'html')
        return parentNode(p.parentNode, q);
    else
        return
}
function bind(q, tg, fn) {
    
    var o = node(q);
    if (!o)
        return;
    if (o.addEventListener) {
        o.addEventListener(tg, fn, !1)
    } else if (o.attachEvent) {
        o.attachEvent('on' + tg, fn)
    } else {
        o['on' + tg] = fn
    }
    return o
}
function text(q, s) {
    var e = node(q);
    if (!e)
        return;
    if (arguments.length > 1) {
        if ('textContent' in e) {
            e.textContent = s
        } else {
            e.innerText = s
        }
        return e
    }
    return e.textContent || e.innerText
}
function hide(q) {
    var e = node(q);
    if (!e)
        return;
    e.setAttribute('style', 'display:none');
    return e
}
function show(q) {
    var e = node(q);
    if (!e)
        return;
    e.setAttribute('style', 'display:inline-block');
    return e
}
function inputValue(q, v) {
    var e = document.querySelector(q);
    if (!e || e.nodeName.toLowerCase() != 'input')
        return;
    if (arguments.length > 1) {
        e.value = v;
        return e
    }
    return e.value
}


function setInitialRiskMetricsFromVector(vectorString) {
    var result = true;

    // Regular expression to match the initial risk vector format
    var initialRiskVectorRegex = /^IRISK:1.0(\/TA:(SR|ANT|OS|HD|SD|IR|TIS|CU|SA|ND|ENG|ARA))*(\/AS:(SD|PD|HN|ATD|CFG|SS|HD|RMP|RM|LD|PDC|P|PRO|NET|AD))*(\/C:(VL|L|M|H|VH))\/I:(VL|L|M|H|VH)\/A:(VL|L|M|H|VH)$/;

    if (!initialRiskVectorRegex.test(vectorString)) {
        return "MalformedVectorString";
    }

    // Parsing the vector string
    var components = vectorString.substring("RISK:1.0/".length).split("/");

    // Variables to store parsed values
    var threatAgentsToSet = [];
    var technicalAssetsToSet = [];
    var confidentiality, integrity, availability;

    // Iterating over components to extract values
    components.forEach(function(component) {
        var parts = component.split(":");
        var key = parts[0];
        var value = parts[1];

        switch (key) {
            case "TA":
                threatAgentsToSet.push(value);
                break;
            case "AS":
                technicalAssetsToSet.push(value);
                break;
            case "C":
                confidentiality = value;
                break;
            case "I":
                integrity = value;
                break;
            case "A":
                availability = value;
                break;
        }
    });

    // Setting the threat agents in the DOM
    threatAgentsToSet.forEach(function(agent) {
        var element = document.getElementById("TA_" + agent);
        if (element) {
            element.checked = true;
        }
    });

    // Setting the technical assets in the DOM
    technicalAssetsToSet.forEach(function(asset) {
        var element = document.getElementById("AS_" + asset);
        if (element) {
            element.checked = true;
        }
    });

    // Setting the Confidentiality, Integrity, and Availability metrics
    if (confidentiality) {
        var confidentialityElement = document.getElementById("C_" + confidentiality);
        if (confidentialityElement) {
            confidentialityElement.checked = true;
        }
    }

    if (integrity) {
        var integrityElement = document.getElementById("I_" + integrity);
        if (integrityElement) {
            integrityElement.checked = true;
        }
    }

    if (availability) {
        var availabilityElement = document.getElementById("A_" + availability);
        if (availabilityElement) {
            availabilityElement.checked = true;
        }
    }

    // Call function to update scores or perform any further actions
    updateScores_initialRisk();

    return result;
}


var CVSSVectorInURL;
function urlhash() {
    var h = document.getElementById("id_initial_risk").value;
    CVSSVectorInURL = h;
 /*   setMetricsFromVector(h)*/
}
function inputSelect() {    
    this.setSelectionRange(0, this.value.length)
}
function initalRiskCalculator() {
    
    /*if (!('CVSS31' in window) || !('CVSS31_Help' in window)) {
    '    setTimeout(cvssCalculator, 100);
    '    return
    '}*/
    
    var L, i, n;
    L = document.querySelectorAll("#initial_risk_calculator input");
    i = L.length;    
    
    while (i--) {
        bind(L[i], 'click', delayedUpdateScores)
    }
  /*  for (n in CVSS31_Help.helpText_en) {
        document.getElementById(n).setAttribute('title', CVSS31_Help.helpText_en[n])
    }
    urlhash();
    if (("onhashchange" in window)) {
        window.onhashchange = urlhash
    }*/
  /*  bind(bind("#vectorString", 'click', inputSelect), "contextmenu", inputSelect)*/
}
if ((document.getElementById("id_initial_risk")) && (document.getElementById("initial_risk_calculator"))) {

    initalRiskCalculator();
}
