var response = '<style type="text/css">' +
' #residual_risk_calculator { position: fixed; height: 70vh; width: 70%; position: absolute; background-color: #ffffff; border: 1px solid #d0d0d0 ;overflow-y:scroll; z-index: 42; padding: 10 px}' +
' #cvssReference { font-size: 100%; }' +
' fieldset { position: relative; background-color: #f2f2f2; margin-top: 50px; border:0; padding: 1em 0; }' +
' fieldset legend { background-color: rgba(32, 166, 216, 0.75);; color: #ffffff; margin: 0; width: 100%; padding: 0.5em 0px; text-indent: 1em; }' +
' fieldset div.metric { padding: 0; margin: 0.5em 0; }' +
 
' @media only screen and (min-width:768px) {' +
' fieldset div.column { width: 45%; margin: 0 0 0 1em; }' +
'  fieldset div.column-left { float: left; height: auto; }' +
'  fieldset div.column-right { float: right; height: auto; }' +
'  fieldset h3 { font-size: 1em; margin: 0; padding-left: 0.1em; }' +
'  fieldset input { display: none; width:auto; }' +
'  fieldset label {' +
'    background: #cccccc; display: inline-block; margin: 3px; padding: 2px 5px; border: 0; cursor: pointer; font-size: 90%;' +
'    border-radius: 5px; color: #666666; border: 1px solid #999999; '+
'    user-select: none; -webkit-user-select: none; -moz-user-select: -moz-none; -ms-user-select: none; user-select: none;' +
'  }' +
'  fieldset label:hover { background: #666666; color: #ffffff; border: 1px solid #666666 }' +
'  fieldset input:checked + label { background: rgba(32, 166, 216, 0.75);; border: 1px solid rgba(32, 166, 216, 0.75); color: #ffffff; }'+
''+ 
'  #vector         { margin: 0 1em;padding:0; }' +
'  #vectorString   { display: none; border: 0; padding: 0; margin: 0; background-color: transparent; color: #ffffff; font-weight: bold;font-size:0.8em;width:80em;max-width:100%; }'+
''+ 
'  .residual_scoreRating { position: absolute; top:-36px; right:0; padding: 0 0.4em; margin: 0 15px; border: 2px solid #666666; background: #dddddd;' +
'    font-size:11px; border-radius: 10px; width: 100px; height: auto; line-height: 150%; text-align: center; }' +
'  .residual_scoreRating.none,' +
'  .residual_scoreRating.low,' +
'  .residual_scoreRating.medium,'+ 
'  .residual_scoreRating.high,' +
'  .residual_scoreRating.critical { color:#ffffff;}' +
''+ 
'  .residual_scoreRating.none     { background:#53aa33; border:2px solid #53aa33; }' +
'  .residual_scoreRating.low      { background:#ffcb0d; border:2px solid #ffcb0d; }' +
'  .residual_scoreRating.medium   { background:#f9a009; border:2px solid #f9a009; }' +
'  .residual_scoreRating.high     { background:#df3d03; border:2px solid #df3d03; }' +
'  .residual_scoreRating.critical { background:#cc0500; border:2px solid #cc0500; }' +
'  .residual_scoreRating span     { font-size: 150%; font-weight: bold; width: 100%; }' +
'  .needBaseMetrics      { text-align:center; line-height:100%; padding-top:5px; font-size:15px; }' +
''+ 
'  #ResidualRiskScore { display: block; font-size: 32px; line-height: 32px; font-weight: normal; margin-top: 4px; } ' +
''+ 
'  #ResidualRiskSeverity { font-size: 16px; font-weight: normal; margin-bottom: 5px; display: block; }' +
''+ 
'  div#scriptWarning { border: solid red 2px; background: #f5dddd; padding: 1em 1em 1em 1em; margin: 0.4em 0; }' +
'' +
'</style>' +
''+
'<form action="#" id="residual_risk_calculator"> ' +
'<fieldset id="residualriskscoregroup">' +
'  <legend id="residualriskscoregroup_Legend">Residual Risk Score</legend>' +
''+ 
'  <div class="column column-left">' +
''+ 
'    <div class="metric">' +
'      <h3 id="Lieklihood_Heading">Likelihood After Mitigation</h3>' +
'     <input name="RLikelihood" value="VL" id="id_rlikelihood_VL" type="radio"><label for="id_rlikelihood_VL" id="id_rlikelihood_VL_Label">Very Low (VL)</label>' +
'	  <input name="RLikelihood" value="L" id="id_rlikelihood_L" type="radio"><label for="id_rlikelihood_L" id="id_rlikelihood_L_Label">Low (L)</label>' +
'	  <input name="RLikelihood" value="M" id="id_rlikelihood_M" type="radio"><label for="id_rlikelihood_M" id="id_rlikelihood_M_Label">Medium(M)</label>' +
'	  <input name="RLikelihood" value="H" id="id_rlikelihood_H" type="radio"><label for="id_rlikelihood_H" id="id_rlikelihood_H_Label">High (H)</label>' +
'	  <input name="RLikelihood" value="VH" id="id_rlikelihood_VH" type="radio"><label for="id_rlikelihood_VH" id="id_rlikelihood_VH_Label">Very High (H)</label>' +
'	</div>' +
''+	
'	<div class="metric">'  +
'      <h3 id="rconfidentiality_Heading">Residual Confidentiality Risk</h3> ' +
'      <input name="Rconfidentiality" value="VL" id="id_rconfidentiality_VL" type="radio"><label for="id_rconfidentiality_VL" id="id_rconfidentiality_VL_Label">Very Low (VL)</label>' +
'	  <input name="Rconfidentiality" value="L" id="id_rconfidentiality_L" type="radio"><label for="id_rconfidentiality_L" id="id_rconfidentiality_L_Label">Low (L)</label>' +
'	  <input name="Rconfidentiality" value="M" id="id_rconfidentiality_M" type="radio"><label for="id_rconfidentiality_M" id="id_rconfidentiality_M_Label">Medium(M)</label>' +
'	  <input name="Rconfidentiality" value="H" id="id_rconfidentiality_H" type="radio"><label for="id_rconfidentiality_H" id="id_rconfidentiality_H_Label">High (H)</label>' +
'	  <input name="Rconfidentiality" value="VH" id="id_rconfidentiality_VH" type="radio"><label for="id_rconfidentiality_VH" id="id_rconfidentiality_VH_Label">Very High (H)</label>' +
'	</div>'  +
''+	
'<div class="metric">'  +
'  <h3 id="rintegrity_Heading">Residual Integrity Risk</h3>' +
'  <input name="Rintegrity" value="VL" id="id_rintegrity_VL" type="radio"><label for="id_rintegrity_VL" id="id_rintegrity_VL_Label">Very Low (VL)</label>' +
'  <input name="Rintegrity" value="L" id="id_rintegrity_L" type="radio"><label for="id_rintegrity_L" id="id_rintegrity_L_Label">Low (L)</label>' +
'  <input name="Rintegrity" value="M" id="id_rintegrity_M" type="radio"><label for="id_rintegrity_M" id="id_rintegrity_M_Label">Medium(M)</label>' +
'  <input name="Rintegrity" value="H" id="id_rintegrity_H" type="radio"><label for="id_rintegrity_H" id="id_rintegrity_H_Label">High (H)</label>' +
'  <input name="Rintegrity" value="VH" id="id_rintegrity_VH" type="radio"><label for="id_rintegrity_VH" id="id_rintegrity_VH_Label">Very High (VH)</label>' +
'</div>' +
''+
'<div class="metric">'  +
'  <h3 id="AV_Ravailability">Residual Availability Risk</h3>' +
'  <input name="Ravailability" value="VL" id="id_ravailability_VL" type="radio"><label for="id_ravailability_VL" id="id_ravailability_VL_Label">Very Low (N)</label>' +
'  <input name="Ravailability" value="L" id="id_ravailability_L" type="radio"><label for="id_ravailability_L" id="id_ravailability_L_Label">Low (L)</label>' +
'  <input name="Ravailability" value="M" id="id_ravailability_M" type="radio"><label for="id_ravailability_M" id="id_ravailability_M_Label">Medium(M)</label>' +
'  <input name="Ravailability" value="H" id="id_ravailability_H" type="radio"><label for="id_ravailability_H" id="id_ravailability_H_Label">High (H)</label>' +
'  <input name="Ravailability" value="VH" id="id_ravailability_VH" type="radio"><label for="id_ravailability_VH" id="id_ravailability_VH_Label">Very High (H)</label>' +
'</div>' +
''+
' </div>' +
'<div class="residual_scoreRating">'+
'    <p class="needBaseMetrics">Select values for all base metrics to generate score</p>' +
'    <span id="ResidualRiskScore"></span>' +
'    <span id="ResidualRiskSeverity"></span>' +
'  </div>' +
'</fieldset>' +
'<div class="end"></div>' +
'</form>' 
'<!-- CVSS Calculator end -->'



$(".residual_risk_calculator").parent().append(response);
$(document).ready(function () {
    $("#id_residual_risk").click(function () {
        $("#residual_risk_calculator").toggle();
    });
});


$(document).mouseup(function (e) {
    var container = $("#residual_risk_calculator");
    if (!container.is(e.target) && container.has(e.target).length === 0) {
        container.hide();
    }
});

"use strict";
function updateScores_residualrisk() {        
    var result = OWASP_RRM.calculateResidualRiskScoreFromMetrics(inputValue('input[type="radio"][name=RLikelihood]:checked'), inputValue('input[type="radio"][name=Rconfidentiality]:checked'), inputValue('input[type="radio"][name=Rintegrity]:checked'), inputValue('input[type="radio"][name=Ravailability]:checked'));        
    if (result.success === !0) {
        var L = document.querySelectorAll(".needBaseMetrics")
            , i = L.length;
        while (i--) {
            hide(L[i])
        }
        if(result.residualRiskScore!=undefined && result.residualRiskSeverity!=undefined)
        parentNode(text("#ResidualRiskScore", result.residualRiskScore), '.residual_scoreRating').className = 'residual_scoreRating ' + result.residualRiskSeverity.toLowerCase();
        text("#ResidualRiskSeverity", "(" + result.residualRiskSeverity + ")");
        
        document.getElementById("id_residualrisk").value = result.residualRiskSeverity + "( " + result.residualRiskScore + " )" ;
     /*   if (result.environmentalSeverity != 'None') {
            document.getElementById("id_severity").value = result.environmentalSeverity;
        }
        else {
            document.getElementById("id_severity").value = 'Info'
        };*/

    } else {
        if (result.error === "Not all base metrics were given - cannot calculate scores.") {
            var L = document.querySelectorAll(".needBaseMetrics"),
                i = L.length;
            while (i--) {
                show(L[i])
            }
            hide("#vectorString")
        }
    }
}

function delayedUpdateScores() {
    setTimeout(updateScores_residualrisk, 100)
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

function setMetricsFromVector(vectorString) {
    var result = !0;
    var urlMetric;
    var metricValuesToSet = {
        AV: undefined,
        AC: undefined,
        PR: undefined,
        UI: undefined,
        S: undefined,
        C: undefined,
        I: undefined,
        A: undefined,
        E: "X",
        RL: "X",
        RC: "X",
        CR: "X",
        IR: "X",
        AR: "X",
        MAV: "X",
        MAC: "X",
        MPR: "X",
        MUI: "X",
        MS: "X",
        MC: "X",
        MI: "X",
        MA: "X"
    }
    var vectorStringRegex_31 = /^CVSS:3.1\/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/;
    if (vectorStringRegex_31.test(vectorString)) {
        var urlMetrics = vectorString.substring("CVSS:3.1/".length).split("/");
        for (var p in urlMetrics) {
            var urlMetric = urlMetrics[p].split(":");
            metricValuesToSet[urlMetric[0]] = urlMetric[1]
        }
        if (metricValuesToSet.AV !== undefined && metricValuesToSet.AC !== undefined && metricValuesToSet.PR !== undefined && metricValuesToSet.UI !== undefined && metricValuesToSet.S !== undefined && metricValuesToSet.C !== undefined && metricValuesToSet.I !== undefined && metricValuesToSet.A !== undefined) {
            for (var p in metricValuesToSet) {
                document.getElementById(p + "_" + metricValuesToSet[p]).checked = !0
            }
        } else {
            result = "NotAllBaseMetricsProvided"
        }
    } else {
        result = "MalformedVectorString"
    }
    updateScores_residualrisk();
    return result
}
var CVSSVectorInURL;
function urlhash() {
    var h = document.getElementById("id_residualrisk").value;
    CVSSVectorInURL = h;
 /*   setMetricsFromVector(h)*/
}
function inputSelect() {    
    this.setSelectionRange(0, this.value.length)
}

function setResidualRiskMetricsFromVector(vectorString) {
    var result = true;

    // Regular expression to match the residual risk vector format
    var residualRiskVectorRegex = /^RRISK:1.0\/L:(VL|L|M|H|VH)\/C:(VL|L|M|H|VH)\/I:(VL|L|M|H|VH)\/A:(VL|L|M|H|VH)$/;

    // Check if the vector string matches the expected format
    if (!residualRiskVectorRegex.test(vectorString)) {
        return "MalformedVectorString";
    }

    // Parsing the vector string
    var components = vectorString.substring("RRISK:1.0/".length).split("/");
    var RLikelihood, RConfidentiality, RIntegrity, RAvailability;

    // Iterating over components to extract values
    components.forEach(function(component) {
        var parts = component.split(":");
        var key = parts[0];
        var value = parts[1];

        switch (key) {
            case "L":
                RLikelihood = value;
                break;
            case "C":
                RConfidentiality = value;
                break;
            case "I":
                RIntegrity = value;
                break;
            case "A":
                RAvailability = value;
                break;
        }
    });

    // Setting the Likelihood in the DOM
    if (RLikelihood) {
        var likelihoodElement = document.getElementById("L_" + RLikelihood);
        if (likelihoodElement) {
            likelihoodElement.checked = true;
        }
    }

    // Setting Confidentiality, Integrity, and Availability metrics in the DOM
    if (RConfidentiality) {
        var confidentialityElement = document.getElementById("C_" + RConfidentiality);
        if (confidentialityElement) {
            confidentialityElement.checked = true;
        }
    }

    if (RIntegrity) {
        var integrityElement = document.getElementById("I_" + RIntegrity);
        if (integrityElement) {
            integrityElement.checked = true;
        }
    }

    if (RAvailability) {
        var availabilityElement = document.getElementById("A_" + RAvailability);
        if (availabilityElement) {
            availabilityElement.checked = true;
        }
    }

    // Call function to update residual risk scores or perform any further actions
    updateScores_residualRisk();

    return result;
}


function RRCalculator() {
    
    /*if (!('CVSS31' in window) || !('CVSS31_Help' in window)) {
    '    setTimeout(cvssCalculator, 100);
    '    return
    '}*/
    
    var L, i, n;
    L = document.querySelectorAll("#residual_risk_calculator input");
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
if ((document.getElementById("id_residual_risk")) && (document.getElementById("residual_risk_calculator"))) {

    RRCalculator();
}
