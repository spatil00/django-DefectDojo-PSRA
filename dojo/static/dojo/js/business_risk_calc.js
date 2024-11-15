var response = '<style type="text/css">' +
' #business_risk_calculator { position: fixed; height: 70vh; width: 70%; position: absolute; background-color: #ffffff; border: 1px solid #d0d0d0 ;overflow-y:scroll; z-index: 42; padding: 10 px}' +
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
'  .scoreRating { position: absolute; top:-36px; right:0; padding: 0 0.4em; margin: 0 15px; border: 2px solid #666666; background: #dddddd;' +
'    font-size:11px; border-radius: 10px; width: 100px; height: auto; line-height: 150%; text-align: center; }' +
'  .scoreRating.none,' +
'  .scoreRating.low,' +
'  .scoreRating.medium,'+ 
'  .scoreRating.high,' +
'  .scoreRating.critical { color:#ffffff;}' +
''+ 
'  .scoreRating.none     { background:#53aa33; border:2px solid #53aa33; }' +
'  .scoreRating.low      { background:#ffcb0d; border:2px solid #ffcb0d; }' +
'  .scoreRating.medium   { background:#f9a009; border:2px solid #f9a009; }' +
'  .scoreRating.high     { background:#df3d03; border:2px solid #df3d03; }' +
'  .scoreRating.critical { background:#cc0500; border:2px solid #cc0500; }' +
'  .scoreRating span     { font-size: 150%; font-weight: bold; width: 100%; }' +
'  .needBaseMetrics      { text-align:center; line-height:100%; padding-top:5px; font-size:15px; }' +
''+ 
'  #businessRiskScore { display: block; font-size: 32px; line-height: 32px; font-weight: normal; margin-top: 4px; } ' +
''+ 
'  #businessRiskSeverity { font-size: 16px; font-weight: normal; margin-bottom: 5px; display: block; }' +
''+ 
'  div#scriptWarning { border: solid red 2px; background: #f5dddd; padding: 1em 1em 1em 1em; margin: 0.4em 0; }' +
'' +
'</style>' +
''+
'<form action="#" id="business_risk_calculator"> ' +
'<fieldset id="businessriskscoregroup">' +
'  <legend id="businessriskscoregroup_Legend">business Risk Score</legend>' +
''+ 
'  <div class="column column-left">' +
''+	
'	<div class="metric">'  +
'      <h3 id="Finance_Heading">Finance</h3> ' +
'      <input name="Finance" value="VL" id="id_Finance_VL" type="radio"><label for="id_Finance_VL" id="id_Finance_VL_Label">Very Low (VL)</label>' +
'	  <input name="Finance" value="L" id="id_Finance_L" type="radio"><label for="id_Finance_L" id="id_Finance_L_Label">Low (L)</label>' +
'	  <input name="Finance" value="M" id="id_Finance_M" type="radio"><label for="id_Finance_M" id="id_Finance_M_Label">Medium(M)</label>' +
'	  <input name="Finance" value="H" id="id_Finance_H" type="radio"><label for="id_Finance_H" id="id_Finance_H_Label">High (H)</label>' +
'	  <input name="Finance" value="VH" id="id_Finance_VH" type="radio"><label for="id_Finance_VH" id="id_Finance_VH_Label">Very High (H)</label>' +
'	</div>'  +
''+	
''+	
'	<div class="metric">'  +
'      <h3 id="Reputation_Heading">Reputation</h3> ' +
'      <input name="Reputation" value="VL" id="id_Reputation_VL" type="radio"><label for="id_Reputation_VL" id="id_Reputation_VL_Label">Very Low (VL)</label>' +
'	  <input name="Reputation" value="L" id="id_Reputation_L" type="radio"><label for="id_Reputation_L" id="id_Reputation_L_Label">Low (L)</label>' +
'	  <input name="Reputation" value="M" id="id_Reputation_M" type="radio"><label for="id_Reputation_M" id="id_Reputation_M_Label">Medium(M)</label>' +
'	  <input name="Reputation" value="H" id="id_Reputation_H" type="radio"><label for="id_Reputation_H" id="id_Reputation_H_Label">High (H)</label>' +
'	  <input name="Reputation" value="VH" id="id_Reputation_VH" type="radio"><label for="id_Reputation_VH" id="id_Reputation_VH_Label">Very High (H)</label>' +
'	</div>'  +
''+	
''+	
'	<div class="metric">'  +
'      <h3 id="Regulatory_Heading">Regulatory Non-Compliance</h3> ' +
'      <input name="regulatorync" value="VL" id="id_regulatorync_VL" type="radio"><label for="id_regulatorync_VL" id="id_regulatorync_VL_Label">Very Low (VL)</label>' +
'	  <input name="regulatorync" value="L" id="id_regulatorync_L" type="radio"><label for="id_regulatorync_L" id="id_regulatorync_L_Label">Low (L)</label>' +
'	  <input name="regulatorync" value="M" id="id_regulatorync_M" type="radio"><label for="id_regulatorync_M" id="id_regulatorync_M_Label">Medium(M)</label>' +
'	  <input name="regulatorync" value="H" id="id_regulatorync_H" type="radio"><label for="id_regulatorync_H" id="id_regulatorync_H_Label">High (H)</label>' +
'	  <input name="regulatorync" value="VH" id="id_regulatorync_VH" type="radio"><label for="id_regulatorync_VH" id="id_regulatorync_VH_Label">Very High (VH)</label>' +
'	</div>'  +
''+	
''+	
'	<div class="metric">'  +
'      <h3 id="Customer_Heading">Customer Non-Compliance</h3> ' +
'      <input name="Customer" value="VL" id="id_Customer_VL" type="radio"><label for="id_Customer_VL" id="id_Customer_VL_Label">Very Low (VL)</label>' +
'	  <input name="Customer" value="L" id="id_Customer_L" type="radio"><label for="id_Customer_L" id="id_Customer_L_Label">Low (L)</label>' +
'	  <input name="Customer" value="M" id="id_Customer_M" type="radio"><label for="id_Customer_M" id="id_Customer_M_Label">Medium(M)</label>' +
'	  <input name="Customer" value="H" id="id_Customer_H" type="radio"><label for="id_Customer_H" id="id_Customer_H_Label">High (H)</label>' +
'	  <input name="Customer" value="VH" id="id_Customer_VH" type="radio"><label for="id_Customer_VH" id="id_Customer_VH_Label">Very High (H)</label>' +
'	</div>'  +
''+	
''+	
'	<div class="metric">'  +
'      <h3 id="Privacy_Heading">Privacy Non-Compliance</h3> ' +
'      <input name="Privacy" value="VL" id="id_Privacy_VL" type="radio"><label for="id_Privacy_VL" id="id_Privacy_VL_Label">Very Low (VL)</label>' +
'	  <input name="Privacy" value="L" id="id_Privacy_L" type="radio"><label for="id_Privacy_L" id="id_Privacy_L_Label">Low (L)</label>' +
'	  <input name="Privacy" value="M" id="id_Privacy_M" type="radio"><label for="id_Privacy_M" id="id_Privacy_M_Label">Medium(M)</label>' +
'	  <input name="Privacy" value="H" id="id_Privacy_H" type="radio"><label for="id_Privacy_H" id="id_Privacy_H_Label">High (H)</label>' +
'	  <input name="Privacy" value="VH" id="id_Privacy_VH" type="radio"><label for="id_Privacy_VH" id="id_Privacy_VH_Label">Very High (H)</label>' +
'	</div>'  +
''+	
''+ 
'    <div class="metric">' +
'      <h3 id="Lieklihood_Heading">likelihood After Mitigation</h3>' +
'     <input name="BLikelihood" value="VL" id="id_blikelihood_VL" type="radio"><label for="id_blikelihood_VL" id="id_blikelihood_VL_Label">Very Low (VL)</label>' +
'	  <input name="BLikelihood" value="L" id="id_blikelihood_L" type="radio"><label for="id_blikelihood_L" id="id_blikelihood_L_Label">Low (L)</label>' +
'	  <input name="BLikelihood" value="M" id="id_blikelihood_M" type="radio"><label for="id_blikelihood_M" id="id_blikelihood_M_Label">Medium(M)</label>' +
'	  <input name="BLikelihood" value="H" id="id_blikelihood_H" type="radio"><label for="id_blikelihood_H" id="id_blikelihood_H_Label">High (H)</label>' +
'	  <input name="BLikelihood" value="VH" id="id_blikelihood_VH" type="radio"><label for="id_blikelihood_VH" id="id_blikelihood_VH_Label">Very High (H)</label>' +
'	</div>' +
''+
' </div>' +
'<div class="scoreRating">'+
'    <p class="needBaseMetrics">Select values for all base metrics to generate score</p>' +
'    <span id="businessRiskScore"></span>' +
'    <span id="businessRiskSeverity"></span>' +
'  </div>' +
'</fieldset>' +
'<div class="end"></div>' +
'</form>' 
'<!-- CVSS Calculator end -->'



$(".business_risk_calculator").parent().append(response);
$(document).ready(function () {
    $("#id_business_risk").click(function () {
        $("#business_risk_calculator").toggle();
    });
});


$(document).mouseup(function (e) {
    var container = $("#business_risk_calculator");
    if (!container.is(e.target) && container.has(e.target).length === 0) {
        container.hide();
    }
});

"use strict";
function updateScores_businessrisk() {        
    var result = OWASP_RRM.calculateBusinessRiskScoreFromMetrics(inputValue('input[type="radio"][name=Finance]:checked'), inputValue('input[type="radio"][name=Reputation]:checked'), inputValue('input[type="radio"][name=regulatorync]:checked'), inputValue('input[type="radio"][name=Customer]:checked'),inputValue('input[type="radio"][name=Privacy]:checked'),inputValue('input[type="radio"][name=BLikelihood]:checked'));        
    if (result.success === !0) {
        var L = document.querySelectorAll(".needBaseMetrics")
            , i = L.length;
        while (i--) {
            hide(L[i])
        }
        if(result.businessRiskScore!=undefined && result.businessRiskSeverity!=undefined)
        parentNode(text("#businessRiskScore", result.businessRiskScore), '.scoreRating').className = 'scoreRating ' + result.businessRiskSeverity.toLowerCase();
        text("#businessRiskSeverity", "(" + result.businessRiskSeverity + ")");
        
        document.getElementById("id_businessrisk").value = result.businessRiskSeverity + "( " +result.businessRiskScore +" )";
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
    setTimeout(updateScores_businessrisk, 100)
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



function setBusinessRiskMetricsFromVector(vectorString) {
    var result = true;

    // Regular expression to match the business risk vector format
    var businessRiskVectorRegex = /^BRISK:1.0\/F:(VL|L|M|H|VH)\/REP:(VL|L|M|H|VH)\/REG:(VL|L|M|H|VH)\/C:(VL|L|M|H|VH)\/P:(VL|L|M|H|VH)$/;

    // Check if the vector string matches the expected format
    if (!businessRiskVectorRegex.test(vectorString)) {
        return "MalformedVectorString";
    }

    // Parsing the vector string
    var components = vectorString.substring("BRISK:1.0/".length).split("/");
    var financial, reputation, regulatoryNC, customerNC, privacy;

    // Iterating over components to extract values
    components.forEach(function(component) {
        var parts = component.split(":");
        var key = parts[0];
        var value = parts[1];

        switch (key) {
            case "F":
                financial = value;
                break;
            case "REP":
                reputation = value;
                break;
            case "REG":
                regulatoryNC = value;
                break;
            case "C":
                customerNC = value;
                break;
            case "P":
                privacy = value;
                break;
        }
    });

    // Setting the Financial impact in the DOM
    if (financial) {
        var financialElement = document.getElementById("F_" + financial);
        if (financialElement) {
            financialElement.checked = true;
        }
    }

    // Setting the Reputation impact in the DOM
    if (reputation) {
        var reputationElement = document.getElementById("REP_" + reputation);
        if (reputationElement) {
            reputationElement.checked = true;
        }
    }

    // Setting the Regulatory Non-Compliance impact in the DOM
    if (regulatoryNC) {
        var regulatoryElement = document.getElementById("REG_" + regulatoryNC);
        if (regulatoryElement) {
            regulatoryElement.checked = true;
        }
    }

    // Setting the Customer Non-Compliance impact in the DOM
    if (customerNC) {
        var customerElement = document.getElementById("C_" + customerNC);
        if (customerElement) {
            customerElement.checked = true;
        }
    }

    // Setting the Privacy impact in the DOM
    if (privacy) {
        var privacyElement = document.getElementById("P_" + privacy);
        if (privacyElement) {
            privacyElement.checked = true;
        }
    }

    // Call function to update business risk scores or perform any further actions
    updateScores_businessRisk();

    return result;
}

var CVSSVectorInURL;
function urlhash() {
    var h = document.getElementById("id_businessrisk").value;
    CVSSVectorInURL = h;
 /*   setMetricsFromVector(h)*/
}
function inputSelect() {    
    this.setSelectionRange(0, this.value.length)
}
function RRCalculator() {
    
    /*if (!('CVSS31' in window) || !('CVSS31_Help' in window)) {
    '    setTimeout(cvssCalculator, 100);
    '    return
    '}*/
    
    var L, i, n;
    L = document.querySelectorAll("#business_risk_calculator input");
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
if ((document.getElementById("id_business_risk")) && (document.getElementById("business_risk_calculator"))) {

    RRCalculator();
}
