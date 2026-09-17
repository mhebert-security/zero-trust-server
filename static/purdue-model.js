/* static/purdue-model.js — interactivity for the Purdue Model tool.
   No inline handlers and no eval: this file is loaded from /static/ and the
   page carries a script-src 'self' CSP. Vanilla DOM only. */
(function () {
    "use strict";

    var LEVELS = {
        5: {
            label: "Level 5",
            name: "Enterprise / External",
            tagline: "The edge where the outside world meets the facility",
            description: "Internet connectivity, cloud services, and every remote access path into the site. This is where the initial foothold usually lands.",
            systems: "Internet uplink, cloud-hosted services, VPN concentrators, vendor remote support paths.",
            techniques: [
                { id: "T0883", name: "Internet Accessible Device" },
                { id: "T0822", name: "External Remote Services" },
                { id: "T0865", name: "Spearphishing Attachment" }
            ],
            impacts: { safety: 1, availability: 2, integrity: 2, confidentiality: 5 },
            clinical: "Health information exchanges, cloud-hosted EHR, vendor remote support, patient portals.",
            surface: "Commodity attackers reach this layer constantly. The pivot toward the control network starts here."
        },
        4: {
            label: "Level 4",
            name: "Enterprise IT",
            tagline: "Corporate IT: email, ERP, finance",
            description: "The business network. Phishing, credential theft, and privilege escalation happen here, on general-purpose IT systems that happen to sit next to the control network.",
            systems: "Corporate email, ERP, HR, finance, internet-facing business systems.",
            techniques: [
                { id: "T0865", name: "Spearphishing Attachment" },
                { id: "T0863", name: "User Execution" },
                { id: "T0859", name: "Valid Accounts" },
                { id: "T0890", name: "Exploitation for Privilege Escalation" }
            ],
            impacts: { safety: 1, availability: 3, integrity: 3, confidentiality: 5 },
            clinical: "Hospital enterprise: corporate email, ERP, HR, finance, and the administrative network.",
            surface: "The critical boundary sits between Level 3 and Level 4. In a facility that grew by accretion, that boundary is often a fiction."
        },
        3: {
            label: "Level 3",
            name: "Site Operations",
            tagline: "Historians, SCADA servers, engineering workstations",
            description: "Where the process is managed and its history is stored. The engineering workstation holds the PLC project files, the canonical copy of the control logic on every controller.",
            systems: "SCADA servers, historians, engineering workstations.",
            techniques: [
                { id: "T0859", name: "Valid Accounts" },
                { id: "T0886", name: "Remote Services" },
                { id: "T0866", name: "Exploitation of Remote Services" },
                { id: "T0891", name: "Hardcoded Credentials" }
            ],
            impacts: { safety: 3, availability: 4, integrity: 4, confidentiality: 4 },
            clinical: "Clinical data and management: EHR servers, PACS archive, interface engine, biomedical device management.",
            surface: "Whoever controls the engineering workstation controls the process. The demilitarized zone between Level 3 and Level 4 is supposed to terminate connections on both sides."
        },
        2: {
            label: "Level 2",
            name: "Supervisory Control",
            tagline: "HMIs and local SCADA: the screen a human watches",
            description: "Operator interfaces and supervisory nodes. Compromise here lets an attacker see what operators see, suppress alarms, show false readings, and issue commands downward while the screen looks normal.",
            systems: "Operator HMIs (human-machine interfaces), local SCADA nodes.",
            techniques: [
                { id: "T0832", name: "Manipulation of View" },
                { id: "T0815", name: "Denial of View" },
                { id: "T0823", name: "Graphical User Interface" },
                { id: "T0814", name: "Denial of Service" },
                { id: "T0833", name: "Modify Control Logic" }
            ],
            impacts: { safety: 4, availability: 4, integrity: 5, confidentiality: 3 },
            clinical: "Clinical network: nursing unit segments, EHR thick clients, medication cabinets, nurse call, workstations on wheels.",
            surface: "The response-function attacks live here: wipes, denial of view, and alarm suppression that hide the incident while it unfolds."
        },
        1: {
            label: "Level 1",
            name: "Basic Control",
            tagline: "PLCs running one program in an infinite loop",
            description: "Programmable logic controllers read inputs, execute logic, and write outputs. Most have no user authentication on the control protocol. If you can reach a PLC on its network, you can command it.",
            systems: "PLC (programmable logic controller) racks, remote I/O, motor drives, valve controllers.",
            techniques: [
                { id: "T0855", name: "Unauthorized Command Message" },
                { id: "T0836", name: "Modify Parameter" },
                { id: "T0839", name: "Module Firmware" },
                { id: "T0889", name: "Modify Program" },
                { id: "T0851", name: "Rootkit" },
                { id: "T0849", name: "Masquerading" }
            ],
            impacts: { safety: 5, availability: 5, integrity: 5, confidentiality: 2 },
            clinical: "Device network: bedside networks, telemetry wireless bands, vendor-isolated segments.",
            surface: "The PLC does not ask who you are. The protocol layer has no identity, so the network boundary is the only control."
        },
        0: {
            label: "Level 0",
            name: "Physical Process",
            tagline: "Sensors, actuators, valves, motors, pumps",
            description: "The physical process itself, plus the safety instrumented system, an independent layer that forces a safe shutdown when thresholds are crossed. False data or false commands here become physical events.",
            systems: "Sensors, actuators, valves, motors, pumps, and the safety instrumented system (SIS).",
            techniques: [
                { id: "T0831", name: "Manipulation of Control" },
                { id: "T0855", name: "Unauthorized Command Message" },
                { id: "T0836", name: "Modify Parameter" },
                { id: "T0879", name: "Damage to Property" },
                { id: "T0880", name: "Loss of Safety" }
            ],
            impacts: { safety: 5, availability: 5, integrity: 5, confidentiality: 1 },
            clinical: "Device and patient: infusion pumps, ventilators, physiologic monitors, imaging, wearables, implantables.",
            surface: "The one level with no industrial equivalent. In a hospital, the machinery is a patient. A wrong command here does not wait for a rollback."
        }
    };

    var IMPACT_LABELS = {
        safety: "Safety",
        availability: "Availability",
        integrity: "Integrity",
        confidentiality: "Confidentiality"
    };

    function esc(text) {
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    }

    function impactClass(value) {
        if (value >= 5) { return "critical"; }
        if (value >= 4) { return "hot"; }
        return "";
    }

    function renderPanel(level) {
        var html = "";

        html += "<h2>" + esc(level.name) + "</h2>";
        html += "<p class=\"pm-level-label\">" + esc(level.label) + " · " + esc(level.tagline) + "</p>";
        html += "<p>" + esc(level.description) + "</p>";

        html += "<p class=\"pm-label\">What lives here</p>";
        html += "<p>" + esc(level.systems) + "</p>";

        html += "<p class=\"pm-label\">ATT&amp;CK for ICS techniques</p>";
        html += "<ul class=\"pm-tech\">";
        level.techniques.forEach(function (t) {
            html += "<li><span class=\"id\">" + esc(t.id) + "</span><span>" + esc(t.name) + "</span></li>";
        });
        html += "</ul>";

        html += "<p class=\"pm-label\">Impact</p>";
        html += "<div class=\"pm-impacts\">";
        Object.keys(IMPACT_LABELS).forEach(function (k) {
            var value = level.impacts[k];
            var label = IMPACT_LABELS[k];
            html += "<div class=\"pm-impact " + impactClass(value) + "\">";
            html += "<span class=\"k\">" + label + "</span>";
            html += "<span class=\"track\"><span class=\"fill w" + value + "\"></span></span>";
            html += "<span class=\"v\">" + value + "/5</span>";
            html += "</div>";
        });
        html += "</div>";

        html += "<p class=\"pm-label\">Clinical parallel</p>";
        html += "<p class=\"pm-clinical\">" + esc(level.clinical) + "</p>";

        html += "<p class=\"pm-label\">Attack surface</p>";
        html += "<p>" + esc(level.surface) + "</p>";

        return html;
    }

    function activate(button) {
        var bands = document.querySelectorAll(".pm-band");
        for (var i = 0; i < bands.length; i++) {
            bands[i].classList.remove("active");
        }
        button.classList.add("active");

        var key = button.getAttribute("data-level");
        var level = LEVELS[key];
        var panel = document.getElementById("pm-panel");
        if (level && panel) {
            panel.innerHTML = renderPanel(level);
        }
    }

    function init() {
        var bands = document.querySelectorAll(".pm-band");
        if (!bands.length) { return; }

        for (var i = 0; i < bands.length; i++) {
            bands[i].addEventListener("click", function (event) {
                activate(event.currentTarget);
            });
        }

        // Open Level 1 by default so the panel is never empty on load.
        var first = document.querySelector(".pm-band[data-level=\"1\"]") || bands[0];
        activate(first);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
