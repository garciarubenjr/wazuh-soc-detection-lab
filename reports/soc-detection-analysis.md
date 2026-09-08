# SOC Detection & Event Analysis Report

## Assessment Information

| Field | Details |
|---|---|
| Platform | Wazuh 4.14 |
| Manager OS | Ubuntu 24.04 |
| Endpoint OS | Ubuntu 24.04 |
| Agent Status | Active |
| Environment | Internal VMware Lab |
| Assessment Dates | December 29–30, 2025 |
| Analyst | Ruben Garcia |

---

## Executive Summary

A Wazuh-based security monitoring environment was deployed to collect and analyze telemetry from a Linux endpoint.

The lab successfully demonstrated several core SOC monitoring capabilities, including:

- Endpoint agent enrollment and health monitoring
- Detection of listening-port changes
- File integrity monitoring
- Privileged command activity logging
- Security alert generation
- MITRE ATT&CK contextualization
- Analyst review of endpoint security events

The objective of this project was to demonstrate the complete detection workflow from endpoint telemetry collection through alert analysis and documentation.

---

## Environment Overview

The environment consisted of a Wazuh manager and a monitored Ubuntu endpoint operating within an isolated VMware lab network.

The Wazuh agent was successfully configured, enabled, and observed reporting telemetry to the manager.

Supporting evidence:

- [Wazuh Dashboard](../evidence/screenshots/01-wazuh-dashboard.png)
- [Agent Configuration](../evidence/screenshots/02-agent-configuration.png)
- [Agent Enabled](../evidence/screenshots/03-agent-enabled.png)
- [Active Agent](../evidence/screenshots/04-active-agent.png)

---

## Detection Workflow

1. Deploy Wazuh monitoring infrastructure
2. Configure endpoint agent
3. Verify agent connectivity
4. Generate security-relevant endpoint activity
5. Review Wazuh alerts
6. Analyze event severity and context
7. Correlate activity with MITRE ATT&CK where available
8. Preserve alert evidence
9. Document analyst observations

---

# Detection 1 — Listening Port Change

## Alert Details

| Field | Value |
|---|---|
| Wazuh Rule ID | 533 |
| Severity | 7 — Medium |
| Description | Listening ports status changed |
| MITRE ATT&CK | T1046 — Network Service Discovery |
| Evidence | Network listening-state change detected |

Wazuh generated an alert after identifying a change in the endpoint's listening network ports.

Changes to listening services are security-relevant because newly opened ports can indicate:

- Installation or activation of a new service
- Configuration changes
- Unexpected application behavior
- Administrative activity
- Potential persistence or remote-access exposure

The event itself does not prove malicious activity. Analyst review is required to determine whether the change is expected.

![Listening port alert](../evidence/screenshots/06-listening-port-alert.png)

## Analyst Assessment

The alert successfully demonstrated Wazuh's ability to identify changes in network service exposure.

In a production SOC environment, follow-up validation would include identifying the associated process, service owner, executable path, user context, and whether the port change corresponded with an approved system change.

---

# Detection 2 — Privileged Access Activity

Wazuh recorded the execution of privileged activity through `sudo`.

![Sudo activity alert](../evidence/screenshots/05-sudo-activity-alert.png)

Privileged command execution is important SOC telemetry because administrative activity can represent either legitimate system administration or unauthorized privilege use.

## Analyst Assessment

The event demonstrated that privileged Linux activity could be collected and surfaced for analyst review.

A production investigation would correlate the event with:

- User identity
- Command executed
- Authentication source
- Timestamp
- Related process activity
- Change-management records
- Other alerts from the same endpoint

The detection should therefore be treated as security-relevant activity requiring context rather than automatically classified as malicious.

---

# Detection 3 — File Integrity Monitoring

The environment also demonstrated Wazuh File Integrity Monitoring capabilities.

Observed activity included:

- File creation
- File deletion
- Real-time file system change detection

File integrity monitoring can help identify changes to sensitive files, configuration files, application content, and other monitored locations.

## Analyst Assessment

The successful detection confirms that the Wazuh agent was capable of monitoring file-system activity and generating telemetry when monitored objects changed.

In an enterprise environment, analysts would validate:

- File path
- User responsible for the change
- Associated process
- File hash
- Creation/modification/deletion time
- Whether the change was authorized

---

## MITRE ATT&CK Context

The listening-port event was associated with:

**T1046 — Network Service Discovery**

MITRE ATT&CK mappings provide useful investigation context, but a mapped technique alone does not prove an attack occurred.

Analysts should use ATT&CK as one source of context alongside host telemetry, user activity, process execution, network activity, and organizational change records.

---

## Event Evidence

Supporting alert data is retained in:

[Wazuh Alert Event Export](../evidence/events/wazuh-alert-events.csv)

The exported event data provides supporting telemetry for additional analysis beyond dashboard screenshots.

---

## Analyst Findings

The lab demonstrated that Wazuh could successfully:

- Enroll and monitor a Linux endpoint
- Detect privileged command activity
- Detect changes in listening network services
- Monitor file-system changes
- Assign alert severity
- Provide MITRE ATT&CK context
- Preserve security event data for investigation

No malicious compromise is claimed as part of this lab.

The objective was to validate detection, monitoring, investigation, and documentation capabilities within a controlled environment.

---

## SOC Analysis Principles Demonstrated

This project reinforced several important SOC concepts:

- An alert is not automatically an incident.
- Detection requires analyst context.
- Privileged activity should be monitored even when legitimate.
- Changes in exposed network services warrant investigation.
- File-system changes can provide valuable endpoint telemetry.
- MITRE ATT&CK mappings assist investigation but do not prove malicious intent.
- Raw event evidence should be retained alongside screenshots.
- Analysts should document both what was observed and what remains unknown.

---

## Evidence Summary

| Evidence | Purpose |
|---|---|
| Wazuh Dashboard | Monitoring platform operational |
| Agent Configuration | Endpoint configured for monitoring |
| Agent Enabled | Wazuh agent service enabled |
| Active Agent | Endpoint successfully reporting |
| Sudo Activity Alert | Privileged activity detection |
| Listening Port Alert | Network service-change detection |
| CSV Event Export | Raw alert/event evidence |

---

## Conclusion

The Wazuh SOC Detection Lab successfully demonstrated an end-to-end endpoint monitoring workflow.

Security-relevant activity was generated on a monitored Linux endpoint, collected by the Wazuh agent, analyzed by the Wazuh manager, surfaced as alerts, and preserved for analyst review.

The project demonstrates foundational SOC capabilities involving endpoint telemetry, alert triage, detection analysis, MITRE ATT&CK contextualization, evidence preservation, and security reporting.

---

## Disclaimer

This analysis was produced from activity generated in a controlled cybersecurity lab environment.

The events documented in this report were created for authorized security training and detection-validation purposes and do not represent a real-world compromise.
