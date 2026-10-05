# Incident Report: Azure RBAC Role Assignment

## Incident Summary

A controlled Azure role assignment was performed as part of a Microsoft Sentinel security-monitoring lab. The **Contributor** role was intentionally assigned to the user-assigned managed identity `id-sentinel-rbac-lab` at the `rg-sentinel-rbac-lab` resource-group scope.

Azure Activity logs recorded the successful role assignment. A custom Microsoft Sentinel analytics rule detected the event and generated a medium-severity alert and incident. After investigation, the Contributor assignment was removed and the incident was closed as a benign positive.

No unauthorized access or malicious activity occurred.

## Incident Classification

| Field | Value |
|---|---|
| Incident ID | AZ-SOC-LAB-001 |
| Microsoft Sentinel incident | Incident 1 |
| Incident title | SOC - Azure RBAC Role Assignment Created |
| Severity | Medium |
| Status | Closed |
| Classification | Benign Positive |
| Classification reason | Suspicious But Expected |
| Event type | Azure RBAC role assignment |
| Affected identity | `id-sentinel-rbac-lab` |
| Assigned role | Contributor |
| Assignment scope | `rg-sentinel-rbac-lab` resource group |
| Environment | Authorized Azure security-monitoring lab |

## Scope and Authorization

This activity was performed in a controlled lab environment within my own Azure for Students subscription. The role assignment was authorized and created specifically to test Azure Activity log ingestion, KQL investigation, Microsoft Sentinel analytics, incident creation, and containment procedures.

The Contributor role was limited to the lab resource group. It was not assigned at the subscription, management-group, or tenant scope.

## Environment

| Component | Configuration |
|---|---|
| Resource group | `rg-sentinel-rbac-lab` |
| Log Analytics workspace | `law-sentinel-rbac-lab-2026` |
| Microsoft Sentinel | Enabled |
| Data connector | Azure Activity |
| Test identity | `id-sentinel-rbac-lab` |
| Temporary role | Contributor |
| Analytics rule | SOC - Azure RBAC Role Assignment Created |
| Rule severity | Medium |
| Query frequency | 5 minutes |
| Query lookback period | 15 minutes |

## Detection Logic

The custom Microsoft Sentinel analytics rule searched Azure Activity logs for successful RBAC role-assignment creation events.

```kusto
AzureActivity
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue =~ "Success"
| extend InitiatingAccount = tostring(Caller)
| project TimeGenerated,
          InitiatingAccount,
          OperationNameValue,
          ActivityStatusValue,
          ResourceGroup,
          ResourceId
```

The rule ran every five minutes and reviewed the preceding fifteen minutes of activity.

## Incident Timeline

| Time (UTC) | Event |
|---|---|
| 2026-10-05 05:49:08 | Contributor role assignment completed successfully |
| 2026-10-05 05:54:49 | Microsoft Sentinel analytics rule generated a medium-severity alert |
| 2026-10-05 05:54:53 | Microsoft Sentinel created Incident 1 |
| 2026-10-05 06:21:00 | Contributor role-assignment removal started |
| 2026-10-05 06:21:01 | Contributor role-assignment removal completed successfully |
| After containment verification | Incident closed as Benign Positive — Suspicious But Expected |

The alert was generated approximately five minutes and forty-one seconds after the successful role assignment.

## Investigation

The Azure Activity event was investigated using Microsoft Sentinel and Kusto Query Language. The investigation confirmed:

- The operation was `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`.
- The operation completed successfully.
- The assignment occurred within `RG-SENTINEL-RBAC-LAB`.
- The affected identity was the lab-managed identity `id-sentinel-rbac-lab`.
- The assigned role was Contributor.
- The assignment was limited to the lab resource group.
- The activity matched the authorized simulation plan.
- No evidence of unauthorized access or malicious activity was identified.

### Role-assignment investigation query

```kusto
AzureActivity
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue =~ "Success"
| project TimeGenerated,
          OperationNameValue,
          ActivityStatusValue,
          ResourceGroup,
          ResourceId,
          Caller
| sort by TimeGenerated desc
```

## Alert and Incident Validation

Microsoft Sentinel successfully generated:

- One medium-severity security alert
- One Microsoft Sentinel incident
- A reference to the custom analytics rule
- A record of the successful Azure RBAC role assignment

The results confirmed that the Azure Activity connector, Log Analytics workspace, KQL detection logic, analytics rule, and incident-generation workflow were operating correctly.

## Containment

The Contributor role assignment was removed from `id-sentinel-rbac-lab` at the lab resource-group scope.

After removal:

- The resource-group role-assignment list was searched for the managed identity.
- No Contributor assignment remained.
- Azure Activity recorded the role-assignment deletion.
- The deletion operation completed successfully.

### Containment-verification query

```kusto
AzureActivity
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/DELETE"
| project TimeGenerated,
          OperationNameValue,
          ActivityStatusValue,
          ResourceGroup,
          ResourceId,
          Caller
| sort by TimeGenerated desc
```

## Impact Assessment

No unauthorized access occurred. The managed identity was created specifically for the controlled simulation, and the temporary privilege was restricted to the lab resource group.

No production resources, university resources, or unrelated identities were used or modified as part of the simulation.

## Root Cause

The alert resulted from an intentional and authorized RBAC role assignment created to validate the Microsoft Sentinel detection and incident-response workflow.

The detection was therefore accurate, but the underlying activity was expected.

## Incident Closure

The incident was closed with the following classification:

- **Status:** Closed
- **Classification:** Benign Positive
- **Classification reason:** Suspicious But Expected

Closure comment:

> Authorized security-lab simulation. The Contributor role was intentionally assigned to the test managed identity to validate Azure Activity log ingestion and the custom Microsoft Sentinel RBAC detection rule. The alert was investigated and confirmed accurate. Containment was completed by removing the Contributor role assignment, and verification confirmed that the identity no longer retained privileged access. No unauthorized access or malicious activity occurred.

## Recommendations

- Follow the principle of least privilege when assigning Azure roles.
- Assign privileged roles at the narrowest practical scope.
- Monitor successful creation and deletion of Azure RBAC assignments.
- Investigate unexpected role assignments promptly.
- Use time-bound privileged access when available.
- Require appropriate approval for privileged role assignments.
- Review inactive managed identities and remove unnecessary access.
- Maintain Azure Activity log ingestion in Microsoft Sentinel.
- Document incident evidence and containment actions.
- Remove temporary lab resources after evidence has been preserved.

## Evidence Collected

The following evidence was collected during the project:

- Azure budget configuration
- Lab resource group
- Log Analytics workspace
- Microsoft Sentinel enablement
- Azure Activity connector configuration
- Azure Activity log-ingestion validation
- Test managed identity
- Custom Microsoft Sentinel analytics rule
- Successful RBAC role-assignment event
- Microsoft Sentinel alert and incident
- Contributor role-assignment removal
- Successful RBAC deletion event
- Closed incident classification

Sensitive information—including subscription IDs, object IDs, email addresses, and unrelated university identities—was excluded or redacted from the public evidence.

## Conclusion

This controlled exercise demonstrated an end-to-end cloud security monitoring and incident-response workflow using Azure Activity logs, Log Analytics, KQL, Microsoft Sentinel, Azure RBAC, and managed identities.

The role assignment was successfully logged, detected, investigated, contained, verified, classified, and closed. The project demonstrates practical experience with SIEM operations, detection engineering, cloud IAM monitoring, incident triage, containment, and security documentation.
