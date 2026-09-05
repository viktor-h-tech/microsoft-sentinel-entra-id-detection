# Incident Walkthrough — Repeated Failed Entra ID Sign-Ins

## Scenario

A non-privileged lab test account generated repeated failed sign-in attempts. The Microsoft Sentinel analytics rule was expected to create an incident when the configured threshold was met.

## Analyst validation flow

1. Open the incident and confirm that it originated from the **Entra ID Failed Sign-In Detection** scheduled analytics rule.
2. Review the mapped account and IP entities.
3. Verify that the alert contains at least three failed sign-ins for the same user and IP within the configured 10-minute bin.
4. Query `SigninLogs` for the affected user and source IP to understand the surrounding authentication activity.
5. Determine whether the activity matches the controlled test. In a real investigation, compare it with expected user behavior, conditional-access results, sign-in location, device details, and other identity telemetry.
6. Document the disposition and any needed response action.

## Example investigation query

```kql
SigninLogs
| where TimeGenerated > ago(30m)
| where UserPrincipalName == "<affected-user>"
| where IPAddress == "<source-ip>"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription, AppDisplayName, Location
| order by TimeGenerated desc
```

## Lab outcome

The test generated a Microsoft Sentinel incident, confirming the pipeline from Entra ID log ingestion through KQL detection and incident creation.

## Production tuning notes

- Group related alerts to avoid repeated incidents when scheduled queries use overlapping time windows.
- Suppress known benign sources only after reviewing evidence.
- Adjust the threshold and time window against normal tenant behavior.
- Add contextual fields and automation only after confirming the signal quality.
