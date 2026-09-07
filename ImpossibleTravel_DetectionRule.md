# [THREAT DETECTION RULE Impossible Travel Login]

---

## 📋 Rule Metadata

| Field | Value |
|---|---|
| **Rule Name** | Impossible Travel Login |
| **Rule ID** | SENTINEL-AUTH-01 |
| **Rule Type** | Scheduled Analytics Rule |
| **Severity** | 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low |
| **Status** | Draft |
| **Data Connector** | [e.g. Azure Entra ID — SigninLogs] |
| **Query Frequency** | Every 1 hour |
| **Query Period** |  7-day lookback |
| **Alert Threshold** | Generate alert on any result (> 0 rows) |
| **MITRE Tactics** | Initial Access · Credential Access |
| **Created** | 2026-03-05 |
| **Last Modified** | 2026-03-10 |
| **Owner** | Olebogeng Sebogodi |
| **Classification** | TLP:GREEN |

---

## Description

This Sentinel Analytics Rule detects Impossible Travel — a scenario where a user account successfully authenticates from two geographically distant locations within a timeframe that makes physical travel between them impossible. The pattern is a strong indicator of credential compromise, account takeover, or the use of anonymisation infrastructure such as VPNs, proxies, or Tor exit nodes.

### Detection Logic

- Collect all successful Azure Entra ID sign-ins over the lookback window (default: 1 hour)
- For each user, sort events chronologically and compare consecutive login pairs
- Calculate the great-circle distance (km) between each pair using the Haversine formula 
- Calculate the time delta (minutes) between each pair 
- Compute the minimum required travel speed (km/h) to move between both locations 
- Flag any pair where distance ≥ 500 km AND time delta ≤ 60 minutes 
- Assign severity: CRITICAL (>1,000 km/h), HIGH (>500 km/h), MEDIUM (>200 km/h)

---

## KQL Detection Query

> Deploy in Sentinel under **Analytics → Create → Scheduled Query Rule**.

```kql
// ============================================================
// Impossible Travel Login Detection - Microsoft Sentinel
// Author: Olebogeng Sebogodi
// Last Updated: 2026-03-09
// ============================================================

// -- Tunable parameters --
let lookback = 7d; // Detection window 
let travelThresholdKm = 200; // Min km to flag as suspicious
let timeThresholdMinutes= 60; // Max minutes between logins

// Haversine great-circle distance (returns km) 
let haversine = (lat1:real, lon1:real, lat2:real, lon2:real) { let dLat = radians(lat2 - lat1); 
let dLon = radians(lon2 - lon1); 
let a = sin(dLat/2)*sin(dLat/2) + cos(radians(lat1))*cos(radians(lat2))* sin(dLon/2)*sin(dLon/2); 
6371.0 * 2 * atan2(sqrt(a), sqrt(1-a)) 
};

// -- Main query --
SigninLogs 
| where TimeGenerated >= ago(lookback) 
| where ResultType == 0 // Successful logins only 
| where isnotempty(LocationDetails.countryOrRegion) 
| project 
TimeGenerated, 
UserPrincipalName, 
UserId, 
IPAddress, 
Latitude = toreal(LocationDetails.geoCoordinates.latitude), 
Longitude = toreal(LocationDetails.geoCoordinates.longitude), 
Country = tostring(LocationDetails.countryOrRegion), 
City = tostring(LocationDetails.city), AppDisplayName, 
DeviceDetail, 
RiskLevelDuringSignIn, 
RiskState, 
ClientAppUsed, 
ConditionalAccessStatus 
| sort by UserPrincipalName asc, TimeGenerated asc 
| extend 
PrevTime = prev(TimeGenerated, 1), 
PrevLatitude = prev(Latitude, 1), 
PrevLongitude = prev(Longitude, 1), 
PrevCountry = prev(Country, 1), 
PrevCity = prev(City, 1), 
PrevIP = prev(IPAddress, 1), 
PrevUser = prev(UserPrincipalName, 1) 
| where UserPrincipalName == PrevUser 
| extend 
TimeDeltaMinutes = datetime_diff('minute', TimeGenerated, PrevTime),
DistanceKm = haversine(PrevLatitude, PrevLongitude, Latitude, Longitude) 
| where TimeDeltaMinutes > 0 and TimeDeltaMinutes <= timeThresholdMinutes 
| where DistanceKm >= travelThresholdKm 
| extend 
RequiredSpeedKmH = DistanceKm / (toreal(TimeDeltaMinutes) / 60.0), 
TravelSummary = strcat( PrevCity,'(',PrevCountry,') -> ',City,'(',Country,')' 
) 
| extend 
AlertSeverity = case( RequiredSpeedKmH > 1000, 'CRITICAL', 
RequiredSpeedKmH > 500, 'HIGH', 
RequiredSpeedKmH > 200, 'MEDIUM', 
'LOW') 
| project 
TimeGenerated, AlertSeverity, UserPrincipalName, UserId, TravelSummary, 
DistanceKm = round(DistanceKm, 1), 
TimeDeltaMinutes, 
RequiredSpeedKmH = round(RequiredSpeedKmH, 1), 
Login1_Time = PrevTime, 
Login1_IP = PrevIP, 
Login2_Time = TimeGenerated, 
Login2_IP = IPAddress, 
AppDisplayName, ClientAppUsed, RiskLevelDuringSignIn, RiskState, ConditionalAccessStatus 
| order by RequiredSpeedKmH desc
```

### Query Tuning Parameters

| Parameter | Default | Recommended Range | Description |
|---|---|---|---|
| `lookback` | `7d` | `1d – 30d` | Historical window for event collection |
| `travelThresholdKm` | `200` | `200 – 1000` | Minimum distance to trigger an alert|
| `timeThresholdMinutes` | `60min` | `15-200` | Max time delta between two logins |
| `Speed > 500 km/h` | `HIGH` | `Configurable` | Exceeds maximum vehicle speed below commercial aircraft speed |
| `Speed > 1,000 km/h` | `CRITICAL` | `Configurable` | Exceeds maximum commercial aircraft speed |

---

## False Positive Guidance

### Known Benign Scenarios

- Corporate VPNs and split-tunnel configurations routing DNS through a different country
- Shared service accounts administered by global teams logging in near-simultaneously
- Mobile apps using cached authentication tokens from a previous geographic location
- Satellite internet providers (e.g., Starlink) with geographically inconsistent IP resolution 
- IPv6 addresses where geolocation databases have low accuracy 
- Tor exit nodes and commercial proxies used by security researchers

### Recommended Exclusions

- Create a Sentinel Watchlist(VPN_Known_Egress_IPs) and add a | where IPAddress !in (watchlist) filter
- Exclude shared / service accounts via a UPN allow-list if managed by distributed admins 
- Add | where RiskState != 'remediated' to suppress already-resolved risk events

---

## Investigation Steps

>  **Analyst Reminder:** Treat this as a potential account takeover until proven otherwise. Do NOT alert the user until initial triage is complete — avoid tipping off a potential attacker.

### Phase 1 — Initial Triage *(0–15 minutes)*

1. **Identify the affected account:** confirm UserPrincipalName, both login locations, time delta, distance, and implied speed from the alert fields.
2. **Verify not a false positive:** check if the login IPs belong to known VPN egress ranges, Tor exit nodes, or corporate proxies using threat intelligence lookups (VirusTotal, Shodan, or your TIP)
3. **Check Entra ID Identity Protection:** navigate to Entra ID > Risky Users and assess current risk level and any prior risk events
4. **Review application scope:** determine if both logins target the same app — cross-app impossible travel is more suspicious and may indicate token replay
5. **Review MFA status:** if one login bypassed MFA and the other did not, this is a strong indicator of a stolen session token or MFA fatigue attack

### Phase 2 — Deep-Dive Investigation *(15–60 minutes)*

#### KQL Hunt 1 — Login History

```kql
// Full login history for the flagged user (last 24 hours)
[TableName]
| where TimeGenerated >= ago(24h)
| where UserPrincipalName == "" 
| project TimeGenerated, IPAddress, Location, AppDisplayName, DeviceDetail, ResultType, RiskLevelDuringSignIn, ClientAppUsed, ConditionalAccessStatus 
| order by TimeGenerated desc
```

#### KQL Hunt 2 — Concurrent Multi-Country Sessions

```kql
// Detect concurrent multi-country sessions
SigninLogs 
| where TimeGenerated between (ago(24h) .. now()) 
| where UserPrincipalName == "" 
| where ResultType == 0 
| summarize Sessions = count(), 
Countries = make_set(tostring(LocationDetails.countryOrRegion)),
IPs = make_set(IPAddress) 
by bin(TimeGenerated, 1h) 
| where array_length(Countries) > 1
```

#### KQL Hunt 3 — Post-Compromise Privilege Activity

```kql
// Post-compromise privilege / account manipulation
AuditLogs 
| where TimeGenerated >= ago(24h) 
| where InitiatedBy.user.userPrincipalName == "" 
| where OperationName in ( 
    'Add member to role', 'Reset user password', 
    'Update application', 'Add service principal', 
    'Set federation settings on domain', 'Update user') 
| project TimeGenerated, OperationName, Result, TargetResources 
| order by TimeGenerated desc
```

6. **Review Unified Audit Log:** check for inbox rule creation, external mail forwarding, bulk downloads, or suspicious OAuth app consents
7. **Correlate with endpoint telemetry:** verify enrolled devices match the DeviceDetail field; a mismatched or unmanaged device is a high-risk indicator
8. **Review Conditional Access evaluation:** if ConditionalAccessStatus is not 'success', investigate which policy was bypassed and why


### Phase 3 — Containment Decision

| Verdict | Recommended Action |
|---|---|
| Confirmed threat/compromise | Containment action Disable account in Entra ID, revoke all refresh tokens(Revoke-MgUserSignInSession -UserId), initiate out-of-band password reset, notify manager|
|  High suspicion | Apply temporary Conditional Access policy requiring compliant device + strong MFA challenge pending further investigation |
|  False positive | Document reason (VPN / proxy / travel), add IP to watchlist exclusion, close incident with classification and analyst notes |
|  Evidence preservation | Export SigninLogs and AuditLogs to storage account or Log Analytics for forensic retention regardless of verdict |

---

##  MITRE ATT&CK Mapping

The following techniques are covered by this detection rule. The primary tactic is Initial Access via Valid Accounts (T1078), but the signal is consistent with multiple credential-theft and evasion patterns.

| Tactic | Technique ID | Technique Name | Relevance to This Rule |
|---|---|---|---|
| Initial Access | [T1078] | Valid Accounts | Core detection — attacker authenticates with stolen credentials from a foreign location |
| Initial Access | [T1078.004] | Cloud Accounts | Targets Entra ID cloud identity sign-ins via SigninLogs |
| Initial Access | [T1133] | External Remote Services | Login may target cloud apps, VPN portals, or remote access services |
| Credential Access | [T1110] | Brute Force | LImpossible travel can follow a successful brute-force or password spray |
| Credential Access | [T1110.003] | Password Spraying | Distributed low-and-slow spraying across IPs can trigger this detection |
| Credential Access | [T1539] | Steal Web Session Cookie | Token replay from a stolen session cookie manifests as impossible travel |

### Coverage Summary

| Tactic | Coverage | Notes |
|---|---|---|
| Initial Access | Strong | Primary detection surface — core rule purpose |
| Credential Access | Moderate | Correlates strongly with credential theft patterns |

---

##  Automated Response Playbook

> Configure as a LogicApp in Sentinel under **Automation → Create → Automation rule**, triggered on alert creation.

| Action | Trigger Condition | Description |
|---|---|---|
| `IP Enrichment` | All alerts | Enrich both login IPs with MDTI / VirusTotal threat intelligence and append results to incident|
| `Manager Notification` | All alerts  | Send Teams / email to user's line manager via Microsoft Graph API asking to verify user location |
| `CA Step-Up` | Speed > 500 km/h | Apply temporary Conditional Access policy requiring FIDO2 or Windows Hello for 24 hours |
| `Auto Token Revocation` | Speed > 1,000 km/h | Immediately revoke all refresh tokens via Microsoft Graph |
| `ITSM Ticket` | All alerts | Auto-create ServiceNow / Jira ticket with full alert context and link to Sentinel incident |

---

##  Deployment Instructions

### Prerequisites

- [ ] Microsoft Sentinel workspace with Entra ID Diagnostic Settings forwarding SigninLogs and AuditLogs
- [ ] Azure AD Premium P2 license (required for Identity Protection risk signals used in triage)
- [ ] Sentinel Contributor RBAC role on the Sentinel workspace

### Deployment Steps

1. Navigate to **Microsoft Sentinel → Analytics → + Create → Scheduled query rule**
2. **General tab:** set Name, Severity, and Tactics as per the metadata table above
3. **Set rule logic:** paste the KQL query from the section above; configure scheduling and lookback
4. **Alert enrichment:** map entities — [e.g. Account: UserPrincipalName, IP: IPAddress]
5. **Automated response:** attach Logic App playbook if configured
6. Review and **Enable** the rule

### Validation

- [ ] Verify events appear in Logs within 10 minutes of a known triggering event
- [ ] Use the **Simulation** feature in the Analytics rule editor to test against historical data
- [ ] Authenticate from two VPN endpoints in different continents within 30 minutes and confirm an alert is generated

---

##  References

- [Initial Access](https://attack.mitre.org/tactics/TA0001/)
- [Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [Sentinel Scheduled Rules](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules?tabs=defender-portal)

---

##  Change Log

| Version | Date | Author | Summary |
|---|---|---|---|
| 1.0 | 2026-03-05 | Olebogeng Sebogodi | Initial rule creation |
| 2.0 | 2026-03-09 | Olebogeng Sebogodi | Credential Access Mapping & publication |
