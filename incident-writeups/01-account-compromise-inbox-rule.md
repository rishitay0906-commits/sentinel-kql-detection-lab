# Incident Writeup: Account Compromise and Malicious Inbox Rule

## Summary
An external actor at IP 175.45.176.99 attempted access to a disabled
account, immediately pivoted to a valid account, signed in successfully,
and created a hidden inbox rule for email collection. Time from first
attempt to persistence was under three seconds.

## Severity
High. Confirmed account compromise with attacker established persistence.

## Affected entities
- Compromised account: adelev@m365x816222.onmicrosoft.com
- Probed account (failed): johns@m365x816222.onmicrosoft.com
- Actor IP: 175.45.176.99

## Timeline (UTC)
- 21:50:17 Failed sign-in to disabled account johns, ResultType 50057, geo KP
- 21:50:19 Successful sign-in to adelev, ResultType 0, multiple sessions
- 21:50:19 New-InboxRule created on adelev mailbox from the same IP

## Investigation steps
1. Detected repeated failed sign-ins to a disabled account from a single IP
   using the brute force detection query (T1110).
2. Checked for successful sign-ins from rare locations. This returned nothing,
   an initial false all-clear, because the successful logins resolved to a
   common location (IL) rather than a rare one.
3. Correlated all activity by the actor IP rather than by geo. This revealed
   the successful adelev logins from the same IP two seconds after the failed
   attempt, confirming compromise.
4. Searched OfficeActivity for inbox rule creation and found a New-InboxRule
   event from the same IP on the adelev mailbox.
5. Inspected the rule parameters.

## Findings
The inbox rule was named "junk" to appear benign. It targeted messages with
"legal" in the subject and set StopProcessingRules to true, suppressing
normal handling so the user would not see targeted correspondence. This is
consistent with post compromise email collection and evasion.

## Key analytical note
The same IP resolved to two different countries (KP and IL) across requests.
Geolocation was treated as unreliable and the IP was used as the primary
correlation key. Relying on geo alone would have missed the compromise.

## Verdict
True positive. Confirmed account takeover with persistence via a malicious
inbox rule.

## Recommended response
- Disable the adelev account and force credential reset.
- Remove the malicious inbox rule and audit for other rules on the mailbox.
- Block IP 175.45.176.99 at the perimeter.
- Hunt for the same IP across all other data sources.
- Review why the disabled account johns was still being targeted and confirm
  it is fully deprovisioned.

## MITRE ATT&CK techniques observed
- T1110 Brute Force
- T1078 Valid Accounts
- T1114.003 Email Collection, Email Forwarding Rule
