# API Coverage & Parity

This document tracks VirusTotal API v3 feature coverage and parity between the .NET client and PowerShell cmdlets.

Legend: ✅ full, ⚠️ partial, ❌ missing
Source: https://docs.virustotal.com/reference/overview
Last reviewed: 2026-01-17

## IOC Reputation & Enrichment

| Area | C# (.NET) | PowerShell | Notes |
| --- | --- | --- | --- |
| IP addresses | ⚠️ | ⚠️ | C# has reports, relationships, related data; missing rescan + object descriptors. PowerShell covers report only via `Get-VirusReport`. |
| Domains & resolutions | ⚠️ | ⚠️ | C# has report, DNS, resolutions, relationships; missing rescan + object descriptors. PowerShell covers report only. |
| Files | ⚠️ | ⚠️ | C# has submit, report, reanalyze, download, relationships, comments/votes; missing some crowd rules objects. PowerShell supports report + submit. |
| File behaviours | ⚠️ | ❌ | C# has behaviour report/summary + network traffic; missing HTML/EVTX/memdump endpoints. |
| URLs | ✅ | ⚠️ | C# has submit, report, reanalyze, relationships, comments/votes. PowerShell supports report + submit. |
| Comments | ⚠️ | ⚠️ | C# can get/create comments; missing delete, latest comments, comment votes. PowerShell can get comments for file/URL only. |
| Analyses / submissions / operations | ⚠️ | ❌ | C# has analysis fetch + submission lists; missing operation objects. |
| Attack tactics | ❌ | ❌ | Not implemented. |
| Attack techniques | ❌ | ❌ | Not implemented. |
| Popular threat categories | ✅ | ❌ | C# has `GetPopularThreatCategoriesAsync`. |
| Code insights | ❌ | ❌ | Not implemented. |
| Saved searches | ❌ | ❌ | Not implemented. |
| SSL certificates | ✅ | ❌ | C# supports certificate reports and domain/IP relationships. |

## VT Enterprise

| Area | C# (.NET) | PowerShell | Notes |
| --- | --- | --- | --- |
| Search & metadata | ⚠️ | ❌ | C# supports basic search; no advanced corpus/metadata endpoints. |
| Collections | ⚠️ | ❌ | C# supports CRUD + items; missing export + collection search. |
| Bundles | ⚠️ | ❌ | C# supports CRUD + items; missing export + bundle search. |
| Threat actors | ❌ | ❌ | Not implemented. |
| References | ❌ | ❌ | Not implemented. |
| Zipping files | ❌ | ❌ | Not implemented. |

## VT Hunting

| Area | C# (.NET) | PowerShell | Notes |
| --- | --- | --- | --- |
| YARA rules | ⚠️ | ❌ | C# supports YARA rulesets CRUD + watchers; missing transfer/advanced ops. |
| IoC stream | ⚠️ | ❌ | C# supports stream fetch only. |
| Livehunt | ⚠️ | ❌ | C# supports notifications + acknowledgement + file download; missing some ruleset admin operations. |
| Monitors (items/events) | ⚠️ | ❌ | C# supports monitor items + events; missing advanced workflows. |
| Retrohunt | ⚠️ | ❌ | C# supports create/get/list/delete; missing abort + some match details. |

## VT Graph

| Area | C# (.NET) | PowerShell | Notes |
| --- | --- | --- | --- |
| VT Graphs | ⚠️ | ❌ | C# supports CRUD + comments + collaborators; missing search + ACL coverage. |
| VT Graph permissions & ACL | ❌ | ❌ | Not implemented. |

## VT Private Scanning

| Area | C# (.NET) | PowerShell | Notes |
| --- | --- | --- | --- |
| Files | ⚠️ | ❌ | C# supports private file submit + get private analysis. |
| Analyses | ⚠️ | ❌ | C# supports get private analysis only. |
| File behaviours | ❌ | ❌ | Not implemented. |
| URLs | ❌ | ❌ | Not implemented. |
| Zipping private files | ❌ | ❌ | Not implemented. |

## VT Feeds

| Area | C# (.NET) | PowerShell | Notes |
| --- | --- | --- | --- |
| File intelligence feed | ⚠️ | ❌ | C# supports generic feed API. |
| Sandbox analyses feed | ⚠️ | ❌ | C# supports generic feed API. |
| Domain intelligence feed | ⚠️ | ❌ | C# supports generic feed API. |
| IP intelligence feed | ⚠️ | ❌ | C# supports generic feed API. |
| URL intelligence feed | ⚠️ | ❌ | C# supports generic feed API. |

## VT Enterprise Administration

| Area | C# (.NET) | PowerShell | Notes |
| --- | --- | --- | --- |
| User management | ⚠️ | ⚠️ | C# has get user/privileges/quota; PowerShell has `Get-VirusUser`. |
| Group management | ❌ | ❌ | Not implemented. |
| Quota management | ⚠️ | ⚠️ | C# has get quota only; PowerShell via `Get-VirusUser`. |
| Service account management | ❌ | ❌ | Not implemented. |
| Audit log | ❌ | ❌ | Not implemented. |

## VT Augment

| Area | C# (.NET) | PowerShell | Notes |
| --- | --- | --- | --- |
| VT Augment | ❌ | ❌ | Not implemented. |

## TODO (controlled parity plan)

1. Confirm full API v3 endpoint list and align it with existing C# methods and models.
2. Define minimal PowerShell surface (one cmdlet per resource) vs full parity.
3. Implement PowerShell parity in phases:
   - Phase 1: Collections, Bundles, Graphs
   - Phase 2: Intelligence search + Retrohunt
   - Phase 3: Livehunt + IoC stream
   - Phase 4: YARA rulesets + Feeds + Private scanning
4. Add tests for each new cmdlet in both PowerShell 7 and Windows PowerShell 5.1.
5. Update examples + README for each phase.
