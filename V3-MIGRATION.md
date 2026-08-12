# VirusTotal V3 API cleanup

This change removes methods that targeted routes not provided by the VirusTotal V3 API and separates public endpoints from licensed Intelligence features. The library is not yet published, so the cleanup favors a clear V3 contract over compatibility shims.

## Search

`SearchAsync` now calls the public `/search` endpoint. Use `SearchIntelligenceAsync` for advanced VirusTotal Intelligence queries, ordering, and descriptors.

## Reports and file behavior

The multi-report methods now make one documented object request per id and preserve input order. They return a non-null list and are no longer limited to four ids.

Use these file behavior APIs:

- `GetFileBehaviorsAsync(fileId, ...)` lists sandbox behavior objects.
- `GetFileBehaviorAsync(behaviorId)` gets one behavior object.
- `GetFileBehaviorSummaryAsync(fileId)` gets the combined summary.
- `DownloadFileBehaviorArtifactAsync(behaviorId, artifact)` downloads HTML, EVTX, PCAP, or memory-dump artifacts.

The former network-traffic, PE-info, classification, strings, crowdsourced YARA, and crowdsourced IDS methods were removed because their routes do not exist. PE metadata, popular threat classification, crowdsourced results, and future fields are available from `FileAttributes`; sandbox details are available from behavior objects and summaries.

## Uploads, feeds, and ZIP files

Private scanning now posts to `/private/files`. Pass `PrivateFileUploadOptions` for sandbox, internet, TLS interception, command-line, archive password, retention, storage region, interaction timeout, and locale settings. Large private files use `/private/files/upload_url`.

`DownloadFeedBatchAsync` replaces the old feed methods. It accepts `FeedType`, a UTC-normalized timestamp, and minute or hour granularity, and returns the compressed feed stream.

The unsupported bundle API was replaced by VirusTotal Intelligence ZIP jobs:

- `CreateZipFileAsync`
- `GetZipFileAsync`
- `GetZipFileDownloadUrlAsync`
- `DownloadZipFileAsync`

## Graphs, collections, and comments

Graph collaborators are now modeled as viewer or editor permissions. Use `GetGraphPermissionsAsync`, `GrantGraphPermissionAsync`, and `RevokeGraphPermissionAsync` with user or group descriptors.

Graph create and update requests now use the V3 graph document fields: `GraphData`, `Nodes`, `Links`, and `Private`. The former name-only write shape was removed because it did not match the V3 graph schema.

Graph canvas state is available through `Position` (`X`, `Y`, and `Scale`) on both read and write attributes.

Collection relationships now distinguish full objects from descriptors. Use `GetCollectionObjectsAsync` or `GetCollectionRelationshipDescriptorsAsync`, and mutate relationships with `RelationshipDescriptorsRequest`.

Comments are deleted through the global comment id with `DeleteCommentAsync(commentId)`.

## Resource types

`ResourceType.Search`, `ResourceType.Feed`, and `ResourceType.Bundle` were removed because they are not V3 object types. `Group` and `ZipFile` were added, and file behavior serializes as `file_behaviour`.
