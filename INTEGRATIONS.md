= Scry - Third-Party Integrations Guide

This document provides comprehensive configuration and usage information for all third-party integrations available in Scry.

## Table of Contents

1. [Threat Intelligence Platforms](#threat-intelligence-platforms)
2. [SIEM/SOAR Integrations](#siemsoar-integrations)
3. [Case Management](#case-management)
4. [Social Media Collectors](#social-media-collectors)
5. [Configuration Examples](#configuration-examples)

---

## Threat Intelligence Platforms

### MISP (Malware Information Sharing Platform)

**Purpose**: Bi-directional sync with MISP for collaborative threat intelligence sharing.

**Configuration**:
```bash
CTI_MISP_URL=https://your-misp-instance.com
CTI_MISP_API_KEY=your-api-key-here
CTI_MISP_VERIFY_SSL=true
```

**Features**:
- Search events and attributes
- Create events and add observables
- Add sightings to attributes
- Export to STIX 1/2, Suricata, Snort, YARA
- Manage tags and organizations

**Usage Example**:
```python
from scry.integrations.misp import MISPClient

client = MISPClient()

# Search for events
result = client.search_events(value="malicious-domain.com", type_attribute="domain")

# Create event
result = client.create_event(
    info="Phishing Campaign 2024-05",
    severity=1,
    attributes=[
        {"type": "domain", "value": "malicious-domain.com", "to_ids": True}
    ]
)

# Export to STIX 2
result = client.export_stix(event_id="123", version="2")
```

---

### OpenCTI (Open Cyber Threat Intelligence Platform)

**Purpose**: STIX 2.1 threat intelligence platform with knowledge graph capabilities.

**Configuration**:
```bash
CTI_OPENCTI_URL=https://your-opencti-instance.com
CTI_OPENCTI_API_KEY=your-api-key-here
CTI_OPENCTI_VERIFY_SSL=true
```

**Features**:
- GraphQL API for complex queries
- Search indicators, observables, threat actors, malware
- STIX 2.1 bundle import/export
- MITRE ATT&CK integration
- Vulnerability tracking

**Usage Example**:
```python
from scry.integrations.opencti import OpenCTIClient

client = OpenCTIClient()

# Search indicators
result = client.search_indicators(pattern="192.168.1.1", limit=50)

# Get threat actors
result = client.get_threat_actors(limit=100)

# Export STIX bundle
result = client.export_stix_bundle(entity_type="indicator")

# Import STIX bundle
result = client.import_stix_bundle(bundle_data)
```

---

### TAXII 2.1 Client

**Purpose**: Consume STIX 2.1 threat intelligence from TAXII servers.

**Configuration**:
```bash
CTI_TAXII_URL=https://taxii-server.com/taxii2
CTI_TAXII_USERNAME=your-username
CTI_TAXII_PASSWORD=your-password
CTI_TAXII_VERIFY_SSL=true
```

**Features**:
- Discovery and API root enumeration
- Collection browsing
- Object retrieval and manifest queries
- Polling for new/updated objects
- STIX 2.1 indicator extraction

**Usage Example**:
```python
from scry.integrations.taxii import TAXII21Client

client = TAXII21Client()

# Discover TAXII server
result = client.get_discovery()

# List collections
result = client.get_collections(api_root="api1")

# Get objects from collection
result = client.get_objects(
    collection_id="abc-123",
    match_type=["indicator", "malware"],
    limit=100
)

# Poll for new objects
result = client.poll_collection(
    collection_id="abc-123",
    last_poll="2024-05-23T00:00:00Z"
)
```

---

## SIEM/SOAR Integrations

### Microsoft Sentinel

**Purpose**: Azure-native SIEM/SOAR platform integration.

**Configuration**:
```bash
CTI_SENTINEL_WORKSPACE_ID=your-workspace-id
CTI_SENTINEL_API_KEY=your-api-key
CTI_SENTINEL_SUBSCRIPTION_ID=azure-subscription-id
CTI_SENTINEL_RESOURCE_GROUP=your-resource-group
```

**Features**:
- Incident management (create, query, update)
- Threat intelligence indicator management
- KQL log queries
- Watchlist management
- STIX pattern support

**Usage Example**:
```python
from scry.integrations.sentinel import MicrosoftSentinelClient

client = MicrosoftSentinelClient()

# Get incidents
result = client.get_incidents(filter_query="properties/status eq 'New'", top=50)

# Create incident
result = client.create_incident(
    title="Suspicious Activity Detected",
    severity="High",
    description="Multiple failed login attempts from known bad IP"
)

# Add threat indicator
pattern, pattern_type = observable_to_sentinel_pattern("ipv4", "192.168.1.1")
result = client.create_threat_indicator(
    pattern=pattern,
    pattern_type=pattern_type,
    display_name="Known C2 Server",
    confidence=90
)

# Query logs with KQL
result = client.query_logs(
    query="SecurityEvent | where EventID == 4625 | top 100 by TimeGenerated",
    timespan="P1D"
)
```

---

### Splunk

**Purpose**: Enterprise SIEM platform with threat intelligence framework.

**Configuration**:
```bash
CTI_SPLUNK_URL=https://your-splunk-instance.com:8089
CTI_SPLUNK_TOKEN=your-bearer-token
CTI_SPLUNK_VERIFY_SSL=true
```

**Features**:
- SPL search queries
- Notable event management
- Threat Intelligence Framework integration
- Alert management
- Index exploration

**Usage Example**:
```python
from scry.integrations.splunk import SplunkClient

client = SplunkClient()

# Search Splunk
result = client.search(
    query="index=main sourcetype=access_combined error",
    earliest_time="-1h",
    max_results=100
)

# Get notable events
result = client.get_notable_events(earliest_time="-24h", severity="high")

# Create notable event
result = client.create_notable_event(
    title="Anomalous Network Traffic",
    description="C2 beacon detected",
    severity="critical"
)

# Add threat intel
result = client.add_threat_intel(
    ioc_type="domain",
    ioc_value="malicious.com",
    threat_key="c2_domain",
    weight=10
)
```

---

### Elastic Security

**Purpose**: Elastic Stack-based SIEM with detection rules and case management.

**Configuration**:
```bash
CTI_ELASTIC_URL=https://your-elastic-instance.com
CTI_ELASTIC_API_KEY=your-api-key
CTI_ELASTIC_VERIFY_SSL=true
```

**Features**:
- Detection rule management
- Alert/signal querying
- Case management
- Threat indicator ingestion
- ECS (Elastic Common Schema) support

**Usage Example**:
```python
from scry.integrations.elastic import ElasticSecurityClient

client = ElasticSecurityClient()

# Get alerts
result = client.get_alerts(page=1, per_page=50)

# Create detection rule
result = client.create_detection_rule(
    name="Suspicious PowerShell Execution",
    description="Detects suspicious PowerShell commands",
    rule_type="query",
    query="process.name:powershell.exe and process.args:*bypass*",
    risk_score=75,
    severity="high"
)

# Create case
result = client.create_case(
    title="Investigation: Phishing Campaign",
    description="Multiple users reported suspicious emails",
    severity="medium",
    tags=["phishing", "email"]
)

# Add threat indicator
result = client.add_threat_indicator(
    indicator_type="ipv4-addr",
    value="192.168.1.100",
    description="Known malicious IP",
    confidence="High"
)
```

---

## Case Management

### TheHive + Cortex

**Purpose**: Security incident response platform with automated analysis.

**Configuration**:
```bash
# TheHive
CTI_THEHIVE_URL=https://your-thehive-instance.com
CTI_THEHIVE_API_KEY=your-api-key
CTI_THEHIVE_VERIFY_SSL=true

# Cortex
CTI_CORTEX_URL=https://your-cortex-instance.com
CTI_CORTEX_API_KEY=your-api-key
CTI_CORTEX_VERIFY_SSL=true
```

**TheHive Features**:
- Case management (create, search, update)
- Alert management
- Observable tracking
- Task assignment
- TLP/PAP marking

**Cortex Features**:
- Analyzer execution (VirusTotal, MISP, etc.)
- Responder actions (block IP, quarantine file)
- Job report retrieval

**Usage Example**:
```python
from scry.integrations.thehive import TheHiveClient, CortexClient

# TheHive
hive = TheHiveClient()

# Create case
result = hive.create_case(
    title="Ransomware Incident",
    description="Encrypted files detected on multiple hosts",
    severity=3,  # 1=Low, 2=Medium, 3=High, 4=Critical
    tlp=2,  # 0=White, 1=Green, 2=Amber, 3=Red
    tags=["ransomware", "incident"]
)

case_id = result.data["_id"]

# Add observables
result = hive.add_observable(
    case_id=case_id,
    data_type="ip",
    data="192.168.1.100",
    ioc=True,
    tags=["c2"]
)

# Create alert
result = hive.create_alert(
    title="Suspicious DNS Query",
    description="Query to known malicious domain",
    type_alert="internal",
    source="CTI Agent",
    severity=2,
    artifacts=[
        {"dataType": "domain", "data": "malicious.com", "ioc": True}
    ]
)

# Cortex
cortex = CortexClient()

# Get available analyzers
result = cortex.get_analyzers()

# Run analyzer
result = cortex.run_analyzer(
    analyzer_id="VirusTotal_GetReport_3_0",
    data_type="hash",
    data="abcdef1234567890...",
    tlp=2
)

job_id = result.data["id"]

# Get report
result = cortex.get_job_report(job_id)
```

---

## Social Media Collectors

### Reddit

**Purpose**: Monitor security-focused subreddits for threat discussions.

**Configuration**:
```bash
CTI_REDDIT_CLIENT_ID=your-client-id
CTI_REDDIT_CLIENT_SECRET=your-client-secret
```

**Monitored Subreddits** (default):
- r/netsec
- r/cybersecurity
- r/malware
- r/ReverseEngineering
- r/threatintel

**Usage Example**:
```python
from scry.collectors.reddit import RedditCollector

collector = RedditCollector()

# Search posts
result = collector.search_posts(
    query="CVE-2024",
    subreddit="netsec",
    time_filter="week"
)

# Get subreddit posts
result = collector.get_subreddit_posts(
    subreddit="malware",
    sort="hot",
    limit=50
)

# Collect security intel
posts = collector.collect_security_intel(
    keywords=["CVE", "0day", "exploit"],
    subreddits=["netsec", "cybersecurity"],
    time_filter="day"
)
```

---

### X (Twitter)

**Purpose**: Monitor security researchers and threat intel accounts.

**Configuration**:
```bash
CTI_TWITTER_BEARER_TOKEN=your-bearer-token
```

**Monitored Accounts** (default):
- @vxunderground
- @MalwareJake
- @GossiTheDog
- @CVEnew
- @Unit42_Intel

**Usage Example**:
```python
from scry.collectors.twitter import TwitterCollector

collector = TwitterCollector()

# Search recent tweets
result = collector.search_recent_tweets(
    query="CVE -is:retweet lang:en",
    max_results=100
)

# Get user tweets
result = collector.get_user_tweets(
    username="vxunderground",
    max_results=50
)

# Collect security intel
tweets = collector.collect_security_intel(
    keywords=["CVE", "#threatintel", "#malware"],
    accounts=["vxunderground", "MalwareJake"],
    hours_back=24
)
```

---

### Bluesky

**Purpose**: Monitor security researchers on Bluesky social network.

**Configuration**:
```bash
CTI_BLUESKY_HANDLE=your-handle.bsky.social
CTI_BLUESKY_PASSWORD=your-password
```

**Usage Example**:
```python
from scry.collectors.bluesky import BlueskyCollector

collector = BlueskyCollector()

# Search posts
result = collector.search_posts(query="CVE", limit=100)

# Get author feed
result = collector.get_author_feed(
    actor="security-researcher.bsky.social",
    limit=50
)

# Collect security intel
posts = collector.collect_security_intel(
    keywords=["CVE", "vulnerability", "exploit"],
    accounts=["researcher1.bsky.social"]
)
```

---

### Mastodon

**Purpose**: Monitor federated Mastodon instances for security discussions.

**Configuration**:
```bash
CTI_MASTODON_INSTANCE=infosec.exchange
CTI_MASTODON_TOKEN=your-access-token  # Optional
```

**Popular Instances**:
- infosec.exchange (security-focused)
- mastodon.social (general)
- fosstodon.org (open source)

**Usage Example**:
```python
from scry.collectors.mastodon import MastodonCollector

collector = MastodonCollector(instance="infosec.exchange")

# Search posts
result = collector.search_posts(query="CVE-2024", limit=40)

# Get hashtag timeline
result = collector.get_hashtag_timeline(hashtag="threatintel", limit=40)

# Get public timeline
result = collector.get_public_timeline(local=True, limit=40)

# Collect security intel
posts = collector.collect_security_intel(
    keywords=["CVE", "breach"],
    hashtags=["infosec", "cybersecurity", "threatintel"]
)
```

---

## Configuration Examples

### Complete .env File

```bash
# Threat Intelligence Platforms
CTI_MISP_URL=https://misp.company.com
CTI_MISP_API_KEY=abc123...
CTI_MISP_VERIFY_SSL=true

CTI_OPENCTI_URL=https://opencti.company.com
CTI_OPENCTI_API_KEY=xyz789...
CTI_OPENCTI_VERIFY_SSL=true

CTI_TAXII_URL=https://taxii.company.com/taxii2
CTI_TAXII_USERNAME=taxii_user
CTI_TAXII_PASSWORD=secure_pass
CTI_TAXII_VERIFY_SSL=true

# SIEM/SOAR
CTI_SENTINEL_WORKSPACE_ID=abc-123-def
CTI_SENTINEL_API_KEY=token...
CTI_SENTINEL_SUBSCRIPTION_ID=sub-123
CTI_SENTINEL_RESOURCE_GROUP=rg-security

CTI_SPLUNK_URL=https://splunk.company.com:8089
CTI_SPLUNK_TOKEN=bearer_token...
CTI_SPLUNK_VERIFY_SSL=true

CTI_ELASTIC_URL=https://elastic.company.com
CTI_ELASTIC_API_KEY=api_key...
CTI_ELASTIC_VERIFY_SSL=true

# Case Management
CTI_THEHIVE_URL=https://thehive.company.com
CTI_THEHIVE_API_KEY=hive_key...
CTI_THEHIVE_VERIFY_SSL=true

CTI_CORTEX_URL=https://cortex.company.com
CTI_CORTEX_API_KEY=cortex_key...
CTI_CORTEX_VERIFY_SSL=true

# Social Media
CTI_REDDIT_CLIENT_ID=reddit_client
CTI_REDDIT_CLIENT_SECRET=reddit_secret

CTI_TWITTER_BEARER_TOKEN=twitter_bearer...

CTI_BLUESKY_HANDLE=user.bsky.social
CTI_BLUESKY_PASSWORD=bluesky_pass

CTI_MASTODON_INSTANCE=infosec.exchange
CTI_MASTODON_TOKEN=mastodon_token...  # Optional
```

### Testing Configuration

Test each integration after configuration:

```python
# MISP
from scry.integrations.misp import MISPClient
client = MISPClient()
result = client.get_tags()
print(f"MISP: {'✓ Connected' if result.ok else '✗ Failed'}")

# OpenCTI
from scry.integrations.opencti import OpenCTIClient
client = OpenCTIClient()
result = client.get_threat_actors(limit=1)
print(f"OpenCTI: {'✓ Connected' if result.ok else '✗ Failed'}")

# TAXII
from scry.integrations.taxii import TAXII21Client
client = TAXII21Client()
result = client.get_discovery()
print(f"TAXII: {'✓ Connected' if result.ok else '✗ Failed'}")

# Sentinel
from scry.integrations.sentinel import MicrosoftSentinelClient
client = MicrosoftSentinelClient()
result = client.get_incidents(top=1)
print(f"Sentinel: {'✓ Connected' if result.ok else '✗ Failed'}")

# And so on for other integrations...
```

---

## Best Practices

1. **Rate Limiting**: All integrations include built-in rate limiters. Monitor logs for rate limit warnings.

2. **SSL Verification**: Use `VERIFY_SSL=false` only in development. Always verify SSL in production.

3. **API Keys**: Store API keys securely. Use environment variables or secret management systems.

4. **Error Handling**: All clients return Result objects with `.ok` boolean and `.error` string for robust error handling.

5. **Caching**: Many read operations are cached locally to reduce API calls. Cache is stored in `.cti_cache/`.

6. **Resource Cleanup**: Always call `.close()` on clients when done to release HTTP connections.

7. **Logging**: Enable DEBUG logging to troubleshoot integration issues:
   ```bash
   CTI_LOG_LEVEL=DEBUG
   ```

---

## Troubleshooting

### Common Issues

**Connection Errors**:
- Verify URLs are correct and reachable
- Check firewall rules and proxy settings
- Ensure SSL certificates are valid

**Authentication Errors**:
- Verify API keys/tokens are correct
- Check token expiration
- Ensure sufficient permissions

**Rate Limiting**:
- Reduce request frequency
- Upgrade to higher-tier API plans
- Use caching to minimize API calls

**Data Not Found**:
- Check query syntax
- Verify data exists in source system
- Review time filters (may exclude recent data)

---

For additional help, see the main documentation or open an issue on GitHub.
