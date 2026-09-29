# Feedly Threat Intelligence Integration

This document describes the comprehensive Feedly API integration for the CTI Enrichment Agent.

## Overview

Feedly provides dual functionality:
1. **Enricher**: Enrich existing CVEs, IOCs, threat actors, and malware with Feedly intelligence
2. **Collector**: Collect threat intelligence articles from Feedly streams and searches

## Features

### Enrichment Capabilities

The Feedly enricher (`scry/enrichment/feedly.py`) provides enrichment for:

#### CVE Enrichment
- CVE metadata (CVSS, EPSS, severity)
- Exploit availability status
- Trending CVE detection
- Affected vendors and products
- Attack vector information
- Article count and references
- Timeline of CVE mentions

**Supported CVE Types**: `cve`

#### IOC Enrichment
- Indicator metadata (first/last seen)
- Associated malware families
- Related threat actors
- Severity scoring
- Article mentions
- Tags and categorization

**Supported IOC Types**: `domain`, `ipv4`, `ipv6`, `sha256`, `sha1`, `md5`

#### Threat Actor Intelligence
- Actor profiles with aliases
- Sophistication and motivation
- Attribution (country)
- Targeted sectors and countries
- TTPs (MITRE ATT&CK)
- Malware tools used
- Activity timeline

**Supported Types**: `threat_actor`

#### Malware Intelligence
- Malware family and variants
- Type classification (ransomware, trojan, etc.)
- Associated threat actors
- Targeted sectors
- Platforms (Windows, Linux, etc.)
- Detection rules (YARA, Sigma)
- TTPs

**Supported Types**: `malware`

### Collection Capabilities

The Feedly collector (`scry/sources/feedly_collector.py`) provides:

#### Article Search
```python
from scry.sources.feedly_collector import FeedlyCollector

collector = FeedlyCollector()

# Search for ransomware articles
articles = collector.search_articles("ransomware", count=100)

# Search for specific CVE mentions
articles = collector.search_articles("CVE-2024-*", count=50)

# Search for threat actor activity
articles = collector.search_articles("APT28 OR Fancy Bear", count=100)
```

#### Stream Collection
```python
# Collect from a personal stream/category
articles, continuation = collector.get_stream_contents(
    stream_id="user/{userId}/category/Security",
    count=100
)

# Collect from a specific feed
articles, continuation = collector.get_stream_contents(
    stream_id="feed/https://example.com/feed.xml",
    count=50
)
```

#### Entity-Based Collection
```python
# Collect articles mentioning a specific CVE
articles = collector.collect_articles_by_entity(
    entity_id="CVE-2024-1234",
    entity_type="cve",
    count=50
)

# Collect articles about a threat actor
articles = collector.collect_articles_by_entity(
    entity_id="APT28",
    entity_type="threat-actor",
    count=100
)

# Collect articles about malware
articles = collector.collect_articles_by_entity(
    entity_id="lockbit",
    entity_type="malware",
    count=50
)
```

#### Trending Intelligence
```python
# Get trending CVEs
trending_cves = collector.get_trending_cves(days=7, count=20)

# Get trending threat actors
trending_actors = collector.get_trending_threat_actors(days=7, count=20)

# Get trending malware
trending_malware = collector.get_trending_malware(days=7, count=20)

# Get recent cyber attacks
attacks = collector.get_cyber_attacks(days=7)
```

## Configuration

### Authentication

Feedly uses OAuth 2.0 Bearer tokens. You need:
1. A Feedly account (Enterprise or Teams plan recommended for TI features)
2. An API token from https://feedly.com/v3/auth/dev

### Environment Variables

Add to your `.env` file:

```bash
# Required
CTI_FEEDLY_API_TOKEN=your_bearer_token_here

# Optional (for personal stream access)
CTI_FEEDLY_USER_ID=your_feedly_user_id
```

### Getting Your API Token

1. Go to https://developers.feedly.com/
2. Sign in with your Feedly account
3. Navigate to "Get Access Token"
4. Copy your developer access token
5. For production, use OAuth 2.0 flow: https://developers.feedly.com/reference/authorization

### Finding Your User ID

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.feedly.com/v3/profile
```

The response includes your `id` field.

## Usage

### Via Web UI

1. Navigate to http://localhost:8000/ui/settings/connectors
2. Find "Feedly Threat Intelligence"
3. Verify API token is configured (set in `.env`)
4. Click "Test connection" to verify
5. Enable the connector
6. Click "Run Enabled Connectors" to enrich observables

### Via Enrichment Engine

The enrichment engine automatically uses Feedly when processing:
- CVEs
- Domains, IPs, file hashes (IOCs)
- Threat actors
- Malware families

Enriched data appears in the `enrichment` JSONB field:

```sql
SELECT 
    normalized_value,
    type,
    enrichment->'feedly'->>'cvss_score' as cvss,
    enrichment->'feedly'->>'exploit_available' as has_exploit,
    enrichment->'feedly'->'malware_families' as malware
FROM observables
WHERE enrichment->'feedly' IS NOT NULL;
```

### Via Collector (Programmatic)

Create a custom ingestion script:

```python
from scry.sources.feedly_collector import FeedlyCollector
from scry.pipeline import CTIPipeline

collector = FeedlyCollector()
pipeline = CTIPipeline()

# Search and ingest
articles = collector.search_articles("ransomware healthcare", count=100)

for article in articles:
    # Pipeline automatically extracts entities, IOCs, etc.
    result = pipeline.process_article(
        url=article.url,
        title=article.title,
        content=article.content,
        published=article.published_date,
        source_name=article.source_name
    )
    
    # Feedly entities are already extracted
    print(f"CVEs: {article.entities.get('cve', [])}")
    print(f"Threat Actors: {article.entities.get('threat_actor', [])}")
    print(f"Malware: {article.entities.get('malware', [])}")
    print(f"IOCs: {len(article.indicators)} indicators")

collector.close()
```

## API Endpoints

### Enrichment Methods

All methods are on `FeedlyEnricher`:

```python
from scry.enrichment.feedly import FeedlyEnricher

enricher = FeedlyEnricher()

# Lookup single item
result = enricher.lookup("CVE-2024-1234", "cve")
result = enricher.lookup("malicious.com", "domain")
result = enricher.lookup("APT28", "threat_actor")

# Trending intelligence
trending_cves = enricher.get_trending_cves(days=7, count=20)
trending_actors = enricher.get_trending_threat_actors(days=7, count=20)
trending_malware = enricher.get_trending_malware(days=7, count=20)

# Cyber attacks
attacks = enricher.get_cyber_attacks(days=7)

# Search
results = enricher.search_articles("zero-day exploit", count=50)

enricher.close()
```

### Collection Methods

All methods are on `FeedlyCollector`:

```python
from scry.sources.feedly_collector import FeedlyCollector

collector = FeedlyCollector()

# Article search
articles = collector.search_articles(
    query="ransomware",
    count=100,
    newer_than=1704067200000  # Unix timestamp in ms
)

# Stream contents
articles, next_token = collector.get_stream_contents(
    stream_id="user/{userId}/category/Security",
    count=100,
    continuation=None
)

# Entity articles
articles = collector.collect_articles_by_entity(
    entity_id="CVE-2024-1234",
    entity_type="cve",
    count=50
)

# Trending
trending = collector.get_trending_articles(
    entity_type="cve",  # or 'threat_actor', 'malware', 'all'
    days=7,
    count=50
)

collector.close()
```

## Rate Limits

Feedly API limits (as of API documentation review):
- **Most endpoints**: 250 requests/minute
- **Search endpoint**: 100 requests/minute
- **Enterprise plans**: Higher limits available

The connector implements automatic rate limiting and respects Feedly's limits.

## Response Caching

All enrichment responses are cached in `.cti_cache/feedly/` organized by type:
- `.cti_cache/feedly/cve/`
- `.cti_cache/feedly/domain/`
- `.cti_cache/feedly/threat_actor/`
- `.cti_cache/feedly/malware/`

Cache prevents re-querying the API for the same entity.

## Entity Extraction

Feedly automatically extracts entities from articles using their LEO (Language Entity Ontology):

### Extracted Entity Types
- **CVEs**: All CVE IDs mentioned
- **Threat Actors**: APT groups, nation-state actors
- **Malware**: Families, variants, campaigns
- **TTPs**: MITRE ATT&CK techniques
- **Vulnerabilities**: Software vulnerabilities
- **IOCs**: Domains, IPs, hashes, URLs

### Example Article Structure

```python
article = FeedlyArticle(
    id="feedly_article_id",
    title="LockBit Ransomware Exploits CVE-2024-1234",
    url="https://example.com/article",
    content="Full article text...",
    summary="Brief summary...",
    published_date="2024-05-24T12:00:00Z",
    author="Security Researcher",
    source_name="Security Blog",
    source_url="https://example.com",
    tags=["ransomware", "apt", "critical"],
    entities={
        "cve": ["CVE-2024-1234"],
        "malware": ["lockbit", "ransomware"],
        "threat_actor": ["lockbit_group"],
        "ttp": ["T1486", "T1490"],
    },
    indicators=[
        {"type": "domain", "value": "malicious.com", "mentions": 3},
        {"type": "ip", "value": "1.2.3.4", "mentions": 2},
    ],
    raw={...}  # Full Feedly JSON
)
```

## Integration with Existing Pipelines

### Automatic Enrichment

When observables or CVEs are ingested, the enrichment engine automatically calls Feedly:

```python
from scry.enrichment import EnrichmentEngine

engine = EnrichmentEngine()

# This automatically uses Feedly if enabled
result = engine.enrich_observable(
    value="CVE-2024-1234",
    ob_type="cve"
)

# Feedly data in result
print(result.fields.get("feedly"))
```

### Article Ingestion Workflow

1. Collector fetches articles from Feedly
2. Articles are normalized to `FeedlyArticle` format
3. Entities and IOCs are pre-extracted by Feedly
4. Pipeline ingests article and creates:
   - `Article` record
   - `Observable` records for IOCs
   - `Entity` records for threat actors/malware
   - `CVE` records
   - `Relationship` records between entities

## Advanced Use Cases

### Daily CVE Monitoring

```python
from scry.enrichment.feedly import FeedlyEnricher

enricher = FeedlyEnricher()

# Get trending CVEs from last 24 hours
trending = enricher.get_trending_cves(days=1, count=50)

for cve_entry in trending:
    cve_id = cve_entry.get("cveId")
    
    # Get full CVE insights
    result = enricher.lookup(cve_id, "cve")
    
    if result.fields.get("exploit_available"):
        print(f"⚠️  {cve_id} has exploit available!")
        print(f"CVSS: {result.fields.get('cvss_score')}")
        print(f"Articles: {result.fields.get('article_count')}")

enricher.close()
```

### Threat Actor Tracking

```python
from scry.sources.feedly_collector import FeedlyCollector

collector = FeedlyCollector()

# Track specific threat actor
actor = "APT28"
articles = collector.collect_articles_by_entity(
    entity_id=actor,
    entity_type="threat-actor",
    count=100
)

print(f"Found {len(articles)} articles about {actor}")

for article in articles:
    print(f"- {article.title}")
    print(f"  TTPs: {article.entities.get('ttp', [])}")
    print(f"  Malware: {article.entities.get('malware', [])}")
    print(f"  IOCs: {len(article.indicators)}")

collector.close()
```

### Ransomware Intelligence

```python
collector = FeedlyCollector()

# Get trending malware
trending = collector.get_trending_malware(days=7, count=20)

for malware_entry in trending:
    malware_id = malware_entry.get("malwareId")
    
    # Collect recent articles
    articles = collector.collect_articles_by_entity(
        entity_id=malware_id,
        entity_type="malware",
        count=20
    )
    
    # Extract all IOCs from articles
    all_iocs = []
    for article in articles:
        all_iocs.extend(article.indicators)
    
    print(f"{malware_id}: {len(all_iocs)} IOCs from {len(articles)} articles")

collector.close()
```

## Troubleshooting

### "Feedly API token not configured"
- Ensure `CTI_FEEDLY_API_TOKEN` is set in `.env`
- Restart the application after setting environment variables
- Verify token with: `curl -H "Authorization: Bearer YOUR_TOKEN" https://api.feedly.com/v3/profile`

### "Rate limit (429)"
- Feedly enforces 250 req/min for most endpoints
- The connector automatically rate limits, but parallel processes may exceed limits
- Consider upgrading to Feedly Enterprise for higher limits

### "HTTP 401 Unauthorized"
- Token is invalid or expired
- Generate a new token at https://feedly.com/v3/auth/dev
- For production, implement OAuth refresh flow

### "Not found (404)"
- Entity doesn't exist in Feedly's database
- CVE might be too new or not yet tracked
- Try alternative entity identifiers (aliases)

### Entity Mapping Issues
- Feedly uses specific entity IDs (lowercase, normalized)
- Try variations: "APT28" vs "apt28" vs "Fancy Bear"
- Use entity lookup endpoint to find canonical ID

## API Documentation

Full Feedly API documentation:
- Introduction: https://developers.feedly.com/reference/introduction
- Authorization: https://developers.feedly.com/reference/authorization
- Building TI Integration: https://developers.feedly.com/reference/building-your-first-ti-integration
- CVE Insights: https://developers.feedly.com/reference/cve-json
- Threat Actors: https://developers.feedly.com/reference/threat-actor-insight-card-json
- Malware: https://developers.feedly.com/reference/malware-insight-card-json
- IOCs: https://developers.feedly.com/reference/collect-iocs
- Search: https://developers.feedly.com/reference/search

## Best Practices

1. **Cache Aggressively**: Feedly data is expensive (API quota), cache locally
2. **Batch Operations**: Collect multiple articles in single API calls
3. **Entity Normalization**: Feedly uses specific entity IDs, maintain mapping table
4. **Rate Limit Awareness**: Stay under 250 req/min
5. **Token Security**: Never commit API tokens, use environment variables
6. **Pagination**: Use continuation tokens for large result sets
7. **Time Filtering**: Use `newer_than` to avoid re-fetching old articles
8. **Error Handling**: Handle 404s gracefully (entity not found is normal)

## Future Enhancements

Potential additions:
- Feedly AI Actions (experimental)
- Real-time webhooks for new articles
- Personal stream integration
- Team board synchronization
- Custom entity training
- Bulk IOC enrichment endpoint
- STIX export from Feedly data
