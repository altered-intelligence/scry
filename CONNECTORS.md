# Third-Party Connectors

This document describes the available third-party enrichment connectors for Scry.

## Implemented Connectors

### IP/Domain Enrichment

#### GreyNoise
- **Purpose**: Distinguish noisy internet scanners from targeted infrastructure
- **API Key**: Set `CTI_GREYNOISE_API_KEY` environment variable
- **Supported Types**: IPv4, IPv6
- **Rate Limit**: 60 requests/minute (free tier)
- **Documentation**: https://docs.greynoise.io/

#### urlscan.io
- **Purpose**: URL/domain enrichment with screenshots, redirects, infrastructure pivots
- **API Key**: Set `CTI_URLSCAN_API_KEY` environment variable
- **Supported Types**: URL, Domain
- **Rate Limit**: ~100 requests/minute (public tier)
- **Documentation**: https://urlscan.io/docs/api/

#### AbuseIPDB
- **Purpose**: IP abuse scoring and community reports (can be noisy, use carefully)
- **API Key**: Set `CTI_ABUSEIPDB_API_KEY` environment variable
- **Supported Types**: IPv4, IPv6
- **Rate Limit**: 1000 requests/day (free tier)
- **Documentation**: https://docs.abuseipdb.com/

#### FortiGuard Labs (IOC Research API)
- **Purpose**: Verdicts, categories, confidence, related indicators, and outbreak intel from FortiGuard Labs — the widest-coverage provider Scry ships (domains, URLs, IPs, hashes, emails, onions-as-URLs)
- **API Key**: Set `CTI_FORTIGUARD_API_KEY` environment variable, or enter it on the Intel Feeds → Enrichment Providers page (Fernet-encrypted, DB-stored, masked)
- **Supported Types**: Domain, URL, IPv4, IPv6, MD5, SHA1, SHA256, email, onion
- **Rate Limit**: Research API — Scry paces at 2 req/s (`CTI_FORTIGUARD_RATE_PER_SEC`); 429 = quota exhausted
- **Refresh TTL**: 7 days (`CTI_ENRICHMENT_REFRESH_DAYS_FORTIGUARD`)
- **CLI**: `scry fortiguard search|related|visits|submit|outbreak-tags|test|…` (17 subcommands — full API v1.6 surface)
- **Documentation**: FortiGuard IOC Research API guide (v1.6)

### Infrastructure Discovery

#### Censys
- **Purpose**: Infrastructure pivoting with certificates, services, exposed hosts
- **Credentials**: 
  - Set `CTI_CENSYS_API_ID` environment variable
  - Set `CTI_CENSYS_API_SECRET` environment variable
- **Supported Types**: IPv4, Domain
- **Rate Limit**: 0.4 requests/second (120/5min, free tier)
- **Documentation**: https://search.censys.io/api

#### Shodan
- **Purpose**: Infrastructure pivoting with exposed services, certificates, vulnerabilities
- **API Key**: Set `CTI_SHODAN_API_KEY` environment variable
- **Supported Types**: IPv4, Domain
- **Rate Limit**: 1 request/second (free tier)
- **Documentation**: https://developer.shodan.io/api

### Threat Intelligence Platform

#### Feedly Threat Intelligence
- **Purpose**: CVE insights, threat actor intelligence, malware tracking, IOC enrichment, article collection
- **API Token**: Set `CTI_FEEDLY_API_TOKEN` environment variable
- **Supported Types**: CVE, Domain, IPv4, IPv6, SHA256, SHA1, MD5, Threat Actor, Malware
- **Rate Limit**: 250 requests/minute (most endpoints)
- **Documentation**: https://developers.feedly.com/
- **Dual Mode**: Acts as both enricher (for observables/CVEs) and collector (for articles)
- **Features**:
  - CVE trending and exploit intelligence
  - Threat actor profiles with TTPs
  - Malware family tracking and detection rules
  - IOC enrichment with context
  - Article search and stream collection
  - Cyber attack tracking
- **See**: [docs/archive/FEEDLY_INTEGRATION.md](./docs/archive/FEEDLY_INTEGRATION.md) for comprehensive documentation

## Planned Connectors

The following connectors are planned for future implementation:

### CVE Enrichment
- **EPSS**: Exploitation probability scores
- **NVD**: National Vulnerability Database metadata
- **GitHub Advisories**: Open-source package advisories

### Threat Intelligence Platforms
- **MISP**: Import/export events, attributes, tags, sightings
- **OpenCTI**: STIX 2.1 import/export
- **TAXII 2.1**: Client for STIX object collections

### SIEM/SOAR Integration
- **Microsoft Sentinel**: Push validated indicators and STIX objects
- **Splunk Enterprise Security**: Export high-confidence indicators
- **Elastic Security**: Push STIX indicators or maintain threat-intel index

### Case Management
- **TheHive + Cortex**: Create cases/alerts and run analyzers

### Social Media Collectors
- **Reddit**: Public/OAuth API for early-warning
- **X/Twitter**: Search API for threat intelligence
- **Bluesky**: searchPosts API
- **Mastodon**: Search endpoints

## Configuration

All connectors are configured via environment variables. You can set them in your `.env` file:

```bash
# IP/Domain Enrichment
CTI_GREYNOISE_API_KEY=your_key_here
CTI_URLSCAN_API_KEY=your_key_here
CTI_ABUSEIPDB_API_KEY=your_key_here

# Infrastructure Discovery
CTI_CENSYS_API_ID=your_id_here
CTI_CENSYS_API_SECRET=your_secret_here
CTI_SHODAN_API_KEY=your_key_here

# CVE Enrichment (planned)
CTI_NVD_API_KEY=your_key_here  # Optional, increases rate limit
CTI_GITHUB_TOKEN=your_token_here

# Threat Intelligence Platforms (planned)
CTI_MISP_API_KEY=your_key_here
CTI_OPENCTI_API_KEY=your_key_here
CTI_TAXII_USERNAME=your_username
CTI_TAXII_PASSWORD=your_password
CTI_TAXII_COLLECTION_URL=https://your.taxii.server/collections/...

# SIEM/SOAR (planned)
CTI_SENTINEL_WORKSPACE_ID=your_workspace_id
CTI_SENTINEL_API_KEY=your_key_here
CTI_SPLUNK_URL=https://your.splunk.instance
CTI_SPLUNK_TOKEN=your_token_here
CTI_ELASTIC_URL=https://your.elastic.instance
CTI_ELASTIC_API_KEY=your_key_here

# Case Management (planned)
CTI_THEHIVE_URL=https://your.thehive.instance
CTI_THEHIVE_API_KEY=your_key_here
CTI_CORTEX_URL=https://your.cortex.instance
CTI_CORTEX_API_KEY=your_key_here

# Social Media (planned)
CTI_REDDIT_CLIENT_ID=your_client_id
CTI_REDDIT_CLIENT_SECRET=your_secret
CTI_TWITTER_BEARER_TOKEN=your_token
CTI_BLUESKY_HANDLE=your.handle
CTI_BLUESKY_PASSWORD=your_password
CTI_MASTODON_INSTANCE=https://mastodon.social
CTI_MASTODON_TOKEN=your_token

# Feedly Threat Intelligence
CTI_FEEDLY_API_TOKEN=your_bearer_token
CTI_FEEDLY_USER_ID=your_user_id  # Optional
```

## Usage

### Via Web UI

1. Navigate to http://localhost:8000/ui/settings/connectors
2. Each connector shows:
   - Configuration status (API key set or missing)
   - Connection test status
   - Number of observables checked vs. total supported
3. Enable/disable connectors with the toggle switch
4. Click "Test connection" to verify API credentials
5. Click "Run Enabled Connectors" to enrich all unchecked observables

### Via CLI

```bash
# Run enrichment for all enabled connectors
scry enrich

# Check connector status
scry connectors list
```

## Best Practices

1. **Rate Limiting**: All connectors implement rate limiting based on their API tier
2. **Caching**: Responses are cached locally in `.cti_cache/<provider>/` to avoid re-querying
3. **Graceful Degradation**: If a connector fails, enrichment continues with other providers
4. **Progressive Enrichment**: Connectors only process unchecked observables
5. **Test First**: Always test connector configuration before enabling for production use

## Troubleshooting

### Common Issues

**"API key not configured"**
- Ensure the environment variable is set correctly in your `.env` file
- Restart the application after updating environment variables

**"Rate limit (429)"**
- The connector has hit its API rate limit
- Wait for the rate limit window to reset
- Consider upgrading to a higher API tier

**"Connection error"**
- Check your network connectivity
- Verify the API endpoint is accessible
- Check if the service is experiencing an outage

**"Not found (404)"**
- The observable was not found in the service's database
- This is normal and indicates the service has no data for that indicator

### Viewing Enrichment Results

Enriched data is stored in the `enrichment` JSONB field of the `observables` table:

```sql
SELECT 
    normalized_value,
    type,
    enrichment->'greynoise' as greynoise_data,
    enrichment->'urlscan' as urlscan_data
FROM observables
WHERE enrichment IS NOT NULL;
```

Or via the Web UI at http://localhost:8000/ui/observables/

## Contributing

To add a new connector:

1. Create a new enricher class in `scry/enrichment/<provider>.py`
2. Inherit from `BaseEnricher` and implement `enrich()` and `lookup()` methods
3. Add API key configuration to `scry/config.py`
4. Register the connector in `CONNECTOR_META` in `scry/api/router.py`
5. Update this documentation

See existing enrichers (e.g., `greynoise.py`, `urlscan.py`) for implementation patterns.
