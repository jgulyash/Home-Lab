"""
MISP Integration Client

Connect to MISP (Malware Information Sharing Platform) for threat intelligence.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MISPClient:
    """
    Client for MISP API integration

    MISP is the industry-standard threat intelligence sharing platform.
    """

    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None, verify_ssl: bool = False):
        self.url = url or os.getenv('MISP_URL', 'https://localhost:8443')
        self.api_key = api_key or os.getenv('MISP_API_KEY')
        self.verify_ssl = verify_ssl

        self.headers = {
            'Authorization': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        logger.info(f"MISP Client initialized (URL: {self.url})")

    def test_connection(self) -> bool:
        """Test connection to MISP"""
        try:
            response = requests.get(
                f"{self.url}/servers/getVersion",
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            logger.info("MISP connection successful")
            return True
        except Exception as e:
            logger.error(f"MISP connection failed: {e}")
            return False

    def search_attributes(
        self,
        value: Optional[str] = None,
        type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        last: Optional[str] = "1d"
    ) -> List[Dict[str, Any]]:
        """
        Search for attributes (IOCs) in MISP

        Args:
            value: Attribute value to search for
            type: Attribute type (ip-src, domain, md5, etc.)
            tags: List of tags to filter by
            last: Time period (e.g., '1d', '7d', '30d')

        Returns:
            List of matching attributes
        """
        try:
            payload = {
                "returnFormat": "json",
                "last": last
            }

            if value:
                payload["value"] = value
            if type:
                payload["type"] = type
            if tags:
                payload["tags"] = tags

            response = requests.post(
                f"{self.url}/attributes/restSearch",
                headers=self.headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            attributes = data.get('response', {}).get('Attribute', [])

            logger.info(f"Found {len(attributes)} attributes in MISP")
            return attributes

        except Exception as e:
            logger.error(f"MISP attribute search failed: {e}")
            return []

    def search_events(
        self,
        tags: Optional[List[str]] = None,
        last: Optional[str] = "7d",
        published: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Search for events in MISP

        Args:
            tags: Filter by tags
            last: Time period
            published: Only published events

        Returns:
            List of matching events
        """
        try:
            payload = {
                "returnFormat": "json",
                "last": last,
                "published": published
            }

            if tags:
                payload["tags"] = tags

            response = requests.post(
                f"{self.url}/events/restSearch",
                headers=self.headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            events = data.get('response', [])

            logger.info(f"Found {len(events)} events in MISP")
            return events

        except Exception as e:
            logger.error(f"MISP event search failed: {e}")
            return []

    def add_attribute(
        self,
        event_id: str,
        attribute_type: str,
        value: str,
        category: str = "Network activity",
        to_ids: bool = True,
        comment: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        Add an attribute (IOC) to MISP event

        Args:
            event_id: MISP event ID
            attribute_type: Type (ip-src, domain, md5, etc.)
            value: Attribute value
            category: Category
            to_ids: Mark for IDS signatures
            comment: Optional comment

        Returns:
            Created attribute or None
        """
        try:
            payload = {
                "type": attribute_type,
                "value": value,
                "category": category,
                "to_ids": to_ids,
                "comment": comment
            }

            response = requests.post(
                f"{self.url}/attributes/add/{event_id}",
                headers=self.headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()
            logger.info(f"Added attribute to MISP event {event_id}: {value}")
            return result.get('Attribute')

        except Exception as e:
            logger.error(f"Failed to add attribute to MISP: {e}")
            return None

    def create_event(
        self,
        info: str,
        threat_level_id: int = 2,  # Medium
        analysis: int = 1,  # Ongoing
        distribution: int = 1,  # This community only
        tags: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Create a new event in MISP

        Args:
            info: Event description
            threat_level_id: 1=High, 2=Medium, 3=Low
            analysis: 0=Initial, 1=Ongoing, 2=Complete
            distribution: 0=Org only, 1=Community, 2=Connected, 3=All
            tags: List of tags

        Returns:
            Created event or None
        """
        try:
            payload = {
                "info": info,
                "threat_level_id": threat_level_id,
                "analysis": analysis,
                "distribution": distribution,
                "published": False
            }

            response = requests.post(
                f"{self.url}/events/add",
                headers=self.headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()
            event = result.get('Event')

            if event and tags:
                event_id = event.get('id')
                for tag in tags:
                    self.add_tag(event_id, tag)

            logger.info(f"Created MISP event: {info}")
            return event

        except Exception as e:
            logger.error(f"Failed to create MISP event: {e}")
            return None

    def add_tag(self, event_id: str, tag: str) -> bool:
        """Add tag to event"""
        try:
            response = requests.post(
                f"{self.url}/tags/attachTagToObject",
                headers=self.headers,
                json={"uuid": event_id, "tag": tag},
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to add tag: {e}")
            return False

    def sync_iocs_to_firewall(self, ioc_type: str = "ip-src") -> List[str]:
        """
        Get IOCs from MISP for firewall blocking

        Args:
            ioc_type: Type of IOC (ip-src, domain, etc.)

        Returns:
            List of IOC values to block
        """
        attributes = self.search_attributes(
            type=ioc_type,
            last="7d"
        )

        iocs = []
        for attr in attributes:
            if attr.get('to_ids'):  # Only actionable IOCs
                iocs.append(attr.get('value'))

        logger.info(f"Retrieved {len(iocs)} {ioc_type} IOCs from MISP")
        return iocs

    def enrich_ioc(self, value: str) -> Dict[str, Any]:
        """
        Enrich an IOC with MISP data

        Args:
            value: IOC value to enrich

        Returns:
            Enrichment data
        """
        attributes = self.search_attributes(value=value)

        enrichment = {
            'value': value,
            'found_in_misp': len(attributes) > 0,
            'occurrences': len(attributes),
            'events': [],
            'tags': set(),
            'threat_actors': set(),
            'first_seen': None,
            'last_seen': None
        }

        for attr in attributes:
            event_info = attr.get('Event', {}).get('info', '')
            enrichment['events'].append(event_info)

            # Collect tags
            for tag in attr.get('Tag', []):
                enrichment['tags'].add(tag.get('name'))

            # Track timestamps
            timestamp = attr.get('timestamp')
            if timestamp:
                if not enrichment['first_seen'] or timestamp < enrichment['first_seen']:
                    enrichment['first_seen'] = timestamp
                if not enrichment['last_seen'] or timestamp > enrichment['last_seen']:
                    enrichment['last_seen'] = timestamp

        enrichment['tags'] = list(enrichment['tags'])
        enrichment['threat_actors'] = list(enrichment['threat_actors'])

        return enrichment


def sync_misp_to_lab() -> Dict[str, Any]:
    """
    Sync IOCs from MISP to lab environment

    This function can be called periodically to update
    firewall rules and detection systems with latest IOCs.
    """
    client = MISPClient()

    if not client.test_connection():
        return {'status': 'error', 'message': 'MISP not available'}

    results = {
        'status': 'success',
        'timestamp': datetime.now().isoformat(),
        'iocs_synced': {}
    }

    # Sync different IOC types
    ioc_types = ['ip-src', 'ip-dst', 'domain', 'url', 'md5', 'sha256']

    for ioc_type in ioc_types:
        iocs = client.sync_iocs_to_firewall(ioc_type)
        results['iocs_synced'][ioc_type] = len(iocs)

        # In production, update firewall/IDS with these IOCs
        logger.info(f"Synced {len(iocs)} {ioc_type} IOCs")

    return results


if __name__ == "__main__":
    # Test MISP connection
    client = MISPClient()

    if client.test_connection():
        print("✅ MISP connection successful")

        # Test search
        events = client.search_events(last="1d")
        print(f"Found {len(events)} events in last 24 hours")

        # Sync IOCs
        result = sync_misp_to_lab()
        print(f"\nIOC Sync Results:")
        print(json.dumps(result, indent=2))
    else:
        print("❌ MISP connection failed")
        print("Make sure MISP is running and MISP_URL/MISP_API_KEY are set")
