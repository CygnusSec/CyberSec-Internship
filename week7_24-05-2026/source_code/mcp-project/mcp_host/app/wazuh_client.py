import httpx
from datetime import datetime, timezone, timedelta


class WazuhClient:

    def __init__(self):
        self.indexer_url = "https://172.30.0.11:9200"
        self.username = "admin"
        self.password = "SecretPassword"

    async def get_latest_alert(self):
        # Chỉ lấy alert trong 5 phút gần nhất
        since = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

        query = {
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": 5}}},
                        {"range": {"@timestamp": {"gte": since}}}
                    ]
                }
            }
        }

        try:
            async with httpx.AsyncClient(verify=False, timeout=20) as client:
                response = await client.post(
                    f"{self.indexer_url}/wazuh-alerts-*/_search",
                    auth=(self.username, self.password),
                    json=query
                )

                if response.status_code != 200:
                    return None

                hits = response.json().get("hits", {}).get("hits", [])
                if not hits:
                    return None

                hit = hits[0]
                source = hit["_source"]
                source["id"] = hit.get("_id", source.get("@timestamp", "unknown"))
                return source

        except Exception as e:
            print(f"[WAZUH ERROR] {e}", flush=True)
            return None
