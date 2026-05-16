"""o
Central configuration for MCP Host
AI-native SOAR System
"""

#################################################
# WAZUH CONFIG
#################################################

WAZUH_INDEXER_URL = "https://172.30.0.11:9200"
WAZUH_USERNAME = "admin"
WAZUH_PASSWORD = "SecretPassword"

WAZUH_ALERT_MIN_LEVEL = 5

#################################################
# POLLING CONFIG
#################################################

POLL_INTERVAL = 10

#################################################
# MCP SERVER ENDPOINTS
#################################################

COLLECTOR_SERVER_URL = "http://collector_server:8000"

TRANSLATOR_SERVER_URL = "http://translator_server:8000"

CORRELATOR_SERVER_URL = "http://correlator_server:8000"

REASONING_SERVER_URL = "http://reasoning_server:8000"

RESPONSE_SERVER_URL = "http://response_server:8000"

#################################################
# CLAUDE API CONFIG
#################################################

CLAUDE_API_KEY = "your_claude_api_key_here"

CLAUDE_MODEL = "claude-3-5-sonnet-20241022"

#################################################
# TELEGRAM ALERT CONFIG
#################################################

TELEGRAM_BOT_TOKEN = "your_telegram_bot_token"

TELEGRAM_CHAT_ID = "your_telegram_chat_id"

#################################################
# SANDBOX CONFIG
#################################################

MAX_SANDBOX_RETRY = 5

AUTO_RESPONSE_CONFIDENCE_THRESHOLD = 0.95

#################################################
# INCIDENT POLICY
#################################################

ENABLE_AUTO_BLOCK_IP = True

ENABLE_AUTO_ISOLATE_CONTAINER = False

REQUIRE_ADMIN_APPROVAL_FOR_CRITICAL = True
