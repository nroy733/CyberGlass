//! # Local AI Provider
//!
//! Offline AI provider for cyberglass environments. Uses pattern matching
//! to generate CyberQL queries and threat analysis without external dependencies.

use crate::error::AiError;
use crate::model::{ChatResponse, TokenUsage};
use crate::vendor::{AIProvider, ChatRequest};
use tracing::debug;

/// Local (offline) AI model provider.
pub struct LocalModelProvider {
    pub model_name: String,
    pub context_size: usize,
}

impl LocalModelProvider {
    pub fn new() -> Self {
        Self {
            model_name: "phi-4-mini-q4".to_string(),
            context_size: 4096,
        }
    }

    /// Chat with the local provider using pattern-based responses.
    pub async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, AiError> {
        let user_message = request
            .messages
            .iter()
            .find(|m| matches!(m.role, crate::vendor::ChatRole::User))
            .map(|m| m.content.to_lowercase())
            .unwrap_or_default();

        debug!("Local AI processing: {}", user_message);

        let response = if user_message.contains("brute force") || user_message.contains("t1110") {
            self.brute_force_response()
        } else if user_message.contains("privilege escalation") {
            self.privilege_escalation_response()
        } else if user_message.contains("powershell") || user_message.contains("encoded") {
            self.powershell_response()
        } else if user_message.contains("firewall") || user_message.contains("blocked") {
            self.firewall_response()
        } else if user_message.contains("cyberql") || user_message.contains("query") {
            self.cyberql_help_response(&user_message)
        } else {
            self.general_response(&user_message)
        };

        Ok(ChatResponse {
            content: response,
            usage: TokenUsage::default(),
            provider: "Local".to_string(),
            model: self.model_name.clone(),
        })
    }

    fn brute_force_response(&self) -> String {
        r#"To detect brute force attacks in CyberQL, use this query:

```cyberql
source="windows_security" EventID=4625 | stats count by TargetUserName, IpAddress | where count > 5 | sort -count
```

This detects:
- Multiple failed logon attempts (EventID 4625)
- Groups by target username and source IP
- Alerts when more than 5 failures occur
- Sorts by highest count

MITRE ATT&CK: T1110 (Brute Force)"#.to_string()
    }

    fn privilege_escalation_response(&self) -> String {
        r#"To detect privilege escalation in CyberQL:

```cyberql
source="windows_security" EventID=4672 | stats count by TargetUserName, IpAddress | sort -count
```

Or for suspicious process execution:

```cyberql
source="endpoint" Image="*powershell.exe" CommandLine="*-enc*" | stats count by User, Host
```

MITRE ATT&CK: T1068, T1078 (Privilege Escalation)"#
            .to_string()
    }

    fn powershell_response(&self) -> String {
        r#"To detect suspicious PowerShell in CyberQL:

```cyberql
source="endpoint" Image="*powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-e*") | stats count by User, Host, CommandLine
```

This detects:
- Encoded PowerShell commands (-enc flag)
- Suspicious PowerShell execution
- Groups by user and host

MITRE ATT&CK: T1059.001 (PowerShell)"#.to_string()
    }

    fn firewall_response(&self) -> String {
        r#"To analyze blocked firewall traffic in CyberQL:

```cyberql
source="firewall" action="blocked" | stats count by src_ip, dest_ip, app | sort -count
```

Or for recent blocked traffic:

```cyberql
source="firewall" action="blocked" | head 100 | table _time, src_ip, dest_ip, app, bytes
```

MITRE ATT&CK: T1041 (Exfiltration), T1071 (Application Layer Protocol)"#
            .to_string()
    }

    fn cyberql_help_response(&self, query: &str) -> String {
        format!(
            r#"CyberQL Query Help

You asked about: "{}"

CyberQL is a pipeline-based query language. Common commands:

- `source="index"` - Filter by source index
- `where <condition>` - Filter events
- `stats count by <field>` - Aggregate statistics
- `sort -<field>` - Sort descending
- `head <N>` - Limit results
- `dedup <field>` - Remove duplicates
- `table <fields>` - Display as table
- `eval <field> = <expression>` - Calculate fields

Example: source="firewall" action=blocked | stats count by src_ip | sort -count

Would you like me to generate a specific query for your use case?"#,
            query
        )
    }

    fn general_response(&self, query: &str) -> String {
        format!(
            r#"CyberGlass AI Threat Hunter

I received your query: "{}"

I'm running in local offline mode. I can help you with:
- Writing CyberQL queries
- Explaining MITRE ATT&CK techniques
- Analyzing security events
- Creating detection rules

Try asking:
- "How do I detect brute force attacks?"
- "How do I detect privilege escalation?"
- "Find blocked firewall traffic"
- "How to detect suspicious PowerShell?"

For advanced AI features, configure a remote provider (OpenAI, Anthropic, Google, OpenRouter) in Settings."#,
            query
        )
    }
}

impl Default for LocalModelProvider {
    fn default() -> Self {
        Self::new()
    }
}
