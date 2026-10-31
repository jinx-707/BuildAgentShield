package agentshield.execution

import future.keywords.if
import future.keywords.in

default deny_policy := "opa.deny"

default decision := {
  "decision": "DENY",
  "reason": "Default deny: no OPA rule matched.",
  "policy_id": "opa.default_deny"
}

tools := {
  "read_document", "read_file", "read_system_file", "read_env_var",
  "run_command", "delete_file", "browse_url", "send_email", "export_data",
  "download_file", "initiate_payment", "call_external_api", "mcp_call",
}

decision := {
  "decision": "DENY",
  "reason": reason,
  "policy_id": policy_id,
} if {
  reason := deny_reason
  policy_id := deny_policy
}

decision := {
  "decision": "REQUIRE_APPROVAL",
  "reason": reason,
  "policy_id": "opa.requires_approval",
} if {
  not deny_reason
  reason := approval_reason
}

decision := {
  "decision": "REDACT",
  "reason": "Sensitive export requires redaction.",
  "policy_id": "opa.redact",
} if {
  not deny_reason
  not approval_reason
  input.local_decision == "REDACT"
}

decision := {
  "decision": "ALLOW",
  "reason": "OPA policy allowed the request.",
  "policy_id": "opa.allow",
} if {
  not deny_reason
  not approval_reason
  input.local_decision != "REDACT"
  input.local_decision != "DENY"
  input.local_decision != "QUARANTINE"
}

deny_reasons contains "Tool is not registered." if {
  not input.tool.name in tools
}

deny_reasons contains reason if {
  input.tool.name in tools
  reason := permission_reason
  reason != ""
}

deny_reasons contains "Critical inspection finding." if {
  some finding in input.findings
  finding.severity == "critical"
}

deny_reasons contains "Path traversal detected." if {
  some finding in input.findings
  finding.code == "path_traversal"
}

deny_reasons contains "Destructive command detected." if {
  some finding in input.findings
  finding.code == "destructive_command"
}

deny_reasons contains "Destination host is not allowlisted." if {
  input.tool.name in {"browse_url", "download_file", "call_external_api"}
  host := request_host
  not host_allowed(host)
}

deny_reasons contains "Payment exceeds the agent budget." if {
  input.tool.name == "initiate_payment"
  amount := to_number(input.arguments.amount)
  budget := to_number(object.get(input.principal.scopes, "payment_budget", 0))
  amount > budget
}

deny_reasons contains "Merchant is not allowlisted." if {
  input.tool.name == "initiate_payment"
  merchant := object.get(input.arguments, "merchant", "")
  merchants := object.get(input.principal.scopes, "allowed_merchants", [])
  not merchant in merchants
}

deny_reasons contains "MCP server is not allowlisted." if {
  input.tool.name == "mcp_call"
  server := object.get(input.arguments, "server", "")
  servers := object.get(input.principal.scopes, "allowed_servers", [])
  not server in servers
}

deny_reasons contains "Environment variable is not explicitly scoped." if {
  input.tool.name == "read_env_var"
  name := object.get(input.arguments, "name", "")
  allowed := object.get(input.principal.scopes, "allowed_env", [])
  not name in allowed
}

deny_reasons contains "Protected system file is not explicitly scoped." if {
  input.tool.name == "read_system_file"
  path := object.get(input.arguments, "path", "")
  allowed := object.get(input.principal.scopes, "allowed_system_paths", [])
  not path in allowed
}

deny_reasons contains "File path is outside the workspace scope." if {
  input.tool.name in {"read_file", "delete_file"}
  path := object.get(input.arguments, "path", "")
  not path_allowed(path)
}

deny_reason := reason if {
  some reason in deny_reasons
  reason := reason
}

deny_policy := "opa.registry" if {
  not input.tool.name in tools
}

deny_policy := "opa.rbac" if {
  input.tool.name in tools
  permission_reason != ""
}

deny_policy := "opa.inspection" if {
  some finding in input.findings
  finding.severity == "critical"
}

deny_policy := "opa.abac" if {
  deny_reason == "Destination host is not allowlisted."
}

deny_policy := "opa.financial" if {
  deny_reason == "Payment exceeds the agent budget."
}

deny_policy := "opa.financial" if {
  deny_reason == "Merchant is not allowlisted."
}

deny_policy := "opa.scope" if {
  deny_reason == "Environment variable is not explicitly scoped."
}

deny_policy := "opa.scope" if {
  deny_reason == "Protected system file is not explicitly scoped."
}

deny_policy := "opa.scope" if {
  deny_reason == "File path is outside the workspace scope."
}

permission_reason := reason if {
  permission := input.tool.permission
  not permission in input.principal.permissions
  reason := sprintf("Agent lacks permission %s.", [permission])
}

permission_reason := "" if {
  input.tool.permission in input.principal.permissions
}

approval_reason := reason if {
  input.tool.requires_approval
  reason := "Tool requires exact-action human approval."
}

approval_reason := reason if {
  input.tool.supports_egress
  input.local_decision == "REQUIRE_APPROVAL"
  reason := "External integration requires human approval."
}

request_host := host if {
  raw := object.get(input.arguments, "url", object.get(input.arguments, "endpoint", ""))
  host := lower(split_url_host(raw))
}

split_url_host(raw) := host if {
  parts := split(raw, "/")
  count(parts) > 2
  authority := parts[2]
  host := split(authority, ":")[0]
}

split_url_host(_) := ""

host_allowed(host) if {
  allowed := object.get(input.principal.scopes, "allowed_domains", [])
  some domain in allowed
  host == lower(domain)
}

host_allowed(host) if {
  allowed := object.get(input.principal.scopes, "allowed_domains", [])
  some domain in allowed
  endswith(host, concat(".", [lower(domain)]))
}

path_allowed(path) if {
  normalized := trim_prefix(replace(path, "\\", "/"), "./")
  not contains(normalized, "..")
  allowed := object.get(input.principal.scopes, "allowed_paths", [])
  some item in allowed
  scope := trim(item, "/")
  normalized == scope
}

path_allowed(path) if {
  normalized := trim_prefix(replace(path, "\\", "/"), "./")
  not contains(normalized, "..")
  allowed := object.get(input.principal.scopes, "allowed_paths", [])
  some item in allowed
  scope := trim(item, "/")
  startswith(normalized, concat("/", [scope, ""]))
}
