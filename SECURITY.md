# Security

This is an early-stage local utility for a single OS user. Only the latest
`main` revision is maintained. There has been no independent security audit.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/m-saad-siddique/AWS-MCP/security/advisories/new).
Include the affected commit, reproduction steps using synthetic data, impact,
and suggested mitigation if known. Do not open a public issue with exploit
details, credentials, dashboard tokens, real query results, or private AWS data.
No guaranteed response time is offered.

## Trust boundary

- The broker binds to loopback and separates operator and agent API tokens.
  Filesystem access under the same OS user can expose either token or alter
  the application. This is not multi-user isolation or a sandbox for the agent.
- Policies constrain commands routed through this MCP. IAM/database permissions
  remain the authority; other tools can bypass this MCP if separately permitted.
- Default approval is manual. Broader automatic rules and direct output delivery
  authorize the associated data access and possible remote effects.
- MFA credentials are held in memory or macOS Keychain until expiration. MFA
  codes and database authentication passwords are not saved to history.
- `.runtime/` contains private tokens, configuration, policies, query text,
  parameters, and released results. Never commit, upload, or share it. Custom
  `AWS_MCP_STATE_DIR` locations have the same sensitivity.
- Recognizable credential fields are redacted; arbitrary secrets in output,
  SQL literals/parameters, or application data may remain. Review and mask when
  needed. Unreleased output is memory-only and cannot be recovered after restart.
- Cancellation stops local work; it cannot undo remote actions. Inspect requests
  marked `outcome_unknown` before retrying. Restart does not replay requests.

See the README's Local boundaries, History, Policies, and MFA sections for
operational details. Public examples and test screenshots use synthetic data.
