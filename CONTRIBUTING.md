# Contributing

Bug reports, documentation fixes, and focused pull requests are welcome.
Discuss large behavior changes in an issue first. Keep examples synthetic.

## Develop locally

Use Node.js 22.14 or newer:

```sh
npm ci --ignore-scripts
npm run check
npm test
npx playwright install chromium
npm run test:ui
```

The unit/integration/browser suites use fake AWS credentials and runners. They
need loopback ports and do not call AWS. The browser test regenerates synthetic
screenshots in `examples/`; avoid unrelated screenshot churn in pull requests.
The optional real PostgreSQL/MySQL/Keychain checks are documented in the README.

Run `npm start` only when you want the dashboard to read your own local profiles.
Actual requests you approve there use your real AWS/database permissions.

## Pull requests

Explain the user-facing problem, behavior change, and relevant validation.
Add meaningful coverage for approval, policy, execution, persistence, or data
exposure changes. Keep execution shell-free, broker checks authoritative,
held output private, and approvals tied to explicit request IDs. Do not weaken
TLS verification or add secrets to logs, command arguments, or fixtures.

Never include `.runtime/`, credential files, private certificates/keys, real
account identifiers, database output, or authenticated dashboard URLs. The
public RDS CA bundle under `assets/` is intentionally included.

Report vulnerabilities using [SECURITY.md](SECURITY.md), not a public issue.
Contributions are made under the project's [MIT license](LICENSE).
