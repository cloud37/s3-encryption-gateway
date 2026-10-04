# Documentation

Start with the task you need to complete. Each topic below has one authoritative
guide; current instructions take precedence over historical plans and examples.

## Choose Your Task

| I need to… | Start here | What it contains |
|---|---|---|
| Decide whether my application will work | [S3 compatibility](S3_API_IMPLEMENTATION.md) | Released feature summary, every pinned SDK operation, request-option caveats, SDK/backend evidence |
| Install or configure the gateway | [Deployment](DEPLOYMENT.md) | Docker/Helm, backend selection, TLS, gateway credentials, bucket policies, Valkey/spool prerequisites |
| Configure an S3 client | [CLI tools](S3_CLI_TOOLS.md) | AWS CLI, s5cmd, mc, common recipes; consult compatibility before migration |
| Choose/manage encryption keys | [Key management](KMS_COMPATIBILITY.md) | Password/local-envelope/KMS choices, key sources, provider auth, rotation and retention |
| Upgrade, re-encrypt, or recover objects | [Migration](MIGRATION.md) | Coordinated upgrades/rollback, explicit gateway GET→PUT, read-only audit tool, controlled recovery |
| Respond to an incident or use the admin API | [Operations runbook](RUNBOOK.md) | State/key recovery, listing-size cache, alert playbooks, admin auth/endpoints |
| Configure dashboards, logs, or profiling | [Observability](OBSERVABILITY.md) | Metrics/audit/tracing, Prometheus/Grafana, profiling recipes |
| Size the deployment or measure performance | [Performance and scaling](PERFORMANCE.md) | Benchmark evidence/methodology, HPA, graceful shutdown, memory/disk/Valkey capacity |
| Understand the design | [Architecture](ARCHITECTURE.md) and [encryption design](ENCRYPTION_DESIGN.md) | Component/security boundaries, formats, metadata, FIPS build profile |
| Contribute code or docs | [Contributor guide](DEVELOPMENT_GUIDE.md) | Local setup, ownership, explanatory commits, review and documentation conventions |
| Run tests or understand quality gates | [Testing](TESTING.md) | Unit/FIPS/conformance commands, regression recipes, coverage/exclusion/mutation policy |
| Publish a release | [Release checklist](releasing.md) | Chart/image/changelog/SBOM preparation and release automation |
| Follow accepted future work | [Roadmap](ROADMAP.md) | Issue-linked unreleased work; no speculative delivery dates |

## Supporting References

- [Helm chart reference](../helm/s3-encryption-gateway/README.md),
  [example configuration](../config.yaml.example), and
  [chart values/schema](../helm/s3-encryption-gateway/): exact deployment fields.
- [Progressive delivery](OPS_DEPLOYMENT.md): blue/green, canary, shared-state
  constraints, and runnable [deployment examples](examples/).
- [Harbor integration](integrations/harbor.md): application-specific setup.
- [Security reporting](../SECURITY.md): disclosure process. The older
  [security audit](SECURITY_AUDIT.md) and [security findings](security/) are
  evidence/reference material, not a claim that every historical mitigation is deployed.
- [Diagrams](diagrams/), [benchmark evidence](perf/), and [ADRs](adr/): durable
  supporting artifacts, separate from installation instructions.

## Historical Records and Moved Topics

[Plans](plans/), [issues](issues/), ADRs, security findings, and milestone benchmark
artifacts are preserved. The historical [V0.6 KeyManager sketch](V0.6-SEC-1-IMPLEMENTATION.md)
is not the current interface specification. Historical citations retain their
original filenames; consult the topic owners above for current instructions.

The former operation/option/SDK guides are consolidated into **S3 compatibility**;
backend/policy setup into **Deployment**; admin/metadata-key operations into the
**Runbook**; encryption-mode/rotation into **Key management**; old KMS migration
into **Migration**; metadata/FIPS into **Encryption design**; coverage into
**Testing**; scaling into **Performance**; and agent guidance into the
**Contributor guide**. No empty redirect files are maintained.
