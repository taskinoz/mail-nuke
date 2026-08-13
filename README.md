# Mail Nuke

Mail Nuke is a local-first, self-hosted email indexing, spam-classification, review, and retraining service. Version 2 connects directly to IMAP mailboxes, stores durable state in SQLite, trains private models from configured mailbox folders, and can observe or move newly classified spam.

Version 2 is functional but remains a development release. Use `observe` mode until the production blockers below are completed and the installation has been validated against real mailboxes.

See the [v2 architecture plan](docs/v2-architecture-and-implementation-plan.md) for the detailed design. The former Thunderbird add-on and export-based workflow are retained only as [legacy v1 reference](docs/legacy-thunderbird-v1.md).

## Current capabilities

- One local administrator with bearer-token sessions and no public registration.
- Multiple encrypted IMAP accounts in independent or shared model groups.
- Connection testing, folder discovery, and `ham`, `spam`, `monitored`, `excluded`, or `neutral` folder roles.
- Resumable initial indexing with UID checkpoints and compressed raw-message storage.
- Periodic/manual reconciliation for new messages, moves, corrections, and deletions.
- Versioned privacy profiles shared by indexing, training, and live inference.
- Message review, label corrections, training exclusion, and permanent purge.
- Immutable group datasets, deterministic cohorts, candidate evaluation, and guarded promotion.
- Group threshold overrides and per-account `off`, `observe`, or `move` automation.
- Per-mailbox readiness and background-job activity in the portal.

## Run with Docker

Requirements are Docker Desktop or Docker Engine with Compose, plus an IMAP account (preferably using an app-specific password).

```bash
docker compose up -d --build
```

Open <http://127.0.0.1:8765>. Compose intentionally binds the portal to localhost. State is stored in the host `data/` directory.

The container briefly starts as root to repair ownership of `/data`, then runs the application as UID `10001`.

```bash
docker compose ps
curl http://127.0.0.1:8765/health
docker compose down
```

`docker compose down` stops the service without deleting the bind-mounted data.

## First mailbox setup

Complete initialization in this order:

1. Create the local administrator and sign in.
2. Create a model group.
3. Add an IMAP account to that group.
4. Test the connection and discover folders.
5. Assign folder roles. A useful training setup normally has both ham and spam sources.
6. Configure the model group's privacy profile.
7. Start the initial index and wait for completion.
8. Train the group and wait for an active model.
9. Enable `observe` and review predictions before considering `move`.

Initial indexing requires at least one `ham`, `spam`, or `monitored` folder. Manual and scheduled synchronization require a completed initial index. These guards prevent uninitialized mailboxes from being treated as operational.

## Mailbox readiness

`GET /api/v2/readiness` returns overall `ready` state and status for each enabled mailbox.

| Status | Meaning | Next action |
|---|---|---|
| `setup_required` | Ham/spam folder coverage is incomplete. | Discover folders and assign roles. |
| `ready_to_index` | Folder setup exists but indexing is incomplete. | Start or retry initial indexing. |
| `indexing` | Initial indexing is queued or running. | Monitor the background job. |
| `model_required` | Indexing is complete but no model is active. | Train the model group. |
| `ready_to_enable` | A model is active but automation is off. | Enable `observe` when ready. |
| `active` | Indexed, modeled, and automation enabled. | Monitor predictions and corrections. |
| `error` | A background job failed. | Review the sanitized error and retry safely. |

The deployment is ready only when at least one enabled mailbox exists and every enabled mailbox is ready.

## Automation safety

- `off`: no live inference or mailbox action.
- `observe`: record predictions without modifying mail.
- `move`: move predicted spam to the selected folder with the `spam` role.

Initial indexing is training-only. Automated moves are not treated as confirmed spam labels, so the model cannot teach itself that its prediction was correct. Human folder corrections and dashboard labels remain the source of truth. Marking a message as Spam in the dashboard also queues a move from its recorded source folder to that mailbox's configured Spam destination; the move appears in background activity and fails safely if the recorded UID is stale.

Use `observe` first. Review false positives, false negatives, thresholds, and destination behavior before enabling `move`.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `MAIL_NUKE_DATA_DIR` | `data` locally; `/data` in Docker | Database, key, raw mail, and models. |
| `MAIL_NUKE_PORT` | `8765` in Compose | Localhost host port. |
| `MAIL_NUKE_SECRET_KEY` | Generated if omitted | Optional externally managed Fernet key. |
| `MAIL_NUKE_RECONCILE_INTERVAL_SECONDS` | `300` | Reconciliation interval; minimum 300 seconds. |
| `MAIL_NUKE_TRAIN_INTERVAL_SECONDS` | `604800` | Training interval; minimum 3600 seconds. |

When no key is supplied, Mail Nuke generates `data/secret.key`. IMAP passwords and configured sensitive values cannot be recovered without it. Back it up securely and separately; never commit it.

The root `.env.example` contains only v2 settings. Legacy tools may require their historical variables when run independently, but those variables are not consumed by the v2 web application.

## API overview

Authenticated calls use `Authorization: Bearer <token>` with the token from `POST /api/v2/auth/login`.

| Area | Endpoints |
|---|---|
| Health/setup | `GET /health`, `GET /api/v2/setup/status`, `POST /api/v2/setup/admin` |
| Authentication | `POST /api/v2/auth/login`, `POST /api/v2/auth/logout` |
| Model groups | `GET|POST /api/v2/model-groups` |
| Accounts | `GET|POST /api/v2/accounts`; test, discovery, roles, index, sync, and automation under `/api/v2/accounts/{id}` |
| Privacy | `GET|PUT /api/v2/model-groups/{id}/privacy-profile` |
| Messages | `GET /api/v2/messages`, `PATCH|DELETE /api/v2/messages/{id}`, `GET /api/v2/messages/{id}/events` |
| Training | Train, model status, and threshold endpoints under `/api/v2/model-groups/{id}` |
| Operations | `GET /api/v2/readiness`, `GET /api/v2/jobs`, `GET /api/v2/exports/sender-classifications` |

Interactive OpenAPI and ReDoc routes are disabled.

## Sender classification exports

The Messages page can download CSV or JSON containing deduplicated sender email addresses and domains classified as ham or spam. The export respects the selected mailbox/model-group scope and label filter.

Each row contains `entity_type`, normalized `value`, effective `label`, `message_count`, `account_count`, `first_seen_at`, and `last_seen_at`. If one sender has both ham and spam history, each classification is retained as a separate row. Purged sender identities are excluded.

The authenticated endpoint is `GET /api/v2/exports/sender-classifications` and accepts:

- `format=csv|json`;
- `entity=all|domain|email`;
- `label=ham|spam` (optional);
- `account_id` or `group_id` (optional).

## Development

Python 3.12 is supported.

```bash
uv sync --frozen
uv run python -m unittest discover -s tests -v
uv run uvicorn mail_nuke.app:app --host 127.0.0.1 --port 8765
```

The application uses Python `sqlite3` and ordered in-process schema migrations. The architecture plan proposed SQLAlchemy and Alembic, but that is not the current implementation.

## Repository layout

```text
mail_nuke/    FastAPI, database, IMAP, indexing, reconciliation, training, scoring
tests/        Python unit and workflow tests
docs/         V2 architecture and legacy reference
data/         Runtime state mounted at /data; ignored by Git
```

`plugin/`, `trainer/`, `config/`, the Bun package files, and the packaging script are legacy v1 assets and are not part of the v2 container runtime.

## Production release blockers

1. Durable job leases, bounded retries, cancellation, concurrency protection, and retention.
2. Explicit model promotion/rejection controls and tested rollback.
3. Backup, restore, integrity checking, key recovery, and upgrade procedures.
4. Real IMAP integration tests for UIDVALIDITY changes, partial failures, reconnects, moves, and deletion.
5. Rate limiting, session hardening, untrusted-email rendering protections, MIME/size limits, redaction, and dependency/container scanning.
6. Large-mailbox performance, restart, outage, and recovery validation.
7. Remaining operational dashboards, trends, and richer provenance/date filtering from the architecture plan.
8. A documented raw-content retention policy, purge validation, and key rotation.

Do not expose the portal directly to the public internet. A supported authenticated reverse-proxy or private-network pattern has not yet been documented or hardened.

## Implementation notes and deviations

- SQLite runs in WAL mode at schema version `8`; migrations live in `mail_nuke/database.py`.
- The scheduler and worker run in-process with FastAPI.
- Running jobs are re-queued at startup, but leases/retries/cancellation remain future work.
- Raw messages are compressed and retained for review and privacy reprocessing.
- The service is single-owner and single-container, not multi-tenant.
- V2 performs IMAP reconciliation and automation itself; the Thunderbird add-on is not its filtering path.

## License

Private/internal project unless otherwise specified.
