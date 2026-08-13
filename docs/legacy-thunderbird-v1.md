# Legacy Thunderbird v1 reference

This document records the former Mail Nuke v1 Thunderbird add-on and export-based training workflow. It is implementation history only and does not describe the active v2 application. Use the [root README](../README.md) for current setup.

## Former architecture

V1 combined:

- a Thunderbird add-on in `plugin/`;
- a local `/score` service in `trainer/server.py`;
- training scripts operating on exported `.eml` files;
- plaintext replacement lists under `config/`;
- Bun-based add-on packaging.

The add-on could score messages automatically or manually, mark detected spam as junk, move it, optionally mark it read, and run without actions. It sent sender, subject, body, date, folder, and optionally raw headers to a local scoring service.

Training read exported ham and spam `.eml` files, normalized message text, replaced configured personal values, and trained a TF-IDF/logistic-regression Joblib model.

## Legacy repository areas

```text
config/      V1 privacy replacement lists
plugin/      Thunderbird extension
scripts/     Thunderbird package builder
trainer/     Export-based training and /score server
package.json Bun packaging commands
```

These paths remain for reference but are not part of the v2 container runtime.

## Legacy packaging

```bash
bun run package:plugin
```

This packages `plugin/` into a versioned `.xpi`. It is unrelated to building or deploying v2.

## Migration context

V2 replaces the Thunderbird/export workflow with direct IMAP indexing, database-backed message lifecycle and labels, private model groups, scheduled training, and server-side observation or mailbox moves. Current v2 does not import historical `.eml` exports.
