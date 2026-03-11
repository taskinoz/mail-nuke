# Thunderbird plugin: Local Spam Filter

This add-on scores messages by calling a local HTTP service and can then:

- mark spam as junk
- move spam to the account junk folder or a custom folder
- tag spam with a configurable Thunderbird tag
- manually score the currently displayed message from the message toolbar button
- automatically score new mail as it arrives

## Expected scoring API

Default URL:

`http://127.0.0.1:8765/score`

Request body:

```json
{
  "from": "Sender <sender@example.com>",
  "subject": "Message subject",
  "body": "Plain text body",
  "date": "2026-03-12T10:00:00.000Z",
  "folder": {
    "id": "...",
    "accountId": "...",
    "name": "Inbox",
    "path": "/Inbox",
    "specialUse": "inbox"
  }
}
```

Response body can be either label-based or score-based:

```json
{
  "label": "spam",
  "spamScore": 0.997,
  "category": "credential_leak_bait"
}
```

The plugin treats a message as spam when either:

- `label === "spam"` (configurable in options)
- or `spamScore >= spamScoreThreshold`

## Folder structure

Place this directory in your repo under `plugin/`.

## Loading in Thunderbird

1. Open **Add-ons and Themes**.
2. Open the gear menu.
3. Choose **Debug Add-ons**.
4. Choose **Load Temporary Add-on**.
5. Select `manifest.json` from this folder.

## Notes

- The extension does not run Python directly. It expects your local spam filter to be exposed as an HTTP service.
- Default behavior is conservative but enabled:
  - automatic mode on
  - manual mode on
  - mark as junk on
  - move to junk folder on
  - add tag on
