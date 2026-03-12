# Local Thunderbird Spam Filter

A local-first Thunderbird spam filter that scores messages using a custom machine learning model trained on your own inbox history.

It supports:

- automatic scoring of new messages
- manual scoring from the message view toolbar
- moving detected spam to Junk or a custom folder
- marking messages as junk
- optional mark-as-read after classification
- configurable scoring threshold
- local HTTP scoring service
- training pipeline using Bun + Python

---

## Features

### Automatic mode

When enabled, new mail is scored as it arrives.

If a message is classified as spam, the add-on can:

- mark it as junk
- move it to the Junk folder
- move it to a custom folder instead
- optionally mark it as read

By default, automatic mode only processes inbox-like folders.

### Manual mode

A toolbar button appears in Thunderbird’s message display view.

When clicked, the currently displayed message or messages are scored immediately.

If spam is detected, the configured actions are applied.

### Local scoring service

The add-on sends message data to a local HTTP service, typically:

`http://127.0.0.1:8765/score`

This means:

- no cloud dependency
- no external email upload
- model stays local
- fast scoring once the model is loaded

### Configurable behaviour

The add-on options allow you to configure:

- automatic mode on/off
- manual mode on/off
- scoring service URL
- request timeout
- spam label value
- spam score threshold
- move enabled/disabled
- destination folder mode
- custom destination folder
- mark as junk enabled/disabled
- mark as read enabled/disabled
- dry run mode
- only scan inbox-like folders automatically
- include raw headers in request payload

---

## Repo layout

```txt
.
├─ config/
│  ├─ user-emails.txt
│  ├─ user-names.txt
│  └─ leaked-passwords.txt
├─ prepared/
├─ models/
│  └─ spam_filter.joblib
├─ plugin/
│  ├─ manifest.json
│  ├─ background.js
│  ├─ options/
│  └─ icons/
├─ scripts/
│  └─ package-plugin.ts
├─ trainer/
│  ├─ train.py
│  ├─ score.py
│  └─ server.py
└─ dist/
```

## How it works

### Training pipeline

The model is trained on `.eml` files exported from your mailbox:

- `ham/` for legitimate mail
- `spam/` for junk mail

A Bun preparation script extracts and normalises:

- sender address
- sender domain
- sender name
- subject
- body

It also replaces sensitive or overfitting-prone values with placeholders such as:

- `__USER_EMAIL__`
- `__USER_NAME__`
- `__LEAKED_PASSWORD__`
- `__PROVIDER_SPAM_MARKER__`

This keeps the text generic while preserving useful structure for the model.

### Model

The baseline model uses:

- TF-IDF vectorisation
- logistic regression
- threshold-based spam decision

### Thunderbird add-on flow

1. Thunderbird receives or displays a message.
2. The add-on extracts sender, subject, and body text.
3. The add-on sends the data to the local scoring service.
4. The service returns a spam score and label.
5. If the message is spam, the configured actions are applied.

## Local scoring service

The plugin expects a local scoring service endpoint such as:

`http://127.0.0.1:8765/score`

Example request:

```json
{
  "from_header": "Support <alerts@example.com>",
  "subject": "Your password has been leaked",
  "body": "We have been watching you..."
}
```

Example response:

```json
{
  "label": "spam",
  "spamScore": 0.9921,
  "threshold": 0.9
}
```

## Thunderbird add-on behaviour

### Automatic mode

Triggered by Thunderbird’s new mail event.

Recommended defaults:

- automatic enabled = true
- move enabled = true
- destination mode = junk
- mark junk enabled = true
- mark read enabled = false

### Manual mode

Triggered by the message display toolbar button.

Useful for:

- rescoring messages manually
- testing the model
- reviewing uncertain mail
- checking false positives and false negatives

### Moving messages

When move is enabled, spam messages can be moved to:

- the account Junk folder
- a custom selected folder

### Dry run mode

When enabled, the plugin still scores messages but does not modify them.

Useful for:

- testing thresholds
- verifying model behaviour
- debugging service integration

## Installation

Temporary install for development

Open Thunderbird.

1. Go to Add-ons and Themes.
1. Open the gear menu.
1. Choose Debug Add-ons or Install Add-on From File depending on your workflow.
1. Load the add-on from the plugin/ directory or packaged .xpi.

### Packaged install

Build the package:

```bash
bun run package:plugin
```

Then install the generated file from `dist/`.

## Packaging

The repo includes a Bun packaging script.

### Build the plugin package

```bash
bun run package:plugin
```

This will:

- read `plugin/manifest.json`
- package the contents of `plugin/`
- output a versioned `.xpi` file into `dist/`

Example output:

```bash
dist/local-thunderbird-spam-filter-v1.0.0.xpi
```

## Development

### Run the Python scoring server

From the trainer/ folder:

```bash
uv run uvicorn server:app --host 127.0.0.1 --port 8765
```

### Test the scoring endpoint

```bash
curl http://127.0.0.1:8765/score \
  -H "Content-Type: application/json" \
  -d '{
    "from_header": "Test Sender <test@example.com>",
    "subject": "We have leaked your password",
    "body": "We have been watching you"
  }'
```

## Configuration files

`config/user-emails.txt`

List of your own email addresses to replace in training/inference.

Example:

```
me@example.com
alias@example.com
```

`config/user-names.txt`

List of personal names to replace in training/inference.

Example:

```
John Smith
J Smith
```

`config/leaked-passwords.txt`

Known leaked passwords to replace with a generic token.

Example:

```
hunter2
oldpassword123
```

## Current scoring payload fields

The add-on sends:

- messageId
- from_header
- subject
- body
- date
- folder
- raw when enabled

The server primarily uses:

- from_header
- subject
- body

## Notes

- This add-on is designed for local/private use.
- It does not require a remote spam filtering service.
- It works best when the training set is regularly refined.
- The safest threshold is usually a conservative one to reduce false positives.
- Dry run mode is recommended before enabling automatic moving in production.

## Limitations

- Tagging support was removed from the current implementation to avoid Thunderbird API compatibility issues.
- The quality of detection depends heavily on the quality of the training data.
- HTML-heavy or image-only spam may need more preprocessing for best results.
- Thunderbird may still apply its own filters before or after the add-on runs.

## Roadmap

Possible future improvements:

- user feedback actions for retraining
- per-category spam labels
- whitelist/blacklist sender rules
- sender reputation cache
- batch scoring endpoint
- automatic retraining workflow
- better options UI
- score explanations in the UI

## License

Private/internal project unless otherwise specified.
