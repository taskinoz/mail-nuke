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

## Thunderbird add-on flow

1) Thunderbird receives or displays a message.
2) The add-on extracts sender, subject, and body text.
3) The add-on sends the data to the local scoring service.
4) The service returns a spam score and label.
5) If the message is spam, the configured actions are applied.

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
