# mail-nuke

To install dependencies:

```bash
bun install
```

To run:

```bash
bun run prepare
```

To train run:
```bash
uv run trainer/train.py
```

To score email text:
```bash
uv run trainer/score.py --text $'from_address=test@bad-domain.com\nfrom_domain=bad-domain.com\nfrom_name=Support Team\nsubject=we have leaked your password __LEAKED_PASSWORD__\nbody=we have been watching you __USER_NAME__'
```

To score `.eml` file:
```bash
uv run trainer/score.py --eml ./test-mails/example.eml
```

To score a folder:
```bash
uv run trainer/score.py --folder ./test-mails
```

and save the results

```bash
uv run trainer/score.py --folder ./test-mails --save ./reports/test-mails-scan.jsonl
```

Run the server:
```bash
cd trainer
uv run uvicorn server:app --host 127.0.0.1 --port 8765
```