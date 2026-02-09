# Generating Signing Keys

Signing keys are used to sign CAPTCHA JWTs and webhook payloads.

## Generate a Key

```bash
openssl rand -base64 32
```

**Example output:**
```
W4+hjYXhOzkS4tg42J3h728oFtAZvohBpalrBq6ENeg=
```
