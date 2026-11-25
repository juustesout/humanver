# humanver

A Hermes plugin that registers a `human_verify` tool for Windows Hello biometric verification.

## How it works

The tool calls into the Windows Biometric Framework (WINBIO) via ctypes. It opens a biometric session and prompts the user to scan a fingerprint. Returns whether the fingerprint matches the enrolled identity.

Available only on Windows (enforced by `check_fn`).

## Files

| File | Purpose |
|---|---|
| `plugin.yaml` | Plugin manifest |
| `__init__.py` | Tool registration, schema, handler |
| `_winbio.py` | WINBIO ctypes bindings |

## Requirements

- Windows 10 or later
- Windows Biometric Service running
- Registered fingerprint enrollment (Windows Hello)

## License

Proof-of-concept. license: MIT.
