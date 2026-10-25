# RUK Sentinel

A small, safe local security-audit helper for **Termux on Android** and **Kali Linux**.

RUK Sentinel uses Python's standard library only. It does not exploit systems, scan public networks, collect passwords, or transmit your data.

## Features

- **System overview:** Python/platform details and whether common defensive tools are installed.
- **Local file-hygiene check:** reports potentially sensitive filenames (such as `.env`, private-key names, and credential files) without opening or printing their contents.
- **URL hygiene check:** checks URL formatting, flags plain HTTP, user-info embedded in a URL, and suspiciously unusual host formatting. It does not visit the URL or claim the site is safe.
- Works offline; no third-party Python packages required.

## Requirements

- Python 3.9 or newer (Python 3.10+ recommended).
- Termux or Kali Linux.
- No API keys or root access required.

## Install and run

### Termux

```bash
pkg update
pkg install python git
git clone https://github.com/Janrahat/janrahat.git
cd janrahat/ruk-sentinel
python ruk_sentinel.py
```

### Kali Linux

```bash
sudo apt update
sudo apt install -y python3 git
git clone https://github.com/Janrahat/janrahat.git
cd janrahat/ruk-sentinel
python3 ruk_sentinel.py
```

If you already cloned the repository, skip the `git clone` command and run `cd janrahat/ruk-sentinel` from the repository directory.

## Menu

1. Show a local system overview.
2. Check a directory for sensitive-looking filenames.
3. Review a URL's basic format.
4. Exit.

For option 2, enter a directory you own or are authorized to inspect. The tool lists filenames only; it does not read file contents. Hidden files are included.

## Limitations

This is a lightweight hygiene helper, **not** a vulnerability scanner, antivirus, firewall, or guarantee of security. URL checks are local string checks only. Verify important findings with trusted tools and official documentation.

## Authorized use

Use only on devices, files, and URLs you own or have permission to review. Do not use findings to access another person's accounts or data.

## License

MIT — see `LICENSE`.
