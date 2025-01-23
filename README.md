# procnotify

[![Build and Package Rust Program](https://github.com/hut8/procnotify/actions/workflows/build.yml/badge.svg)](https://github.com/hut8/procnotify/actions/workflows/build.yml)

Procnotify is a simple utility that notifies the user via email when a particular process has been completed. For example, a particular SQL query might take hours to run; this saves you from having to "poll" your terminal to see if it has completed yet.

## Configuration

You will need an SMTP server. Mailgun works on their free tier. Copy `.env.example` and edit the values. Ensure that they are exported in your shell somehow.

## Usage

```bash
/bin/sleep 3600 & procnotify --pid $! &
```

Notice that that's one `&`, not two. Two means "run the command on the right after the command on the left succeeds", but the single `&` means "run the command to the left in the background, then immediately run the next command, if any".
