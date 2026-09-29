# github-security-overview

Print all GitHub security advisories across one or more GitHub organizations, one advisory per line.

```bash
pip install .
GITHUB_TOKEN=ghp_... security-overview org1 [org2 ...]
```

The token needs `security_events` read access.

## Example

```
$ security-overview acme
created  updated  to-publish  state      severity  org   repo    cve            title
     12        0              draft      high      acme  repo-a  CVE-2026-xxxx  Arbitrary File Read via Path Traversal
    116      116              triage     medium    acme  repo-c                 Authentication Token Theft via XSS
    232        9           6  published  critical  acme  repo-c  CVE-2025-xxxx  Pwn Request via misconfigured workflow
    233      107              draft      high      acme  repo-b                 Path Traversal in Assignment Validation  PRs: #7 (opened)
```

Ages are in days; `to-publish` is the time from open to publication. Advisories come most
recently opened first, unless `--sort` says otherwise. The header goes to
stderr, and when stdout is piped the columns are tab-separated — so `wc -l` counts
advisories and `awk`/`cut`/`datamash` work directly, e.g. `security-overview acme | datamash --narm median 3`.

## Options

```
usage: security-overview [-h] [--state STATE[,STATE...]]
                         [--columns COL[,COL...]] [--sort COL[,COL...]]
                         [--redact] [--format {terminal,md}]
                         [--opened-from YYYY-MM-DD] [--opened-to YYYY-MM-DD]
                         [--published-from YYYY-MM-DD]
                         [--published-to YYYY-MM-DD]
                         org [org ...]

options:
  -h, --help            show this help message and exit
  --state STATE[,STATE...]
                        filter by state; repeatable and/or comma-separated
                        (default: all states)
  --columns COL[,COL...]
                        show only these columns; repeatable and/or comma-
                        separated, always printed in the canonical order
                        (default: all of created, updated, to-publish, state,
                        severity, org, repo, ghsa, cve, title, PRs)
  --sort COL[,COL...]   sort by these columns, first one first; repeatable
                        and/or comma-separated. Day counts sort smallest (most
                        recent) first, severities worst first, orgs in the
                        order given on the command line, the rest
                        alphabetically (default: created,org,repo)
  --redact              hide org/repo names and drop every column that
                        identifies an advisory
  --format {terminal,md}
                        output format (default: terminal)
  --opened-from YYYY-MM-DD
                        only advisories opened on or after this date
  --opened-to YYYY-MM-DD
                        only advisories opened on or before this date
  --published-from YYYY-MM-DD
                        only advisories published on or after this date
  --published-to YYYY-MM-DD
                        only advisories published on or before this date
```

MIT licence.
