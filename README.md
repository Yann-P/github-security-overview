# github-security-overview

Aggregates and prints all github security advisories from all repos belonging to the input github organization(s).

# Why

Because github has no aggregated view for security advisories across repositories.

# Example output

```
$ ./security-overview acme

=== acme ===
repo-a
      0d  Arbitrary File Read via Path Traversal            draft      https://github.com/acme/repo-a/security/advisories/GHSA-xxxx-xxxx-xxxx
      0d  Arbitrary File Write via Path Traversal           draft      https://github.com/acme/repo-a/security/advisories/GHSA-xxxx-xxxx-xxxx
     12d  XSS when output is exported as HTML               draft      https://github.com/acme/repo-a/security/advisories/GHSA-xxxx-xxxx-xxxx
repo-b
    107d  Path Traversal in Assignment Validation           draft      https://github.com/acme/repo-b/security/advisories/GHSA-xxxx-xxxx-xxxx
repo-c
    116d  Authentication Token Theft via XSS                triage     https://github.com/acme/repo-c/security/advisories/GHSA-xxxx-xxxx-xxxx
    181d  Open redirect via untrusted user input            triage     https://github.com/acme/repo-c/security/advisories/GHSA-xxxx-xxxx-xxxx
    232d  Pwn Request via misconfigured workflow            draft      https://github.com/acme/repo-c/security/advisories/GHSA-xxxx-xxxx-xxxx
    454d  XSS via mermaid chart rendering                   draft      https://github.com/acme/repo-c/security/advisories/GHSA-xxxx-xxxx-xxxx
    624d  DOM Clobbering XSS                                draft      https://github.com/acme/repo-c/security/advisories/GHSA-xxxx-xxxx-xxxx
    638d  Arbitrary file overwrite on extension install     triage     https://github.com/acme/repo-c/security/advisories/GHSA-xxxx-xxxx-xxxx
```

# Run it

- Install [Github CLI](https://cli.github.com/) and `gh auth login`

- `curl -fsSL https://raw.githubusercontent.com/Yann-P/github-security-overview/main/security-overview | python3 - org1 [org2]`

# Usage 

```
./security-overview org1 [org2] ... [org𝑛]
./security-overview --state draft --state triage org1 [org2] ... [org𝑛]
```

# Architecture principles

- No python dependencies

# Roadmap

- [x] color-coded full black character at the start of the line using plasma color range (yellow-purple) depending on last update date

# Licence

MIT 