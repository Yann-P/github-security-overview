ALL_STATES = ["published", "draft", "triage", "closed"]

RESET = "\033[0m"
BOLD = "\033[1m"
GREY = "\033[2m"

STATE_COLORS = {
    "draft":     "\033[36m",
    "triage":    "\033[33m",
    "published": "\033[32m",
    "closed":    GREY,
}

PR_STATE_COLORS = {
    "open":   "\033[32m",
    "merged": "\033[35m",
    "closed": "\033[31m",
}
