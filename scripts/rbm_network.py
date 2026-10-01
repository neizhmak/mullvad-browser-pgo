"""Bounded retries for RBM's official Savannah config.git transport failure.

The two-line error signature was observed in both October 1, 2026 hosted
resolve-pgo-rust-identity failures. No other URL, integrity failure, source
selection, compiler build, or showconf error is retried.
"""
from pathlib import Path
import re
import subprocess
import sys
import time


_CONFIG_URL = "https://git.savannah.gnu.org/git/config.git"
_FATAL = re.compile(r"fatal: unable to access '" + re.escape(_CONFIG_URL)
                    + r"/?': (?P<reason>.+)\Z")
_CLONE = re.compile(r"Error: Error cloning " + re.escape(_CONFIG_URL) + r"/?\Z")
_TRANSIENT = re.compile(
    r"(?:The requested URL returned error: (?:500|502|503|504)"
    r"|(?:Operation|Connection) timed out(?: after \d+ (?:milliseconds|ms)"
    r"(?: with \d+ (?:out of \d+ )?bytes received)?)?"
    r"|Timeout was reached"
    r"|Failed to connect to git\.savannah\.gnu\.org port 443(?: after \d+ ms)?: "
    r"(?:Connection timed out|Timeout was reached)"
    r"|(?:Recv|Send) failure: Connection (?:was )?reset(?: by peer)?"
    r"|Connection (?:was )?reset(?: by peer)?"
    r"|Operation too slow\. Less than \d+ bytes/sec transferred the last \d+ seconds)\Z"
)
# Fail closed on mixed failures, including integrity/authentication failures
# without an "Error:" prefix. Benign clone progress is not an error.
_OTHER_FAILURE = re.compile(
    r"\b(?:fatal|error)\s*:|\b(?:checksum|sha-?\d+|hash|digest|integrity|corrupt|"
    r"signature|certificate|cert|ssl|tls|gpg|authentication|authorization|unauthorized|"
    r"forbidden|username|password|credential|revision|commit|ref|mismatch)\b|"
    r"not found|does not exist|permission denied|subcommand failed|build stopped", re.IGNORECASE
)


def _retryable(stderr, stdout):
    fatal = clone = False
    for line in (stderr + "\n" + stdout).splitlines():
        line = line.strip()
        match = _FATAL.fullmatch(line)
        if match:
            if not _TRANSIENT.fullmatch(match["reason"]):
                return False
            fatal = True
        elif _CLONE.fullmatch(line):
            clone = True
        elif _OTHER_FAILURE.search(line):
            return False
    return fatal and clone


def showconf(upstream, project, key, targets, *, pause=None) -> str:
    """Run unchanged RBM showconf; retry only the exact config clone failure.

    ``pause`` is injectable for native tests. Production waits 10 then 30
    seconds, at most three attempts. A failed command's stdout is never an
    identity; the final CalledProcessError retains its native exit and argv.
    """
    upstream = Path(upstream)
    command = [str(upstream / "rbm/rbm"), "showconf", project, key]
    for target in targets:
        command += ["--target", target]
    if pause is None:
        pause = time.sleep
    for attempt in range(1, 4):
        result = subprocess.run(command, cwd=upstream, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.stderr:
            sys.stderr.write(result.stderr)
            sys.stderr.flush()
        if result.returncode == 0:
            return result.stdout.strip()
        if result.stderr and not result.stderr.endswith("\n"):
            sys.stderr.write("\n")
        # RBM can put clone diagnostics on stdout. Retain failed output only
        # on stderr; it must never become the returned source/tool identity.
        if result.stdout:
            sys.stderr.write(result.stdout)
            if not result.stdout.endswith("\n"):
                sys.stderr.write("\n")
            sys.stderr.flush()
        retryable = result.returncode > 0 and _retryable(result.stderr, result.stdout)
        if retryable and attempt < 3:
            delay = (10, 30)[attempt - 1]
            print(f"RBM showconf attempt {attempt}/3 failed (exit {result.returncode}); "
                  f"official Savannah config transport failure; retrying identical command "
                  f"in {delay}s.", file=sys.stderr, flush=True)
            pause(delay)
        else:
            reason = "retry limit reached" if retryable else "not a retryable config transport failure"
            print(f"RBM showconf attempt {attempt}/3 failed (exit {result.returncode}); "
                  f"{reason}.", file=sys.stderr, flush=True)
            raise subprocess.CalledProcessError(result.returncode, command,
                                                output=result.stdout, stderr=result.stderr)
