"""Bounded retries for RBM's official Savannah config.git transport failure.

The unable-to-access signature was observed on October 1, 2026; the paired
HTTP/RPC + expected-packfile signature was observed on October 2. No other
URL, integrity failure, source selection, compiler build, or showconf error
is retried.
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import time


_CONFIG_URL = "https://git.savannah.gnu.org/git/config.git"
_FATAL = re.compile(r"fatal: unable to access '" + re.escape(_CONFIG_URL)
                    + r"/?': (?P<reason>.+)\Z")
_CLONE = re.compile(r"Error: Error cloning " + re.escape(_CONFIG_URL) + r"/?\Z")
_RPC = re.compile(r"error: RPC failed; HTTP (?P<code>500|502|503|504) curl 22 "
                  r"The requested URL returned error: (?P=code)\Z")
_REDIRECT = re.compile(r"warning: redirecting to "
                       r"https://https\.git\.savannah\.gnu\.org/git/config\.git/?\Z")
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
    rpc = packfile = 0
    for line in (stderr + "\n" + stdout).splitlines():
        line = line.strip()
        match = _FATAL.fullmatch(line)
        if match:
            if not _TRANSIENT.fullmatch(match["reason"]):
                return False
            fatal = True
        elif _CLONE.fullmatch(line):
            clone = True
        elif _RPC.fullmatch(line):
            rpc += 1
        elif line == "fatal: expected 'packfile'":
            packfile += 1
        elif _REDIRECT.fullmatch(line):
            pass  # Observed server warning only; never rewrite the source URL.
        elif (_OTHER_FAILURE.search(line) or "rpc failed" in line.lower()
              or line.lower().startswith("warning: redirecting")):
            return False
    # The packfile message alone is not a transport error. Permit it only
    # as the single companion to one positive HTTP/curl22 RPC failure.
    return clone and ((fatal and rpc == packfile == 0)
                      or (not fatal and rpc == packfile == 1))


def _relay_stderr(data):
    buffer = getattr(sys.stderr, "buffer", None)
    if isinstance(data, bytes) and buffer is not None:
        sys.stderr.flush()
        buffer.write(data)
        buffer.flush()
    else:
        sys.stderr.write(data.decode("utf-8", "surrogateescape") if isinstance(data, bytes) else data)
        sys.stderr.flush()


def showconf(upstream, project, key, targets, *, pause=None, raw_output=False) -> str:
    """Run unchanged RBM showconf; retry only the exact config clone failure.

    ``pause`` is injectable for native tests. Production waits 10 then 30
    seconds, at most three attempts. A failed command's stdout is never an
    identity; the final CalledProcessError retains its native exit and argv.
    ``raw_output=True`` returns lossless rendering text without newline conversion
    (UTF-8/surrogateescape); its failed CalledProcessError streams stay bytes.
    """
    upstream = Path(upstream)
    command = [str(upstream / "rbm/rbm"), "showconf", project, key]
    for target in targets:
        command += ["--target", target]
    if pause is None:
        pause = time.sleep
    for attempt in range(1, 4):
        result = subprocess.run(command, cwd=upstream, text=not raw_output,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = result.stdout.decode("utf-8", "surrogateescape") if raw_output else result.stdout
        stderr = result.stderr.decode("utf-8", "surrogateescape") if raw_output else result.stderr
        if result.stderr:
            _relay_stderr(result.stderr)
        if result.returncode == 0:
            return stdout if raw_output else stdout.strip()
        if stderr and not stderr.endswith("\n"):
            sys.stderr.write("\n")
        # RBM can put clone diagnostics on stdout. Retain failed output only
        # on stderr; it must never become the returned source/tool identity.
        if result.stdout:
            _relay_stderr(result.stdout)
            if not stdout.endswith("\n"):
                sys.stderr.write("\n")
            sys.stderr.flush()
        retryable = result.returncode > 0 and _retryable(stderr, stdout)
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--target", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        rendering = showconf(args.upstream.resolve(), args.project, args.key, args.target, raw_output=True)
    except subprocess.CalledProcessError as error:
        # showconf already relayed both failed streams to stderr. Shell callers
        # get the native exit (or conventional 128+signal), never a traceback.
        return 128 - error.returncode if error.returncode < 0 else error.returncode
    except OSError as error:
        print(f"RBM showconf could not start: {error}", file=sys.stderr)
        return 1
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(rendering.encode("utf-8", "surrogateescape"))
    else:
        sys.stdout.write(rendering)
    return 0


if __name__ == "__main__":
    sys.exit(main())
