#!/usr/bin/env python3
"""Entry point for the Buzz API sample.

If setup has not been completed (configuration missing or the private key file is
not readable), the interactive setup runs first.  Then the read-only sample runs.

Usage:
    python scripts/run_buzz_sample.py [--setup]

    --setup   Force re-running setup even if already configured.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import PROJECT_ROOT  # noqa: E402

sys.path.insert(0, PROJECT_ROOT)
from buzz_config import ENV_VARS, load_env  # noqa: E402


def setup_complete() -> bool:
    load_env()
    required = ["server_url", "oauth_user_id", "oauth_kid", "private_key_path"]
    if any(not os.environ.get(ENV_VARS[f]) for f in required):
        return False
    key_path = os.environ.get(ENV_VARS["private_key_path"], "")
    return bool(key_path) and os.path.isfile(key_path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the Buzz API sample (setup first if needed).")
    parser.add_argument("--setup", action="store_true", help="Force re-running setup")
    args = parser.parse_args(argv)

    if args.setup or not setup_complete():
        print("\n-- Running setup ---------------------------------------\n"
              if args.setup else
              "\n-- Setup not complete - starting interactive setup -----\n")
        import setup_buzz_oauth
        rc = setup_buzz_oauth.main([])
        if rc != 0:
            print("\nSetup did not complete.  Exiting.", file=sys.stderr)
            return 1
        # Load the freshly written .env (values absent before setup now load in).
        load_env()

    print("\n-- Running the sample ----------------------------------")
    import sample
    sample.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
