#!/usr/bin/env python3
import sys
import time

def run_marionette_navigation():
    try:
        from marionette_driver.marionette import Marionette
    except ImportError:
        print("marionette-driver not installed, skipping Marionette navigation.", flush=True)
        return False

    client = Marionette(host="127.0.0.1", port=2828)
    connected = False
    for attempt in range(15):
        try:
            print(f"Connecting to Marionette on 127.0.0.1:2828 (attempt {attempt+1}/15)...", flush=True)
            client.start_session()
            connected = True
            print("Successfully connected to Marionette!", flush=True)
            break
        except Exception as e:
            print(f"Connection waiting: {e}", flush=True)
            time.sleep(2)

    if not connected:
        print("Could not connect to Marionette.", flush=True)
        return False

    try:
        print("Navigating to workload via Marionette...", flush=True)
        client.navigate("file:///data/local/tmp/workload/index.html")
        print("Workload navigation succeeded!", flush=True)
        return True
    except Exception as e:
        print(f"Navigation warning: {e}", flush=True)
        return False

if __name__ == "__main__":
    success = run_marionette_navigation()
    sys.exit(0 if success else 1)
