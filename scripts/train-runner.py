#!/usr/bin/env python3
import sys
import time

def run_marionette_session():
    try:
        from marionette_driver.marionette import Marionette
    except ImportError:
        print("marionette-driver not installed, skipping Marionette session.")
        return False

    client = Marionette(host="127.0.0.1", port=2828)
    connected = False
    for attempt in range(25):
        try:
            print(f"Connecting to Marionette on 127.0.0.1:2828 (attempt {attempt+1}/25)...")
            client.start_session()
            connected = True
            print("Successfully connected to Marionette!")
            break
        except Exception as e:
            print(f"Connection waiting: {e}")
            time.sleep(2)

    if not connected:
        print("Could not connect to Marionette.")
        return False

    try:
        print("Navigating to workload via Marionette...")
        client.navigate("file:///data/local/tmp/workload/index.html")
    except Exception as e:
        print(f"Navigation warning: {e}")

    print("Running training session for 120 seconds...")
    for elapsed in range(10, 130, 10):
        time.sleep(10)
        print(f"Training in progress ({elapsed}s / 120s)...")

    print("Instructing GeckoView to cleanly quit from within the application...")
    try:
        client.quit(in_app=True)
        print("In-app quit command sent successfully!")
        time.sleep(5)
        return True
    except Exception as e:
        print(f"In-app quit warning: {e}")
        return False

if __name__ == "__main__":
    success = run_marionette_session()
    sys.exit(0 if success else 1)
