import time
import sys
import traceback
import logging

SERVICE_NAME = "CFS_TEST_MICROSERVICE"

def say(msg):
    print(f"{SERVICE_NAME}: {msg}", flush=True)

def main():
    say("STARTUP")
    counter = 0

    while True:
        counter += 1
        say(f"HEARTBEAT {counter}")
        time.sleep(5)

if __name__ == "__main__":
    try:
        main()
    except Exception:
        say("CRASH")
        print(traceback.format_exc(), flush=True)
        sys.stdout.flush()
        raise
