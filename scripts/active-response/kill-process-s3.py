#!/usr/bin/env python3

import sys
import os
import json
import hashlib
import signal
import time
import re
from datetime import datetime

LOG_FILE = "/var/ossec/logs/active-responses.log"


def log(message):
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(
            f"{timestamp} active-response/bin/kill-process-s3.py: "
            f"{message}\n"
        )


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)

    return h.hexdigest()


def process_exists(pid):
    return os.path.exists(f"/proc/{pid}")


def main():

    input_line = sys.stdin.readline().strip()

    if not input_line:
        log("KILL_PROCESS_ERROR reason=no_input")
        return 1

    try:
        data = json.loads(input_line)
    except Exception as e:
        log(f"KILL_PROCESS_ERROR reason=invalid_json error={e}")
        return 1

    log(f"INPUT: {input_line}")

    parameters = data.get("parameters", {})
    extra_args = parameters.get("extra_args", [])
    alert = parameters.get("alert", {})

    # Valeurs envoyées par n8n
    pid = None
    expected_sha256 = None
    expected_executable = None

    if len(extra_args) >= 3:
        pid = str(extra_args[0])
        expected_sha256 = str(extra_args[1]).lower()
        expected_executable = str(extra_args[2])

    # Fallback vers alert.data.process
    process_data = alert.get("data", {}).get("process", {})

    if not pid:
        pid = str(process_data.get("pid", ""))

    if not expected_sha256:
        expected_sha256 = str(
            process_data.get("sha256", "")
        ).lower()

    if not expected_executable:
        expected_executable = str(
            process_data.get("executable", "")
        )

    # Validation PID
    if not pid.isdigit():
        log(
            f"KILL_PROCESS_ERROR reason=invalid_pid "
            f"pid={pid}"
        )
        return 1

    pid_int = int(pid)

    if pid_int <= 1:
        log(
            f"KILL_PROCESS_ERROR reason=protected_pid "
            f"pid={pid}"
        )
        return 1

    # Validation SHA256
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
        log(
            f"KILL_PROCESS_ERROR reason=invalid_sha256 "
            f"pid={pid}"
        )
        return 1

    proc_exe = f"/proc/{pid}/exe"

    if not os.path.exists(proc_exe):
        log(
            f"KILL_PROCESS_ERROR reason=process_not_found "
            f"pid={pid}"
        )
        return 1

    try:
        real_executable = os.path.realpath(proc_exe)
    except Exception as e:
        log(
            f"KILL_PROCESS_ERROR reason=exe_lookup_failed "
            f"pid={pid} error={e}"
        )
        return 1

    # Vérification chemin executable
    if expected_executable and real_executable != expected_executable:
        log(
            f"KILL_PROCESS_ERROR reason=executable_mismatch "
            f"pid={pid} "
            f"expected={expected_executable} "
            f"actual={real_executable}"
        )
        return 1

    # Vérification hash réelle du binaire
    try:
        actual_sha256 = sha256_file(real_executable)
    except Exception as e:
        log(
            f"KILL_PROCESS_ERROR reason=hash_failed "
            f"pid={pid} error={e}"
        )
        return 1

    if actual_sha256.lower() != expected_sha256.lower():
        log(
            f"KILL_PROCESS_ERROR reason=sha256_mismatch "
            f"pid={pid} "
            f"expected={expected_sha256} "
            f"actual={actual_sha256}"
        )
        return 1

    log(
        f"KILL_PROCESS_REQUEST "
        f"pid={pid} "
        f"exe={real_executable} "
        f"sha256={actual_sha256}"
    )

    # SIGTERM d'abord
    try:
        os.kill(pid_int, signal.SIGTERM)
    except ProcessLookupError:
        log(
            f"KILL_PROCESS_ERROR reason=process_disappeared "
            f"pid={pid}"
        )
        return 1
    except Exception as e:
        log(
            f"KILL_PROCESS_ERROR reason=sigterm_failed "
            f"pid={pid} error={e}"
        )
        return 1

    # Attendre jusqu'à 3 secondes
    for _ in range(30):
        if not process_exists(pid_int):
            log(
                f"KILL_PROCESS_SUCCESS "
                f"pid={pid} "
                f"exe={real_executable} "
                f"sha256={actual_sha256} "
                f"signal=SIGTERM"
            )
            return 0

        time.sleep(0.1)

    # Toujours vivant -> SIGKILL
    try:
        os.kill(pid_int, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception as e:
        log(
            f"KILL_PROCESS_ERROR reason=sigkill_failed "
            f"pid={pid} error={e}"
        )
        return 1

    time.sleep(0.2)

    if not process_exists(pid_int):
        log(
            f"KILL_PROCESS_SUCCESS "
            f"pid={pid} "
            f"exe={real_executable} "
            f"sha256={actual_sha256} "
            f"signal=SIGKILL"
        )
        return 0

    log(
        f"KILL_PROCESS_ERROR reason=process_still_running "
        f"pid={pid}"
    )

    return 1


if __name__ == "__main__":
    sys.exit(main())
