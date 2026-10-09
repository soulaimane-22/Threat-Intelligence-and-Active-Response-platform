import sys
import os
import json
import shutil
import datetime
import uuid

LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

MONITORED_DIRECTORY = r"C:\malware"
QUARANTINE_DIRECTORY = r"C:\Wazuh-Quarantine"


def write_log(message):
    timestamp = datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(
            f"{timestamp} quarantine-file.exe: {message}\n"
        )


def get_file_path(message):
    parameters = message.get("parameters", {})

    # Case 1: Manual/API Active Response
    # n8n arguments arrive in extra_args
    extra_args = parameters.get("extra_args", [])

    if extra_args:
        value = extra_args[0]

        if value and value != "-":
            return value

    # Case 2: Active Response triggered from a FIM alert
    alert = parameters.get("alert", {})
    syscheck = alert.get("syscheck", {})

    return syscheck.get("path")


def is_allowed_path(file_path):
    try:
        monitored = os.path.normcase(
            os.path.abspath(MONITORED_DIRECTORY)
        )

        target = os.path.normcase(
            os.path.abspath(file_path)
        )

        return os.path.commonpath(
            [monitored, target]
        ) == monitored

    except ValueError:
        return False


def main():

    try:
        # Wazuh Active Response sends one JSON message through STDIN
        input_line = sys.stdin.readline()

        if not input_line:
            write_log("ERROR: No JSON received on STDIN")
            return 1

        write_log(f"INPUT: {input_line.strip()}")

        try:
            message = json.loads(input_line)

        except json.JSONDecodeError as error:
            write_log(f"ERROR: Invalid JSON: {error}")
            return 1

        # Stateless Active Response: only execute the add command
        command = message.get("command")

        if command != "add":
            write_log(
                f"IGNORED: command={command}"
            )
            return 0

        file_path = get_file_path(message)

        if not file_path:
            write_log(
                "ERROR: No path found in "
                "parameters.extra_args[0] or "
                "parameters.alert.syscheck.path"
            )
            return 1

        file_path = os.path.abspath(file_path)

        write_log(
            f"Requested quarantine: {file_path}"
        )

        # Only quarantine files under C:\malware
        if not is_allowed_path(file_path):
            write_log(
                f"ERROR: Path outside C:\\malware: {file_path}"
            )
            return 1

        if not os.path.isfile(file_path):
            write_log(
                f"ERROR: File does not exist: {file_path}"
            )
            return 1

        os.makedirs(
            QUARANTINE_DIRECTORY,
            exist_ok=True
        )

        original_name = os.path.basename(file_path)

        timestamp = datetime.datetime.now().strftime(
            "%Y%m%d-%H%M%S"
        )

        unique_id = uuid.uuid4().hex[:8]

        destination_name = (
            f"{timestamp}_{unique_id}_{original_name}"
        )

        destination = os.path.join(
            QUARANTINE_DIRECTORY,
            destination_name
        )

        shutil.move(
            file_path,
            destination
        )

        write_log(
            f"QUARANTINE_SUCCESS source={file_path} destination={destination}"
        )

        return 0

    except Exception as error:
        write_log(
            f"QUARANTINE_ERROR file={file_path} error={error}"
        )

        return 1


if __name__ == "__main__":
    sys.exit(main())
