import json
import logging

def analyze_logs():
    critical_events = []
    try:
        with open("all_logs.json", "r") as file:
            logs = json.load(file)
            if not isinstance(logs, list):
                raise TypeError("Logs must be a list")
            for idx, log in enumerate(logs):
                if not isinstance(log, dict):
                    raise TypeError(f"Log entry at index {idx} is not a dictionary: {log}")
                if log.get("EventID") == 4625:
                    critical_events.append(log)
                elif log.get("EventType") == 1 and "Unauthorized access" in log.get("Description", ""):
                    critical_events.append(log)
                elif log.get("EventType") == 2 and "Malware detected" in log.get("Description", ""):
                    critical_events.append(log)
                elif log.get("StringInserts") is not None and any("IP" in log.get("StringInserts", []) for keyword in ["Source", "Destination"]):
                    critical_events.append(log)
                elif log.get("EventType") == 3 and "Privilege escalation" in log.get("Description", ""):
                    critical_events.append(log)
                elif log.get("EventID") in [4740, 1000]:
                    critical_events.append(log)
    except FileNotFoundError:
        logging.error("Log file not found.")
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}")
    except TypeError as e:
        logging.error(f"Error processing logs: {e}")

    if not critical_events:
        logging.warning("No critical events found.")

    return critical_events

def write_critical_events_to_file(critical_events):
    try:
        with open("all_security_events.json", 'w') as file:
            json.dump(critical_events, file, indent=4)
        logging.info("Critical events saved to file: all_security_events.json")
    except Exception as e:
        logging.error(f"Error saving critical events to file: {e}")

def main():
    logging.basicConfig(level=logging.INFO)

    # Analyze logs
    critical_events = analyze_logs()

    # Write critical events to file
    write_critical_events_to_file(critical_events)

if __name__ == "__main__":
    main()
