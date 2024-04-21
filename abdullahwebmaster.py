import win32evtlog
import logging
from datetime import datetime
import json
import pandas as pd

class SIEMLogCollector:
    def __init__(self, log_source, log_count=10):
        self.log_source = log_source
        self.log_count = log_count

    def collect_logs(self):
        logs = []
        try:
            hand = win32evtlog.OpenEventLog(None, self.log_source)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)

            for idx, event in enumerate(events):
                if idx >= self.log_count:
                    break

                log_entry = {
                    "Timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "Source": self.log_source,
                    "EventID": event.EventID,
                    "TimeGenerated": datetime.utcfromtimestamp(event.TimeGenerated.timestamp()).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "EventType": event.EventType,
                    "Severity": self.get_severity(event.EventType),
                    "StringInserts": event.StringInserts,
                    "Description": self.get_description(event.EventID),
                }
                logs.append(log_entry)

            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            logging.error(f"Error collecting logs from {self.log_source}: {e}")

        # Convert the list of dictionaries to a DataFrame
        logs_df = pd.DataFrame(logs)

        return logs_df.to_dict(orient='records')

    def get_severity(self, event_type):
        return "Unknown"

    def get_description(self, event_id):
        return "No description available"

class SIEMComponent:
    def __init__(self, name, log_source, log_count=10):
        self.name = name
        self.log_collector = SIEMLogCollector(log_source, log_count)

    def run(self):
        component_logs = self.log_collector.collect_logs()

        if component_logs:
            logging.info(f"\n{self.name} Logs:")
            for log in component_logs:
                logging.info(log)
            # Save logs to file
            self.save_logs_to_file(component_logs, "all_logs.json")  # Saving in JSON format
            return component_logs
        else:
            logging.warning(f"\nNo logs found for {self.name}.")
            return []

    def save_logs_to_file(self, logs, filename):
        try:
            with open(filename, 'a') as file:
                if logs:
                    logs_json = [json.dumps(log) for log in logs]
                    file.write('\n'.join(logs_json))  # Each log entry on a new line
                    file.write('\n')  # Add newline after writing logs
                else:
                    logging.warning("No logs to write.")
            logging.info("Logs saved to file.")
        except Exception as e:
            logging.error(f"Error saving logs to file: {e}")

def write_logs_to_file(logs, filename):
    try:
        with open(filename, 'w') as file:
            if logs:
                json.dump(logs, file, indent=4)
            else:
                logging.warning("No logs to write.")
        logging.info(f"Logs saved to file: {filename}")
    except Exception as e:
        logging.error(f"Error saving logs to file: {e}")

def main():
    logging.basicConfig(level=logging.INFO)

    # Create instances of SIEM components
    system_siem = SIEMComponent("System", "System")
    application_siem = SIEMComponent("Application", "Application")
    network_siem = SIEMComponent("Network Devices", "NetworkDevices")
    servers_siem = SIEMComponent("Servers", "Servers")
    databases_siem = SIEMComponent("Databases", "Databases")
    applications_siem = SIEMComponent("Applications", "Applications")
    firewalls_siem = SIEMComponent("Firewalls", "Firewalls")
    antivirus_siem = SIEMComponent("Antivirus", "Antivirus")
    idsips_siem = SIEMComponent("IDS/IPS", "IDSIPS")

    # Run SIEM components and collect logs
    all_logs = []
    for component in [system_siem, application_siem, network_siem, servers_siem, databases_siem, applications_siem, firewalls_siem, antivirus_siem, idsips_siem]:
        all_logs.extend(component.run())

    # Write all logs to a single file
    write_logs_to_file(all_logs, "all_logs.json")

if __name__ == "__main__":
    main()
