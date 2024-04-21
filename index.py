import tkinter as tk
from tkinter import messagebox
import logging
import threading
from abdullahwebmaster import SIEMLogCollector, write_logs_to_file
from analyze import analyze_logs, write_critical_events_to_file
from alert import main as generate_alert
from search import search_logs
import json
from tkinter import simpledialog
from generate_report import generate_pdf_report


class SIEMFrontend:
    def __init__(self, root):
        self.root = root
        self.root.title("SIEM Dashboard")

        # Title label
        self.label = tk.Label(root, text="Security Information and Event Management (SIEM) Dashboard", font=("Helvetica", 16), padx=10, pady=10)
        self.label.pack()

        # Collect Logs Button
        self.collect_button = tk.Button(root, text="Collect Logs", command=self.collect_logs, font=("Helvetica", 12))
        self.collect_button.pack(pady=5)

        # Analyze Logs Button
        self.analyze_button = tk.Button(root, text="Analyze Logs", command=self.analyze_logs, font=("Helvetica", 12))
        self.analyze_button.pack(pady=5)

        # Generate Alarm Button
        self.alarm_button = tk.Button(root, text="Generate Alarm", command=self.generate_alarm, font=("Helvetica", 12))
        self.alarm_button.pack(pady=5)

        # Search Logs Button
        self.search_button = tk.Button(root, text="Search Logs", command=self.search_logs_dialog, font=("Helvetica", 12))
        self.search_button.pack(pady=5)

        # Generate Reports Button
        self.reports_button = tk.Button(root, text="Generate Reports", command=self.generate_report, font=("Helvetica", 12))
        self.reports_button.pack(pady=5)

        # Display Logs Button
        self.display_button = tk.Button(root, text="Display Logs", command=self.display_logs, font=("Helvetica", 12))
        self.display_button.pack(pady=5)

        # Quit Button
        self.quit_button = tk.Button(root, text="Quit", command=self.root.quit, font=("Helvetica", 12), bg="red", fg="white")
        self.quit_button.pack(pady=10)

    def collect_logs(self):
        # Placeholder for collecting logs
        messagebox.showinfo("Information", "Collecting logs...")
        # Invoke backend function in a separate thread
        threading.Thread(target=self.invoke_collect_logs).start()

    def invoke_collect_logs(self):
        try:
            # Define log sources
            log_sources = ["System", "Application", "NetworkDevices", "Servers", "Databases", "Applications", "Firewalls", "Antivirus", "IDSIPS"]

            # Collect logs from each source
            all_logs = []
            for source in log_sources:
                # Create instance of SIEMLogCollector for the current source
                log_collector = SIEMLogCollector(source)
                # Collect logs
                logs = log_collector.collect_logs()
                all_logs.extend(logs)

            # Write all collected logs to file
            write_logs_to_file(all_logs, "all_logs.json")

            # Display message with the number of logs collected
            messagebox.showinfo("Information", f"Logs collected successfully. Total logs: {len(all_logs)}")
            logging.info("Logs collected successfully.")
        except Exception as e:
            logging.error(f"Error collecting logs: {e}")
            messagebox.showerror("Error", f"Error collecting logs: {e}")

    def analyze_logs(self):
        try:
            # Call backend function to analyze logs
            security_events = analyze_logs()

            if not security_events:
                messagebox.showinfo("Information", "No logs to analyze.")
                return

            # Write security events to file
            write_critical_events_to_file(security_events)

            # Display message with the number of security events found
            messagebox.showinfo("Information", f"Security events analyzed successfully. Total events: {len(security_events)}")
            logging.info("Security events analyzed successfully.")
        except Exception as e:
            logging.error(f"Error analyzing logs: {e}")
            messagebox.showerror("Error", f"Error analyzing logs: {e}")

    def generate_alarm(self):
        try:
            # Call backend function to generate alarm
            generate_alert()
            messagebox.showinfo("Information", "Alarm generated successfully.")
            logging.info("Alarm generated successfully.")
        except Exception as e:
            logging.error(f"Error generating alarm: {e}")
            messagebox.showerror("Error", f"Error generating alarm: {e}")

    def search_logs_dialog(self):
        # Prompt user for search query
        query = simpledialog.askstring("Search Logs", "Enter search query:")
        if query:
            search_results = search_logs(query)
            if search_results:
                messagebox.showinfo("Search Results", f"Found {len(search_results)} search results.")
            else:
                messagebox.showinfo("Search Results", "No search results found.")


    def search_logs(self, query):
        try:
            # Call backend function to search logs
            search_results = search_logs(query)

            if not search_results:
                messagebox.showinfo("Information", "No results found for the search query.")
                return

            # Display search results in a messagebox or in a separate window
            messagebox.showinfo("Search Results", f"Search Results:\n\n{json.dumps(search_results, indent=4)}")
            logging.info("Search Results:")
            for result in search_results:
                logging.info(result)
        except Exception as e:
            logging.error(f"Error searching logs: {e}")
            messagebox.showerror("Error", f"Error searching logs: {e}")

    def generate_report(self):
        try:
            # Read critical logs from JSON file
            with open("all_security_events.json", "r") as file:
                logs = json.load(file)
        except FileNotFoundError:
            messagebox.showerror("Error", "Security events file not found.")
            return

        # Generate PDF report
        generate_pdf_report(logs)
        messagebox.showinfo("Information", "Report generated successfully.")

    def display_logs(self):
        try:
            # Read logs from the file
            with open("all_logs.json", "r") as file:
                logs = file.read()

            # Create a new window to display logs
            log_window = tk.Toplevel(self.root)
            log_window.title("Logs")

            # Create a Text widget to display logs with scrollbars
            log_text = tk.Text(log_window, wrap="word")
            log_text.pack(expand=True, fill="both")

            # Insert logs into the Text widget
            log_text.insert("1.0", logs)

            # Add scrollbars to the Text widget
            scrollbar_y = tk.Scrollbar(log_window, orient="vertical", command=log_text.yview)
            scrollbar_y.pack(side="right", fill="y")
            log_text.config(yscrollcommand=scrollbar_y.set)

            scrollbar_x = tk.Scrollbar(log_window, orient="horizontal", command=log_text.xview)
            scrollbar_x.pack(side="bottom", fill="x")
            log_text.config(xscrollcommand=scrollbar_x.set)

        except Exception as e:
            logging.error(f"Error displaying logs: {e}")
            messagebox.showerror("Error", f"Error displaying logs: {e}")

def main():
    logging.basicConfig(level=logging.INFO)

    root = tk.Tk()
    app = SIEMFrontend(root)
    root.mainloop()

if __name__ == "__main__":
    main()
