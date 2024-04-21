from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

import json

def generate_pdf_report(logs):
    doc = SimpleDocTemplate("SIEM_Critical_Events_Report.pdf", pagesize=letter)
    styles = getSampleStyleSheet()

    content = []

    # Add title
    title = "SIEM Critical Events Report"
    content.append(Paragraph(title, styles["Title"]))
    content.append(Spacer(1, 12))

    # Add introduction
    introduction = "Dear Abdullah love,\n\nI am pleased to present the SIEM Critical Events Report, detailing recent security incidents detected by our Security Information and Event Management (SIEM) system. This report provides insights into critical events such as failed login attempts, malware activity, unauthorized access, and other security-related incidents."
    content.append(Paragraph(introduction, styles["Normal"]))
    content.append(Spacer(1, 12))

    # Add section headers for each critical event
    for i, log in enumerate(logs, start=1):
        content.append(Paragraph(f"Event {i}: {log['EventID']}", styles["Heading2"]))
        content.append(Paragraph(f"Timestamp: {log['Timestamp']}", styles["Normal"]))
        content.append(Paragraph(f"Source: {log['Source']}", styles["Normal"]))
        content.append(Paragraph(f"Description: {log['Description']}", styles["Normal"]))
        content.append(Paragraph(f"Severity: {log['Severity']}", styles["Normal"]))
        content.append(Paragraph(f"Additional Information: {', '.join(log['StringInserts'])}", styles["Normal"]))
        content.append(Spacer(1, 12))

        #Conclusion Title
    title2 = "SIEM Critical Events Report"
    content.append(Paragraph(title2, styles["Title"]))
    content.append(Spacer(1, 12))

    # Add conclusion
    conclusion = "In conclusion, our SIEM system has played a vital role in identifying and mitigating potential security threats. By closely monitoring critical events and promptly responding to incidents, we can strengthen our organization's security posture and safeguard our assets. Thank you for your attention to this report."
    content.append(Paragraph(conclusion, styles["Normal"]))

    # Add signature
    signature = "Sincerely, <br /> Abdullah's Lover"
    content.append(Paragraph(signature, styles["Normal"]))

    # Build the PDF document
    doc.build(content)

def main():
    # Read critical logs from JSON file
    try:
        with open("all_security_events.json", "r") as file:
            logs = json.load(file)
    except FileNotFoundError:
        print("Security events file not found.")
        return

    # Generate PDF report
    generate_pdf_report(logs)

if __name__ == "__main__":
    main()
