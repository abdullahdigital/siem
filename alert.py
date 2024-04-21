import os
import smtplib
import json
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def send_email(sender_email, sender_password, receiver_email, subject, message):
    try:
        # Connect to SMTP server
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        # Login to sender's email
        server.login(sender_email, sender_password)

        # Create email message
        email_message = f"Subject: {subject}\n\n{message}"

        # Send email
        server.sendmail(sender_email, receiver_email, email_message)
        logging.info("Email sent successfully!")

        # Quit SMTP server
        server.quit()
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def main():
    # Load environment variables
    receiver_email = os.environ.get("RECEIVER_EMAIL")
    sender_email = os.environ.get("SENDER_EMAIL")
    sender_password = os.environ.get("SENDER_PASSWORD")

    if not receiver_email or not sender_email or not sender_password:
        logging.error("Missing receiver email, sender email, or sender password.")
        return

    # Read security events from JSON file
    try:
        with open("all_security_events.json", "r") as file:
            security_events = json.load(file)
    except FileNotFoundError:
        logging.error("Security events file not found.")
        return

    # Check if there are security events
    if security_events:
        num_events = len(security_events)
        subject = f"SIEM Alert: {num_events} Security Events Detected"
        message = "Dear User,\n\n"
        message += f"We have detected {num_events} security events. Please review the attached file for details.\n\n"
        message += "Best regards,\nYour SIEM System"
        # Send email notification
        send_email(sender_email, sender_password, receiver_email, subject, message)
    else:
        logging.info("No security events detected.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
