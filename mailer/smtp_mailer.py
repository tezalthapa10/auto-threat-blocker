import os
import smtplib
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
print("dotenv_path", dotenv_path)
load_dotenv(dotenv_path)


class Mailer:
    def send_email(self, subject, message):
        receiver_email = os.getenv("TO_EMAIL")
        sender_email = os.getenv("FROM_EMAIL")

        print("************sender email", sender_email)
        # Set up the MIME
        email = MIMEMultipart()
        email['From'] = os.getenv("FROM_EMAIL")
        email['To'] = receiver_email
        email['Subject'] = subject
        sender_password = os.getenv('SENDER_PASSWORD')
        
        # Attach the message to the MIME
        email.attach(MIMEText(message, 'plain'))
        
        try:
            # Connect to the Gmail SMTP server
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()  # Secure the connection
            
            # Login to the sender email
            server.login(sender_email, sender_password)
            
            # Send the email
            text = email.as_string()
            server.sendmail(sender_email, receiver_email, text)
            
            print("Email sent successfully!")
            
        except Exception as e:
            print(f"Error sending email: {e}")
            
        finally:
            server.quit()  # Close the connection


