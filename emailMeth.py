import smtplib
from email.mime.text import MIMEText

def send_email(to_email, subject, body):
    from_email = "pyyhongrp11@gmail.com"
    password = "Chadiraoufilyess"
    try:
        msg = MIMEText(body)
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(from_email, password)
            server.sendmail(from_email, to_email, msg.as_string())

        return f"Email successfully sent to {to_email}"
    except Exception as e:
        return f"Failed to send email. Error: {e}"
