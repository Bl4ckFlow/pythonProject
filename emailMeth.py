import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email(to_email, subject, body):
    from_email = "pythongrp11@gmail.com"
    password = "sako advd mkel kblr"
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Envoi de l'email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()
        print(f"Email envoyé avec succès à {to_email}.")
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")
    
send_email("monretour29@gmail.com", "Alerte CVE", "cc" )
