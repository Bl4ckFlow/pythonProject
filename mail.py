import smtplib
from email.mime.text import MIMEText
import os


def send_email(to_email, subject, body, from_email="votre_email@gmail.com", password="mot_de_passe_application"):
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())

if __name__ == "__main__":
    send_email("destinataire@email.com", 
               "Alerte CVE critique", 
               "Mettez à jour votre serveur Apache immédiatement.")