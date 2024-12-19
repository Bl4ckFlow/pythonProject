import feedparser
import requests
import re
import json

#GLOBAL VAR
URL_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed"


#REQUESTING RSS_Flux
rss_feed_avis = feedparser.parse(URL_AVIS)
rss_feed_list = []

for entry in rss_feed_avis.entries:
    rss_feed_list.append({
        "Titre " : entry.title,
        "Description:" : entry.description,
        "Lien" : entry.link,
        "Date" : entry.published
    })


#GETING CVSE :
def getCSVE(feed_list) :
    csve_list = []
    i = 0
    for feed in feed_list :
        url = feed['Lien'] + "json"
        csve_list.append(str(url))
        response = requests.get(url)
        jsoned_response = response.json()

        
        feed['cves'] = jsoned_response['cves']

        

getCSVE(rss_feed_list)


"""
for item in rss_feed_list : 
    for k,v in item.items() : 
        print(k,v,)
    print('\n\n\n\n')
"""

#ENRICHISSEMENT CVE 



#Génération d'Alertes et Notifications Email

from mail import send_email

critical_vuln = True  
if critical_vuln:
    subject = "Alerte CVE critique détectée"
    body = "Une vulnérabilité critique vient d'être détectée. Veuillez prendre les mesures nécessaires."
    send_email("admin@exemple.com", subject, body)
