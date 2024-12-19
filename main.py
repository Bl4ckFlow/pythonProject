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
def enrich_cve(rssListe):
    enriched_cve = []
    for feed in rss_feed_list : 
        for cve in feed['cves'] : 
            cve_id = cve['name']
            url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            response = requests.get(url)
            jsoned_response = response.json()
            enriched_cve.append(jsoned_response)
    return enriched_cve
            

#cette ligne de code prend bcp de temps a s'executer c'est normal y'a bcp de data qui entre donc je vais trouver une alternative pour ça la team pas
#de probleme eas
liste = enrich_cve(rssListe = rss_feed_list)

for item in liste : 
    print(item)


