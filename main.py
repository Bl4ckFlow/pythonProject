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

#

#GETING CVSE :
def getCSVE(feed_list) :
    csve_list = []
    i = 0
    for feed in feed_list :
        url = feed['Lien'] + "json"
        csve_list.append(str(url))
        response = requests.get(url)

        if i == 1 : 
                    break
        
        jsoned_response = response.json()
        for key, val in jsoned_response.items() : 
            print(key, val)

        i += 1
        

getCSVE(rss_feed_list)