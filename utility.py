import feedparser
import requests
import pandas as pd
import re
import json

#REQUESTING RSS FLUX 
def requestingRss(URL_AVIS) : 
    requests.packages.urllib3.disable_warnings()
    response = requests.get(URL_AVIS, verify=False)
    feed_content = response.text
    return feedparser.parse(feed_content)

#LISTING : 

def listRss(rss_feed_avis) : 
    rss_feed_list = []
    for entry in rss_feed_avis.entries:
        rss_feed_list.append({
            "Titre" : entry.title,
            "Description" : entry.description,
            "Lien" : entry.link,
            "Date" : entry.published
        })
    return rss_feed_list

#GETING CVSE :
def getCSVE(feed_list) :
    for feed in feed_list :
        url = feed['Lien'] + "json"
        response = requests.get(url)
        jsoned_response = response.json()
        feed['cves'] = jsoned_response['cves'] 

#DETERMINE SEVERITY : 
def determineSeverity(cvss_score) : 
    base_severity = ""
    if cvss_score != "Not found":
        if cvss_score >= 0 and cvss_score <= 3:
           base_severity = "Faible"
        elif cvss_score >= 4 and cvss_score <= 6:
            base_severity = "Moyenne"
        elif cvss_score >= 7 and cvss_score <= 8:
            base_severity = "Élevée"
        elif cvss_score >= 9 and cvss_score <= 10:
           base_severity = "Critique"

    return base_severity



def findCVSS_Score(jsoned_response) :

    try:
        metrics = jsoned_response["containers"]["adp"][0]["metrics"][0]
        for key in metrics.keys() : 
            if "cvss" in key : 
                return metrics[key]["baseScore"]
    except (KeyError, IndexError, TypeError) as e:
        print(f"Error in 'adp' container: {e}", end=" ")

    try : 
        metrics = jsoned_response["containers"]["cna"]["metrics"][0]
        for key in metrics.keys() : 
            if "cvss" in key: 
                return metrics[key]["baseScore"]
    except (KeyError, IndexError, TypeError) as e:
        print(f"Error in 'cna' container: {e}", end=" ")

    return "Not found"

def findDesc(jsoned_response) : 
    try:
        return jsoned_response["containers"]["cna"]["descriptions"][0]["value"]
    except :
        return "Not found"
    
def findCWE(jsoned_response) : 
    try:
        return jsoned_response["containers"]["cna"]["descriptions"][0]["value"]
    except :
        return "Not found"