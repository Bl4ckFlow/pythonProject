import utility as utl
import emailMeth as eml

#GLOBAL VAR
URL_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"

#REQUESTING RSS_Flux
rss_feed_avis = utl.requestingRss(URL_AVIS)
rss_feed_list = utl.listRss(rss_feed_avis)

#GETING CVSE :
utl.getCSVE(rss_feed_list)

"""
df = utl.pd.DataFrame(rss_feed_list)
df.to_csv("rss_feed_with_cves.csv", index=False)
"""

#ENRICHISSEMENT CVE 
enrichedCVE= utl.enrich_cve(rss_feed_list)

dataFrame = utl.pd.DataFrame(enrichedCVE)

for i in enrichedCVE :
    for key, value in i.items():
        print(key,": " ,value)
    print('\n\n\n')


#Interprétation et Visualisation
#utl.visu(dataFrame)

#Email

for item in enrichedCVE : 
    if item["CVSS"] >= 7 :
        item_str = utl.json.dumps(item, indent=4)
        eml.send_email("monretour29@gmail.com", "Alerte CVE", item_str )

