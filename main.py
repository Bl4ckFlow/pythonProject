import utility as utl

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

#Connexion API CVE
def enrich_cve(rssListe):
    enriched_cve = []
    for feed in rss_feed_list : 
        i = 0
        for cve in feed['cves'] : 
            print(cve["name"], end=" ")
            cve_id = cve['name']
            url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

            response = utl.requests.get(url)
            if response.status_code == 200:
                jsoned_response = response.json()
                
                cvss_score = utl.findCVSS_Score(jsoned_response)
                utl.determineSeverity(cvss_score)
                desc = utl.findDesc(jsoned_response)

                template = {
                    "Titre du bulletin (ANSSI)" : feed["Titre"],
                    "Type de bulletin" : "",
                    "Date de publication" : feed["Date"],
                    "Identifiant CVE" : cve["name"],
                    "Score CVSS" : cvss_score,
                    "Base Severity" : utl.determineSeverity(cvss_score),
                    "Description" : desc,
                    "Type CWE" : "",

                }
                enriched_cve.append(template)
        i+=1
        if i == 0 : break
    return enriched_cve

enrichedCVE= enrich_cve(rss_feed_list)


for i in enrichedCVE :
    for key, value in i.items():
        print(key,": " ,value)
    print('\n\n\n')

# enriched_data = enrich_cve(rss_feed_list)

"""
with open("enrichementOutput.txt", "w") as file:
    for index, item in enumerate(enriched_data):
        json.dump(item, file, indent=4)  # Write the JSON object
        file.write("\n\n")
"""