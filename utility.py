import feedparser
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
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
        print("")

    try : 
        metrics = jsoned_response["containers"]["cna"]["metrics"][0]
        for key in metrics.keys() : 
            if "cvss" in key: 
                return metrics[key]["baseScore"]
    except (KeyError, IndexError, TypeError) as e:
        print("")
    return "Not found"

def findDesc(jsoned_response) : 
    try:
        return jsoned_response["containers"]["cna"]["descriptions"][0]["value"]
    except :
        return "Not found"
    
def findCWE(jsoned_response) : 
    problemtype = jsoned_response["containers"].get("problemTypes", {})
    if problemtype and "descriptions" in problemtype[0]:
        cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
        return cwe
    else : 
        return "Not found"


def enrich_cve(rssListe):
    enriched_cve = []

    for feed in rssListe : 
        i = 0
        for cve in feed['cves'] : 
            cve_id = cve['name']
            url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

            response = requests.get(url)
            if response.status_code == 200:
                jsoned_response = response.json()
                
                cvss_score = findCVSS_Score(jsoned_response)
                determineSeverity(cvss_score)
                desc = findDesc(jsoned_response)

                vendor = ""
                product_name = ""
                versions = []

                affected = jsoned_response["containers"]["cna"]["affected"]
                for product in affected:
                    vendor = product["vendor"]
                    product_name = product["product"]
                    versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]

                template = {
                    "Titre ANSSI" : feed["Titre"],
                    "Type" : "Avis",
                    "Date" : feed["Date"],
                    "CVE" : cve["name"],
                    "CVSS" : cvss_score,
                    "Base Severity" : determineSeverity(cvss_score),
                    "CWE" : findCWE(jsoned_response),
                    "EPSS" : "",
                    "Lien" : feed["Lien"],
                    "Description" : desc,
                    "Editeur" : vendor,
                    "Produit" : product_name,
                    "Version affectées" : versions,
                }
                enriched_cve.append(template)
            i+=1
            if i ==  1: break

    for cveUnique in enriched_cve : 

        url = f"https://api.first.org/data/v1/epss?cve={cveUnique["CVE"]}"

        response = requests.get(url)
        data = response.json()

        epss_data = data.get("data", [])
        if epss_data:
            epss_score = epss_data[0]["epss"]
            cveUnique["EPSS"] = epss_score
        else : 
            cveUnique["EPSS"] = "Not found"


    return enriched_cve


def visu(dataFrame):

    dataFrame['CVSS'] = pd.to_numeric(dataFrame['CVSS'], errors='coerce')
    dataFrame['EPSS'] = pd.to_numeric(dataFrame['EPSS'], errors='coerce')
    dataFrame['Date'] = pd.to_datetime(dataFrame['Date'], errors='coerce')

    # Supprimer les lignes contenant des valeurs manquantes
    dataFrame = dataFrame.dropna(subset=['CVSS', 'EPSS', 'Date'])

    # 1. Histogramme des scores CVSS
    plt.figure(figsize=(8, 6))
    sns.histplot(data=dataFrame, x="CVSS", bins=10, kde=True, color="blue")
    plt.title("Distribution des scores CVSS")
    plt.xlabel("Score CVSS")
    plt.ylabel("Fréquence")
    plt.show()

    # 2. Diagramme circulaire des types de vulnérabilités (CWE)
    if 'CWE' in dataFrame.columns:
        cwe_counts = dataFrame['CWE'].value_counts()
        plt.figure(figsize=(8, 8))
        cwe_counts.plot.pie(autopct='%1.1f%%', startangle=140, cmap="Set3")
        plt.title("Répartition des types de vulnérabilités (CWE)")
        plt.ylabel("")  # Cacher l'étiquette
        plt.show()

    # 3. Courbe des scores EPSS
    plt.figure(figsize=(8, 6))
    sns.lineplot(data=dataFrame, x="Date", y="EPSS", marker="o", color="red")
    plt.title("Courbe des scores EPSS")
    plt.xlabel("Date")
    plt.ylabel("Score EPSS")
    plt.show()

    # 4. Classement des éditeurs les plus affectés
    top_editors = dataFrame['Editeur'].value_counts().head(10)
    plt.figure(figsize=(10, 6))
    sns.barplot(x=top_editors.values, y=top_editors.index, palette="viridis")
    plt.title("Top 10 des éditeurs les plus affectés")
    plt.xlabel("Nombre de vulnérabilités")
    plt.ylabel("Éditeur")
    plt.show()

    # 5. Heatmap des corrélations entre CVSS et EPSS
    corr_matrix = dataFrame[['CVSS', 'EPSS']].corr()
    plt.figure(figsize=(6, 4))
    sns.heatmap(corr_matrix, annot=True, cmap="coolwarm", cbar=True)
    plt.title("Corrélation entre CVSS et EPSS")
    plt.show()

    # 6. Nuage de points entre Score CVSS et Score EPSS
    plt.figure(figsize=(8, 6))
    sns.scatterplot(data=dataFrame, x="CVSS", y="EPSS", hue="Base Severity", palette="tab10")
    plt.title("Nuage de points : CVSS vs EPSS")
    plt.xlabel("Score CVSS")
    plt.ylabel("Score EPSS")
    plt.show()

    # 7. Courbe cumulative des vulnérabilités en fonction du temps
    dataFrame['Cumulative'] = dataFrame.groupby('Date').cumcount() + 1
    plt.figure(figsize=(8, 6))
    sns.lineplot(data=dataFrame, x="Date", y="Cumulative", color="purple")
    plt.title("Évolution temporelle des vulnérabilités détectées")
    plt.xlabel("Date")
    plt.ylabel("Nombre cumulatif de vulnérabilités")
    plt.show()

    # 8. Boxplot des scores CVSS par éditeur
    top_editors_scores = dataFrame[dataFrame['Editeur'].isin(top_editors.index)]
    plt.figure(figsize=(10, 6))
    sns.boxplot(data=top_editors_scores, x="Editeur", y="CVSS", palette="Set2")
    plt.xticks(rotation=45)
    plt.title("Dispersion des scores CVSS par éditeur")
    plt.xlabel("Éditeur")
    plt.ylabel("Score CVSS")
    plt.show()

    # 9. Des visualisations pour un type défini CWE
    specific_cwe = "CWE-367"  # Exemple de CWE
    cwe_data = dataFrame[dataFrame['CWE'] == specific_cwe]
    plt.figure(figsize=(8, 6))
    sns.histplot(data=cwe_data, x="CVSS", bins=10, kde=True, color="orange")
    plt.title(f"Distribution des scores CVSS pour {specific_cwe}")
    plt.xlabel("Score CVSS")
    plt.ylabel("Fréquence")
    plt.show()

    # 10. Évolution temporelle des vulnérabilités par CWE
    plt.figure(figsize=(10, 6))
    cwe_time = dataFrame.groupby([dataFrame['Date'].dt.to_period('M'), 'CWE']).size().unstack(fill_value=0)
    cwe_time.plot.area(stacked=True, figsize=(12, 6), cmap="tab20")
    plt.title("Évolution temporelle des vulnérabilités par CWE")
    plt.xlabel("Date")
    plt.ylabel("Nombre de vulnérabilités")
    plt.show()

    # 11. Versions les plus fréquemment touchées des produits concernés
    version_counts = dataFrame['Version affectées'].value_counts().head(10)
    plt.figure(figsize=(10, 6))
    sns.barplot(x=version_counts.values, y=version_counts.index, palette="cool")
    plt.title("Top 10 des versions les plus touchées")
    plt.xlabel("Nombre de vulnérabilités")
    plt.ylabel("Version")