import sys
from email_parser import EmailParser
from detection_rules import detecter_anomalies
from risk_scorer import score_email
from exporters import exporter_rapport


def normaliser(data: dict) -> dict:
    headers = data.get("headers", {})
    body = data.get("body", {})
    return {
        "expediteur":     headers.get("From", ""),
        "destinataire":   headers.get("To", ""),
        "sujet":          headers.get("Subject", ""),
        "reply_to":       headers.get("Reply-To", ""),
        "corps":          body.get("text", ""),
        "corps_html":     body.get("html", ""),
        "urls":           data.get("urls", []),
        "ips":            data.get("ips", []),
        "pieces_jointes": data.get("attachments", []),
    }


def print_banners():
    print("\n" + "=" * 60) 
    print(" EML Analyser") 
    print("\n" + "=" * 60) 

def eml_analyser(file : str):
    print("Analysis in progress") 

    print("[1/4] Parsing...")
    parser = EmailParser()
    data = parser.parse(file)
    data = normaliser(data)

    print(f" Expéditeur : {data.get('expediteur', 'inconnu')}")

    # 2) DÉTECTION
    print("\n[2/4] Detecting anomalies...")

    anomalies = detecter_anomalies(data)

    if anomalies :
        for anomalie in anomalies :
            sev = anomalie.get("severite")
            desc = anomalie.get("description")
            print(f"  [{sev.upper()}] {desc}")
    else :
        print("  Aucune anomalie détectée ") 

    # 3) SCORING
    print("\n[3/4] Calculating score...")

    evaluation = score_email(anomalies)

    print(f" Score : {evaluation['score']}/100") 
    print(f" Niveau : {evaluation['niveau']}")
    
    # 4) EXPORT
    print("\n[4/4] Exporting report...") 
    rapport = exporter_rapport(data, anomalies, evaluation) 
    print(f" Rapport généré : {rapport}")



def main(): 
    print_banners() 
    
    if len(sys.argv) < 2: 
        print("Usage : python -m eml_analyser fichier.eml\n") 
        return
    
    fichier = sys.argv[1]

    try : 
        eml_analyser(fichier)
    except FileNotFoundError:
        print(f" Fichier introuvable : {fichier}")
    except Exception as e:
        print(f" Erreur : {e}")

if __name__ == "__main__":
    main()