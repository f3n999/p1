def exporter_rapport(donnees_email: dict, anomalies: list, evaluation: dict, fichier: str = 'rapport.txt'):

    with open(fichier, 'w', encoding='utf-8') as f:
        # En-tête
        f.write("=" * 60 + "\n")
        f.write("RAPPORT D'ANALYSE EMAIL\n")
        f.write("=" * 60 + "\n\n")
        
        # Infos email
        f.write("INFORMATIONS\n")
        f.write("-" * 60 + "\n")
        f.write(f"De      : {donnees_email.get('expediteur', 'N/A')}\n")
        f.write(f"À       : {donnees_email.get('destinataire', 'N/A')}\n")
        f.write(f"Sujet   : {donnees_email.get('sujet', 'N/A')}\n\n")
        
        # Score
        f.write("ÉVALUATION\n")
        f.write("-" * 60 + "\n")
        f.write(f"Score   : {evaluation.get('score', 0)}/100\n")
        f.write(f"Niveau  : {evaluation.get('niveau', 'inconnu').upper()}\n\n")
        
        # Anomalies
        f.write(f"ANOMALIES ({len(anomalies)})\n")
        f.write("-" * 60 + "\n")
        if anomalies:
            for i, anom in enumerate(anomalies, 1):
                f.write(f"{i}. [{anom.get('severite', '?')}] {anom.get('description', '')}\n")
        else:
            f.write("Aucune anomalie détectée.\n")
        
        f.write("\n" + "=" * 60 + "\n")
    
    return fichier
