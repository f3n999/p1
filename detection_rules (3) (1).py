import re

SCORES = {'haute': 40, 'moyenne': 20, 'faible': 5}


class MoteurDetection:
    
    def __init__(self):
        self.anomalies = []
    
    def analyser_email(self, donnees_email: dict) -> list:
        self.anomalies = []
        self._verifier_expediteur(donnees_email)
        self._detecter_urls_suspectes(donnees_email)
        self._detecter_mots_cles_phishing(donnees_email)
        return self.anomalies
    
    def _ajouter_anomalie(self, severite: str, description: str):
        self.anomalies.append({
            'severite': severite,
            'description': description,
            'score': SCORES.get(severite, 0)
        })
    
    def _verifier_expediteur(self, donnees: dict):
        expediteur = donnees.get('expediteur', '')
        reply_to = donnees.get('reply_to', '')
        
        match_domaine = re.search(r'@([\w\.-]+)', expediteur)
        
        if match_domaine:
            domaine = match_domaine.group(1).lower()
            if domaine.count('-') > 2 or sum(c.isdigit() for c in domaine) > 3:
                self._ajouter_anomalie('moyenne', f"Domaine suspect : {domaine}")
        
        if reply_to and reply_to != expediteur:
            self._ajouter_anomalie('haute', f"Reply-To différent : {reply_to}")
    
    def _detecter_urls_suspectes(self, donnees: dict):
        corps = donnees.get('corps', '')
        urls_extraites = donnees.get('urls', [])
        urls_regex = re.findall(r'https?://[^\s<>"]+', corps, re.IGNORECASE)
        urls = list(set(urls_extraites + urls_regex))
        
        for url in urls:
            if re.search(r'(bit\.ly|tinyurl|t\.co|goo\.gl)', url, re.IGNORECASE):
                self._ajouter_anomalie('moyenne', f"URL raccourcie : {url}")
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                self._ajouter_anomalie('haute', f"URL avec IP : {url}")
    
    def _detecter_mots_cles_phishing(self, donnees: dict):
        sujet = donnees.get('sujet', '').lower()
        corps = donnees.get('corps', '').lower()
        corps_html = donnees.get('corps_html', '').lower()
        texte = f"{sujet} {corps} {corps_html}"
        
        mots_suspects = [
            'urgent', 'action requise', 'immédiatement', 'dernier délai',
            'expire bientôt', 'dans les 24 heures', 'répondez vite',
            'ne tardez pas', 'temps limité', 'agissez maintenant',
            'sans délai', 'avant minuit', 'dernière chance',
            'plus que quelques heures', 'dépêchez-vous',
            'compte bloqué', 'compte suspendu', 'accès refusé',
            'activité suspecte', 'connexion inhabituelle', 'accès limité',
            'votre compte sera fermé', 'sécurité compromise', 'compte désactivé',
            'tentative de connexion', 'accès non autorisé', 'compte piraté',
            'violation de sécurité', 'compte expiré', 'suspension imminente',
            'mot de passe', 'identifiants', 'coordonnées bancaires',
            'numéro de carte', 'code secret', 'code pin',
            'informations personnelles', 'données confidentielles',
            'numéro de sécurité sociale', 'date de naissance',
            'adresse complète', 'pièce d identité', 'passeport',
            'rib bancaire', 'cvv', 'cryptogramme',
            'cliquez ici', 'cliquez maintenant', 'accédez ici',
            'vérifiez', 'confirmer', 'valider maintenant',
            'mettre à jour', 'réinitialisez', 'connectez-vous ici',
            'accéder à mon compte', 'suivez ce lien', 'ouvrir le document',
            'téléchargez maintenant', 'installer maintenant',
            'gagnant', 'vous avez gagné', 'félicitations',
            'cadeau gratuit', 'offre exclusive', 'sélectionné',
            'tirage au sort', 'loterie', 'récompense',
            'bonus exceptionnel', 'prix à récupérer', 'lot à retirer',
            'vous êtes l heureux gagnant', 'offre spéciale réservée',
            'iphone gratuit', 'bon cadeau', 'chèque cadeau',
            'virement urgent', 'transfert bancaire', 'remboursement en attente',
            'facture impayée', 'paiement refusé', 'régulariser',
            'dette en cours', 'huissier', 'mise en demeure',
            'recouvrement', 'saisie', 'pénalités',
            'trop perçu', 'avoir disponible', 'crédit offert',
            'investissement garanti', 'rendement exceptionnel',
            'service client', 'support technique', 'votre banque',
            'administration fiscale', 'impôts', 'amende',
            'police nationale', 'gendarmerie', 'interpol',
            'ministère', 'préfecture', 'sécurité sociale',
            'caisse d assurance', 'mutuelle', 'assurance maladie',
            'amazon', 'paypal', 'apple', 'microsoft', 'google',
            'la poste', 'chronopost', 'colissimo', 'dhl', 'fedex',
            'ouvrez la pièce jointe', 'voir le document joint',
            'facture en pièce jointe', 'votre colis', 'suivre ma livraison',
            'document important joint', 'fichier partagé',
            'cher utilisateur', 'cher client', 'cher abonné',
            'nous avons remarqué', 'nous avons détecté',
            'votre participation', 'félicitation', 'vous bénéficiez',
            'profitez maintenant', 'ne manquez pas',
        ]
        
        mots_trouves = []
        
        for mot in mots_suspects:
            if re.search(rf'\b{re.escape(mot)}\b', texte, re.IGNORECASE):
                mots_trouves.append(mot)
        
        if len(mots_trouves) >= 2:
            self._ajouter_anomalie('haute', f"Mots-clés phishing : {', '.join(mots_trouves)}")


def detecter_anomalies(donnees_email: dict) -> list:
    moteur = MoteurDetection()
    return moteur.analyser_email(donnees_email)
