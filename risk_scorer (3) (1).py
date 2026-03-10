def compute_raw_score(triggered_rules):

    raw_score = 0

    for rule in triggered_rules :
        raw_score += rule["score"]
    
    return raw_score


def normalize_score(raw_score):

    if raw_score > 100 : 
        return 100
    elif raw_score < 0 :
        return 0
    else : 
        return raw_score


def determine_risk_level(final_score):

    if 0 <= final_score <= 30: 
        return 'low' 
    elif 30 < final_score <= 60: 
        return 'medium' 
    elif 60 < final_score <= 100: 
        return 'high'


def score_email(triggered_rules):

    raw_score = compute_raw_score(triggered_rules)

    final_score = normalize_score(raw_score)

    risk_level = determine_risk_level(final_score)

    return {
        "score" : final_score,
        "niveau" : risk_level,
        "rules_triggered" : triggered_rules
    }
