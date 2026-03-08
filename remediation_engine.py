





print("🛠️  Remediation Engine ready.")

REMEDIATION_RULES = {
    "Insecure Protocol": "Enable HTTPS and redirect all HTTP traffic to HTTPS."
}

def generate_remediation(vulnerabilities: list):
    suggestions = []

    for v in vulnerabilities:
        rule = REMEDIATION_RULES.get(v.get("type"))
        if rule:
            suggestions.append(rule)

    return suggestions
