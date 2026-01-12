class SeverityEngine:
    def calculate(self, idor_type: str, sensitive_fields: list):
        score = 0

        if idor_type == "Horizontal":
            score += 6

        if sensitive_fields:
            score += 2

        score += 1  # no auth bypass assumed

        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "cvss": round(score, 1),
            "level": level
        }
