import json

class Reporter:
    def __init__(self, path):
        self.path = path
        self.findings = []

    def add(self, finding: dict):
        self.findings.append(finding)

    def generate(self):
        report = {
            "summary": {
                "total_idor": len(self.findings)
            },
            "findings": self.findings
        }

        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
