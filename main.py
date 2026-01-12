import yaml

from auth.session import Session
from core.bruteforce import Bruteforcer
from core.analyzer import Analyzer
from core.validator import Validator
from core.reporter import Reporter

from core.diff import DiffEngine
from core.severity import SeverityEngine
from core.timeline import Timeline


def main():
    with open("config.yaml") as f:
        cfg = yaml.safe_load(f)

    session = Session(
        cfg["target"]["base_url"],
        cfg["auth"]["token"]
    )

    bruteforce = Bruteforcer(*cfg["target"]["id_range"])
    analyzer = Analyzer(cfg["target"]["endpoint"])
    validator = Validator(
        cfg["detection"]["ownership_field"],
        cfg["detection"]["current_user_id"]
    )

    reporter = Reporter(cfg["output"]["report_file"])
    diff_engine = DiffEngine()
    severity_engine = SeverityEngine()
    timeline = Timeline()

    print("[*] Starting IDOR scan")
    timeline.add("Scan started")

    own_object = None

    for obj_id in bruteforce.ids():
        path = analyzer.build_path(obj_id)
        timeline.add(f"GET {path}")

        resp = session.get(path)
        if resp.status_code != 200:
            continue

        data = resp.json()

        # Первый объект считаем «своим»
        if own_object is None:
            own_object = data
            timeline.add(f"Baseline object captured (ID {obj_id})")
            continue

        # Проверяем IDOR
        if validator.is_idor(data):
            diff = diff_engine.diff(own_object, data)
            severity = severity_engine.calculate(
                "Horizontal",
                list(diff.keys())
            )

            print(f"[!] IDOR FOUND on object {obj_id}")

            reporter.add({
                "object_id": obj_id,
                "idor_type": "Horizontal",
                "owner_id": data.get("owner_id"),
                "diff": diff,
                "severity": severity,
                "timeline": timeline.dump()
            })

    reporter.generate()
    print("[+] Scan finished")


if __name__ == "__main__":
    main()
