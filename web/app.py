import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request
import yaml

from auth.session import Session
from core.bruteforce import Bruteforcer
from core.analyzer import Analyzer
from core.validator import Validator
from core.advanced_detector import AdvancedIDORDetector, DetectionStrategy

from core.diff import DiffEngine
from core.severity import SeverityEngine
from core.timeline import Timeline

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    report = None
    logs = []
    progress = {}
    log_summary = {}

    if request.method == "POST":
        # Получаем данные из формы
        target_url = request.form.get('target_url', 'http://127.0.0.1:5000')
        endpoint = request.form.get('endpoint', '/api/orders/{id}')
        id_range_start = int(request.form.get('id_range_start', 1))
        id_range_end = int(request.form.get('id_range_end', 10))
        auth_token = request.form.get('auth_token', 'token_user1')
        ownership_field = request.form.get('ownership_field', 'owner_id')
        current_user_id = int(request.form.get('current_user_id', 1))

        # Создаем продвинутый детектор
        detector = AdvancedIDORDetector(lambda token: Session(target_url, token))
        
        # Конфигурируем детектор
        detector.configure({
            'enable_pattern_matching': True,
            'enable_heuristic_analysis': True,
            'enable_differential_analysis': False,  # Пока отключаем, требует нескольких контекстов
            'enable_blind_detection': True,
            'confidence_threshold': 0.3,  # Понизим порог
            'risk_threshold': 0.3
        })

        # Запускаем комплексное сканирование
        import asyncio
        
        async def run_scan():
            return await detector.comprehensive_scan(
                endpoint,
                list(range(id_range_start, id_range_end + 1)),
                {
                    'ownership_field': ownership_field,
                    'current_user_id': current_user_id,
                    'auth_token': auth_token
                }
            )
        
        # Запускаем асинхронное сканирование
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        advanced_results = loop.run_until_complete(run_scan())
        loop.close()
        
        # Генерируем отчет
        report = detector.generate_comprehensive_report()
        
        # Получаем логи процесса
        logs = detector.logger.get_logs()
        progress = detector.logger.get_progress()
        log_summary = detector.logger.get_summary()
        
        # Отладочный вывод
        print(f"DEBUG: advanced_results = {advanced_results}")
        print(f"DEBUG: detection_results = {detector.detection_results}")
        print(f"DEBUG: report = {report}")
        
        # Конвертируем результаты для отображения
        for result in advanced_results:
            results.append({
                "id": result.object_id,
                "strategies": result.strategies_used,
                "vulnerabilities": result.vulnerabilities,
                "confidence": result.overall_confidence,
                "risk_score": result.risk_score,
                "recommendations": result.recommendations[:3],  # Показываем топ-3 рекомендации
                "evidence_summary": {k: len(v) if isinstance(v, dict) else str(v)[:100] 
                                   for k, v in result.evidence.items()}
            })

    return render_template("index.html", results=results, report=report, logs=logs, progress=progress, log_summary=log_summary)


if __name__ == "__main__":
    app.run(port=8000, debug=True)
