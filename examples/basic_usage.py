#!/usr/bin/env python3
"""
Пример базового использования IDOR Pwn детектора
Автор: Смирных Павел Ильич, 2026
"""

import asyncio
import sys
import os

# Добавляем корень проекта в путь
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.advanced_detector import AdvancedIDORDetector
from auth.session import Session


async def basic_scan_example():
    """Пример базового сканирования"""
    print("🚀 Запуск базового сканирования IDOR Pwn")
    print("=" * 50)
    
    # Создание детектора
    detector = AdvancedIDORDetector(
        lambda token: Session("http://127.0.0.1:5000", token)
    )
    
    # Конфигурация детектора
    detector.configure({
        'enable_pattern_matching': True,
        'enable_heuristic_analysis': True,
        'enable_differential_analysis': False,  # Требует нескольких контекстов
        'enable_blind_detection': True,
        'confidence_threshold': 0.3,
        'risk_threshold': 0.3
    })
    
    print("⚙️ Детектор сконфигурирован")
    
    # Запуск сканирования
    print("🔍 Начинаем сканирование...")
    
    try:
        results = await detector.comprehensive_scan(
            endpoint_template="/api/orders/{id}",
            object_ids=list(range(1, 11)),
            context={
                'ownership_field': 'owner_id',
                'current_user_id': 1,
                'auth_token': '1'
            }
        )
        
        print(f"✅ Сканирование завершено. Найдено {len(results)} объектов с уязвимостями")
        
        # Генерация отчета
        report = detector.generate_comprehensive_report()
        
        print("\n📊 Сводка результатов:")
        print(f"   Всего уязвимостей: {report['summary']['total_vulnerabilities']}")
        print(f"   Средняя уверенность: {report['summary']['average_confidence']:.2f}")
        print(f"   Средний риск: {report['summary']['average_risk_score']:.2f}")
        print(f"   Высокий риск: {report['summary']['high_risk_count']}")
        
        # Детальные результаты
        print("\n🔍 Детальные результаты:")
        for result in results:
            print(f"\n📌 Объект #{result.object_id}:")
            print(f"   Стратегии: {', '.join(result.strategies_used)}")
            print(f"   Уверенность: {result.overall_confidence:.2f}")
            print(f"   Риск: {result.risk_score:.2f}")
            
            if result.vulnerabilities:
                print("   Уязвимости:")
                for vuln in result.vulnerabilities:
                    print(f"     - {vuln.get('type', 'unknown')} (уверенность: {vuln.get('confidence', 0):.2f})")
            
            if result.recommendations:
                print("   Рекомендации:")
                for rec in result.recommendations[:3]:  # Показываем топ-3
                    print(f"     • {rec}")
        
        # Топ рекомендации
        if report.get('top_recommendations'):
            print("\n🎯 Главные рекомендации:")
            for i, rec in enumerate(report['top_recommendations'], 1):
                print(f"   {i}. {rec}")
        
    except Exception as e:
        print(f"❌ Ошибка при сканировании: {e}")
        return False
    
    return True


async def custom_scan_example():
    """Пример сканирования с кастомными параметрами"""
    print("\n🎯 Пример кастомного сканирования")
    print("=" * 50)
    
    # Создание детектора с кастомной сессией
    detector = AdvancedIDORDetector(
        lambda token: Session("http://127.0.0.1:5000", token)
    )
    
    # Кастомная конфигурация
    detector.configure({
        'enable_pattern_matching': True,
        'enable_heuristic_analysis': True,
        'enable_blind_detection': True,
        'confidence_threshold': 0.5,  # Повышенный порог
        'risk_threshold': 0.6
    })
    
    # Сканирование с большим диапазоном
    results = await detector.comprehensive_scan(
        endpoint_template="/api/orders/{id}",
        object_ids=list(range(1, 51)),  # Расширенный диапазон
        context={
            'ownership_field': 'owner_id',
            'current_user_id': 2,  # Другой пользователь
            'auth_token': '2'
        }
    )
    
    # Анализ результатов
    high_risk_objects = [r for r in results if r.risk_score >= 0.6]
    
    print(f"📊 Результаты кастомного сканирования:")
    print(f"   Всего объектов: {len(results)}")
    print(f"   Объектов с высоким риском: {len(high_risk_objects)}")
    print(f"   Процент уязвимых: {len(results) / 50 * 100:.1f}%")
    
    return True


def pattern_analysis_example():
    """Пример анализа конкретных паттернов"""
    print("\n🔍 Пример анализа паттернов")
    print("=" * 50)
    
    from core.patterns import PatternMatcher, IDORType
    
    # Создание матчера паттернов
    matcher = PatternMatcher()
    
    # Тестовые данные
    current_data = {
        "id": 2,
        "owner_id": 101,
        "item": "iPhone 15",
        "price": 120000
    }
    
    baseline_data = {
        "id": 1,
        "owner_id": 100,
        "item": "MacBook Pro",
        "price": 250000
    }
    
    context = {
        'ownership_field': 'owner_id',
        'current_user_id': 1
    }
    
    # Анализ паттернов
    results = matcher.analyze(current_data, baseline_data, context)
    
    print(f"🔍 Результаты анализа паттернов:")
    for result in results:
        print(f"   Тип: {result['type']}")
        print(f"   Уверенность: {result['confidence']}")
        print(f"   Описание: {result['description']}")
        if 'details' in result:
            print(f"   Детали: {result['details']}")
        print()
    
    return True


def logging_example():
    """Пример использования системы логирования"""
    print("\n📝 Пример системы логирования")
    print("=" * 50)
    
    from core.logger import ScanLogger
    
    # Создание логгера
    logger = ScanLogger()
    
    # Имитация процесса сканирования
    logger.start_scan(10)
    logger.info("🚀 Начинаем сканирование 10 объектов")
    
    for i in range(1, 6):
        logger.start_object(i)
        logger.request_made('GET', f'/api/orders/{i}', 200, 0.05)
        
        if i in [2, 4]:
            logger.vulnerability_found(i, 'горизонтальный', 0.8)
            logger.finish_object(i, 1)
        else:
            logger.finish_object(i, 0)
    
    logger.finish_scan()
    
    # Получение логов
    logs = logger.get_logs()
    progress = logger.get_progress()
    summary = logger.get_summary()
    
    print(f"📊 Статистика логирования:")
    print(f"   Всего записей: {len(logs)}")
    print(f"   Прогресс: {progress['progress_percentage']:.1f}%")
    print(f"   Время: {progress['elapsed_time']:.2f} сек")
    print(f"   Уровни логов: {summary['level_counts']}")
    
    return True


async def main():
    """Главная функция"""
    print("🛡️ IDOR Pwn - Примеры использования")
    print("Автор: Смирных Павел Ильич, 2026")
    print("=" * 60)
    
    examples = [
        ("Базовое сканирование", basic_scan_example),
        ("Кастомное сканирование", custom_scan_example),
        ("Анализ паттернов", pattern_analysis_example),
        ("Система логирования", logging_example)
    ]
    
    results = []
    
    for name, func in examples:
        print(f"\n📍 Запуск примера: {name}")
        try:
            if asyncio.iscoroutinefunction(func):
                result = await func()
            else:
                result = func()
            results.append((name, result))
            print(f"✅ Пример '{name}' завершен {'успешно' if result else 'с ошибкой'}")
        except Exception as e:
            print(f"❌ Ошибка в примере '{name}': {e}")
            results.append((name, False))
    
    # Итоги
    print("\n" + "=" * 60)
    print("📊 Итоги выполнения примеров:")
    
    successful = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅" if result else "❌"
        print(f"   {status} {name}")
    
    print(f"\n🎯 Успешно выполнено: {successful}/{total} примеров")
    
    if successful == total:
        print("🎉 Все примеры выполнены успешно!")
    else:
        print("⚠️ Некоторые примеры завершились с ошибками")


if __name__ == "__main__":
    # Запуск примеров
    asyncio.run(main())
