"""
Продвинутый детектор IDOR уязвимостей
Объединяет все техники детекции в единый инструмент
"""
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .patterns import PatternMatcher, IDORType
from .heuristic import HeuristicAnalyzer, ResponseMetrics
from .differential import DifferentialAnalyzer, AccessLevel, AccessContext
from .blind_detector import BlindIDORDetector
from .logger import ScanLogger


class DetectionStrategy(Enum):
    PATTERN_BASED = "pattern_based"
    HEURISTIC = "heuristic"
    DIFFERENTIAL = "differential"
    BLIND = "blind"
    COMPREHENSIVE = "comprehensive"


@dataclass
class AdvancedDetectionResult:
    """Результат продвинутой детекции"""
    object_id: int
    strategies_used: List[str]
    vulnerabilities: List[Dict[str, Any]]
    overall_confidence: float
    risk_score: float
    evidence: Dict[str, Any]
    recommendations: List[str]


class AdvancedIDORDetector:
    """Продвинутый детектор IDOR с использованием всех техник"""
    
    # Словарь для перевода типов уязвимостей на русский
    VULNERABILITY_TYPES_RU = {
        'horizontal': 'Горизонтальный IDOR',
        'vertical': 'Вертикальный IDOR', 
        'context_dependent': 'Контекстно-зависимый IDOR',
        'blind': 'Слепая детекция',
        'pattern_based': 'Паттерн-матчинг',
        'heuristic': 'Эвристический анализ',
        'differential': 'Дифференциальный анализ',
        'heuristic_anomaly': 'Эвристическая аномалия',
        'content_size_difference': 'Различие в размере контента',
        'html_id_parameter': 'ID параметр в HTML',
        'privilege_escalation': 'Повышение привилегий',
        'data_exposure': 'Раскрытие данных',
        'auth_bypass': 'Обход аутентификации',
        'functionality_access': 'Доступ к функционалу',
        'blind_timing': 'Слепая детекция по времени отклика',
        'blind_error': 'Слепая детекция по паттернам ошибок',
        'blind_response_variance': 'Слепая детекция по вариативности ответов',
        'blind_behavioral': 'Слепая детекция по поведению',
        'blind_sequential': 'Слепая детекция по последовательным запросам',
        'blind_side_channel': 'Слепая детекция по побочным каналам',
        'timing_based': 'Слепая детекция по времени',
        'error_pattern': 'Слепая детекция по паттернам ошибок',
        'response_variance': 'Слепая детекция по вариативности ответов',
        'unique_pattern': 'Уникальный паттерн',
        'excessive_pattern': 'Частый паттерн',
        'unique_response': 'Уникальный ответ',
        'high_uniqueness': 'Высокая уникальность',
        'blind_response_analysis': 'Анализ ответов слепой детекции'
    }
    
    def __init__(self, session_factory):
        self.session_factory = session_factory
        
        # Инициализация компонентов
        self.pattern_matcher = PatternMatcher()
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.differential_analyzer = DifferentialAnalyzer(session_factory)
        self.blind_detector = BlindIDORDetector(session_factory)
        
        # Логгер
        self.logger = ScanLogger()
        
        # Результаты детекции
        self.detection_results: List[AdvancedDetectionResult] = []
        
        # Конфигурация
        self.config = {
            'enable_pattern_matching': True,
            'enable_heuristic_analysis': True,
            'enable_differential_analysis': True,
            'enable_blind_detection': True,
            'confidence_threshold': 0.5,
            'risk_threshold': 0.6
        }
    
    def configure(self, config: Dict[str, Any]):
        """Конфигурирует детектор"""
        self.config.update(config)
    
    async def comprehensive_scan(self, endpoint_template: str, object_ids: List[int], 
                                context: Dict, access_contexts: Optional[Dict[AccessLevel, AccessContext]] = None) -> List[AdvancedDetectionResult]:
        """
        Комплексное сканирование с использованием всех техник
        """
        self.detection_results = []
        self.logger.start_scan(len(object_ids))
        
        # Настраиваем дифференциальный анализ если предоставлены контексты
        if access_contexts and self.config['enable_differential_analysis']:
            self.differential_analyzer.setup_access_contexts(access_contexts)
            self.logger.info("🔧 Настроен дифференциальный анализ с несколькими контекстами")
        
        # Запускаем все стратегии детекции
        tasks = []
        
        if self.config['enable_pattern_matching']:
            self.logger.strategy_start("Паттерн-матчинг")
            tasks.append(self._pattern_based_detection(endpoint_template, object_ids, context))
        
        if self.config['enable_heuristic_analysis']:
            self.logger.strategy_start("Эвристический анализ")
            tasks.append(self._heuristic_detection(endpoint_template, object_ids, context))
        
        if self.config['enable_differential_analysis'] and access_contexts:
            self.logger.strategy_start("Дифференциальный анализ")
            tasks.append(self._differential_detection(endpoint_template, object_ids, context))
        
        if self.config['enable_blind_detection']:
            self.logger.strategy_start("Слепая детекция")
            tasks.append(self._blind_detection(endpoint_template, object_ids, context))
        
        # Ждем завершения всех задач
        strategy_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Объединяем результаты
        combined_results = self._combine_detection_results(strategy_results, object_ids)
        
        self.logger.finish_scan()
        self.detection_results = combined_results
        return combined_results
    
    async def _pattern_based_detection(self, endpoint_template: str, object_ids: List[int], 
                                     context: Dict) -> Dict[str, Any]:
        """Детекция на основе паттернов"""
        session = self.session_factory(context.get('auth_token'))
        results = {}
        
        # Получаем базовый объект для сравнения
        baseline_data = None
        for obj_id in object_ids:
            try:
                endpoint = endpoint_template.format(id=obj_id)
                response = session.get(endpoint)
                
                self.logger.request_made('GET', endpoint, response.status_code, 
                                     float(response.elapsed.total_seconds()) if hasattr(response, 'elapsed') else 0.0)
                
                if response.status_code == 200:
                    # Пробуем получить JSON, если не получается - используем HTML
                    try:
                        baseline_data = response.json()
                    except:
                        # Для HTML ответов используем текстовое содержимое
                        baseline_data = {
                            'status_code': response.status_code,
                            'content_length': len(response.text),
                            'content': response.text[:1000],  # Первые 1000 символов
                            'headers': dict(response.headers)
                        }
                    self.logger.info(f"📊 Установлен базовый объект для сравнения: #{obj_id}")
                    break
            except Exception as e:
                self.logger.error(f"❌ Ошибка при получении базового объекта #{obj_id}: {str(e)}")
                continue
        
        if not baseline_data:
            self.logger.error("❌ Не удалось получить базовый объект для паттерн-матчинга")
            return {'strategy': 'pattern_based', 'results': {}}
        
        # Анализируем каждый объект
        vulnerabilities_found = 0
        for obj_id in object_ids:
            self.logger.start_object(obj_id)
            
            try:
                endpoint = endpoint_template.format(id=obj_id)
                response = session.get(endpoint)
                
                self.logger.request_made('GET', endpoint, response.status_code, 
                                     float(response.elapsed.total_seconds()) if hasattr(response, 'elapsed') else 0.0)
                
                if response.status_code == 200:
                    # Пробуем получить JSON, если не получается - используем HTML
                    try:
                        current_data = response.json()
                    except:
                        # Для HTML ответов используем текстовое содержимое
                        current_data = {
                            'status_code': response.status_code,
                            'content_length': len(response.text),
                            'content': response.text[:1000],  # Первые 1000 символов
                            'headers': dict(response.headers)
                        }
                    
                    # Применяем паттерны
                    pattern_results = self.pattern_matcher.analyze(current_data, baseline_data, context)
                    
                    # Для HTML ответов используем дополнительную логику
                    if not pattern_results and isinstance(current_data, dict) and 'content' in current_data:
                        # Проверяем на типичные признаки IDOR в HTML
                        content_diff = abs(current_data['content_length'] - baseline_data['content_length'])
                        if content_diff > 100:  # Значительное различие в размере контента
                            pattern_results.append({
                                'type': self._translate_vulnerability_type('content_size_difference'),
                                'type_ru': self._translate_vulnerability_type('content_size_difference'),  # Русский вариант
                                'severity': 'medium',
                                'description': f'значительное различие в размере контента ({content_diff} символов)',
                                'confidence': 0.6,
                                'evidence': {
                                    'baseline_length': baseline_data['content_length'],
                                    'current_length': current_data['content_length'],
                                    'difference': content_diff
                                }
                            })
                        
                        # Проверяем на наличие данных пользователя в контенте
                        if 'artist=' in current_data['content'] and 'id=' in current_data['content']:
                            # Извлекаем фрагмент с ID параметрами
                            import re
                            id_matches = re.findall(r'[?&]artist=\d+|[?&]id=\d+', current_data['content'])
                            content_snippet = ', '.join(id_matches[:3]) if id_matches else 'artist=X, id=Y'
                            
                            pattern_results.append({
                                'type': self._translate_vulnerability_type('html_id_parameter'),
                                'type_ru': self._translate_vulnerability_type('html_id_parameter'),  # Русский вариант
                                'severity': 'high',
                                'description': 'Обнаружены параметры ID в HTML контенте',
                                'confidence': 0.8,
                                'evidence': {
                                    'content_snippet': content_snippet,
                                    'full_content_length': len(current_data['content']),
                                    'id_parameters_found': len(id_matches)
                                }
                            })
                    
                    # Обновляем типы уязвимостей русскими названиями
                    for pattern in pattern_results:
                        if 'type' in pattern and 'type_ru' not in pattern:
                            pattern['type_ru'] = self._translate_vulnerability_type(pattern['type'])
                    
                    if pattern_results:
                        results[obj_id] = {
                            'vulnerabilities': pattern_results,
                            'baseline_data': baseline_data,
                            'current_data': current_data
                        }
                        vulnerabilities_found += len(pattern_results)
                        
                        for pattern in pattern_results:
                            self.logger.vulnerability_found(obj_id, pattern['type'], pattern['confidence'])
                        
            except Exception as e:
                self.logger.error(f"❌ Ошибка при анализе объекта #{obj_id}: {str(e)}")
                results[obj_id] = {'error': str(e)}
            
            self.logger.finish_object(obj_id, len(pattern_results) if obj_id in results else 0)
        
        self.logger.strategy_result("Паттерн-матчинг", vulnerabilities_found)
        
        print(f"DEBUG _pattern_based_detection: results = {results}")
        return {'strategy': 'pattern_based', 'results': results}
    
    async def _heuristic_detection(self, endpoint_template: str, object_ids: List[int], 
                                 context: Dict) -> Dict[str, Any]:
        """Эвристическая детекция"""
        session = self.session_factory(context.get('auth_token'))
        results = {}
        
        # Устанавливаем базовые метрики
        baseline_metrics = None
        for obj_id in object_ids:
            try:
                endpoint = endpoint_template.format(id=obj_id)
                response = session.get(endpoint)
                
                metrics = self.heuristic_analyzer.create_metrics(response)
                if not baseline_metrics:
                    baseline_metrics = metrics
                    self.heuristic_analyzer.set_baseline(baseline_metrics)
                    break
            except:
                continue
        
        if not baseline_metrics:
            return {'strategy': 'heuristic', 'results': {}}
        
        # Анализируем каждый объект
        for obj_id in object_ids:
            try:
                endpoint = endpoint_template.format(id=obj_id)
                response = session.get(endpoint)
                
                metrics = self.heuristic_analyzer.create_metrics(response)
                heuristic_results = self.heuristic_analyzer.analyze_response(metrics)
                
                if heuristic_results['is_suspicious']:
                    results[obj_id] = {
                        'heuristics': heuristic_results,
                        'metrics': metrics
                    }
                        
            except Exception as e:
                results[obj_id] = {'error': str(e)}
        
        return {'strategy': 'heuristic', 'results': results}
    
    async def _differential_detection(self, endpoint_template: str, object_ids: List[int], 
                                    context: Dict) -> Dict[str, Any]:
        """Дифференциальная детекция"""
        try:
            differential_results = await self.differential_analyzer.analyze_endpoint(
                endpoint_template, object_ids
            )
            
            # Конвертируем результаты в нужный формат
            results = {}
            for result in differential_results:
                results[result.object_id] = {
                    'differential': result,
                    'vulnerability_type': result.vulnerability_type,
                    'confidence': result.confidence,
                    'risk_score': result.risk_score
                }
            
            return {'strategy': 'differential', 'results': results}
            
        except Exception as e:
            return {'strategy': 'differential', 'error': str(e), 'results': {}}
    
    async def _blind_detection(self, endpoint_template: str, object_ids: List[int], 
                              context: Dict) -> Dict[str, Any]:
        """Слепая детекция"""
        try:
            blind_results = await self.blind_detector.detect_blind_idor(
                endpoint_template, object_ids, context
            )
            
            # Группируем результаты по объектам
            results = {}
            for result in blind_results:
                # Извлекаем object_id из evidence если возможно
                obj_id = None
                if 'evidence' in result.evidence:
                    evidence = result.evidence['evidence']
                    if 'timing_anomalies' in evidence and evidence['timing_anomalies']:
                        obj_id = evidence['timing_anomalies'][0].get('object_id')
                    elif 'anomalies' in evidence and evidence['anomalies']:
                        obj_id = evidence['anomalies'][0].get('object_id')
                
                if obj_id is None:
                    # Если не смогли определить ID, используем индекс
                    obj_id = len(results)
                
                if obj_id not in results:
                    results[obj_id] = {'blind_detections': []}
                
                results[obj_id]['blind_detections'].append(result)
            
            return {'strategy': 'blind', 'results': results}
            
        except Exception as e:
            return {'strategy': 'blind', 'error': str(e), 'results': {}}
    
    def _combine_detection_results(self, strategy_results: List[Dict], object_ids: List[int]) -> List[AdvancedDetectionResult]:
        """Объединяет результаты всех стратегий"""
        combined_results = []
        
        print(f"DEBUG _combine_detection_results: strategy_results = {strategy_results}")
        print(f"DEBUG _combine_detection_results: object_ids = {object_ids}")
        
        for obj_id in object_ids:
            # Собираем результаты всех стратегий для этого объекта
            strategies_used = []
            vulnerabilities = []
            evidence = {}
            confidence_scores = []
            risk_scores = []
            
            for strategy_result in strategy_results:
                if isinstance(strategy_result, Exception):
                    continue
                
                strategy_name = strategy_result.get('strategy')
                strategy_data = strategy_result.get('results', {})
                
                if obj_id in strategy_data:
                    strategies_used.append(strategy_name)
                    obj_data = strategy_data[obj_id]
                    
                    # Извлекаем уязвимости
                    if 'vulnerabilities' in obj_data:
                        for vuln in obj_data['vulnerabilities']:
                            vulnerabilities.append(vuln)
                            if 'confidence' in vuln:
                                confidence_scores.append(vuln['confidence'])
                            if 'risk_score' in vuln:
                                risk_scores.append(vuln['risk_score'])
                    
                    # Извлекаем эвристики
                    if 'heuristics' in obj_data:
                        heuristics = obj_data['heuristics']
                        if heuristics['is_suspicious']:
                            vulnerabilities.append({
                                'type': self._translate_vulnerability_type('heuristic_anomaly'),
                                'confidence': heuristics['confidence'],
                                'evidence': heuristics
                            })
                        confidence_scores.append(heuristics['confidence'])
                    
                    # Извлекаем дифференциальные результаты
                    if 'differential' in obj_data:
                        diff = obj_data['differential']
                        vulnerabilities.append({
                            'type': self._translate_vulnerability_type(diff.vulnerability_type),
                            'confidence': diff.confidence,
                            'evidence': diff.evidence
                        })
                        confidence_scores.append(diff.confidence)
                        risk_scores.append(diff.risk_score)
                    
                    # Извлекаем слепую детекцию
                    if 'blind_detections' in obj_data:
                        for blind_result in obj_data['blind_detections']:
                            vulnerabilities.append({
                                'type': self._translate_vulnerability_type(f'blind_{blind_result.method.value}'),
                                'confidence': blind_result.confidence,
                                'evidence': blind_result.evidence
                            })
                            confidence_scores.append(blind_result.confidence)
                    
                    # Извлекаем слепую детекцию из результатов слепого детектора
                    if strategy_name == 'blind' and 0 in strategy_data:
                        blind_data = strategy_data[0]
                        if 'blind_detections' in blind_data:
                            for blind_result in blind_data['blind_detections']:
                                # Распределяем результаты по правильным object_id
                                if 'evidence' in blind_result.evidence and 'anomalies' in blind_result.evidence:
                                    for anomaly in blind_result.evidence['anomalies']:
                                        if 'object_id' in anomaly:
                                            anomaly_obj_id = anomaly['object_id']
                                            if anomaly_obj_id == obj_id:
                                                vulnerabilities.append({
                                                    'type': self._translate_vulnerability_type(f'blind_{blind_result.method.value}'),
                                                    'confidence': blind_result.confidence,
                                                    'evidence': blind_result.evidence
                                                })
                                                confidence_scores.append(blind_result.confidence)
                                                break
                    
                    # Сохраняем evidence
                    evidence[strategy_name] = obj_data
            
            # Рассчитываем общие метрики
            overall_confidence = max(confidence_scores) if confidence_scores else 0.0
            risk_score = max(risk_scores) if risk_scores else overall_confidence
            
            print(f"DEBUG obj_id {obj_id}: vulnerabilities={len(vulnerabilities)}, confidence={overall_confidence}, threshold={self.config['confidence_threshold']}")
            
            # Генерируем рекомендации
            recommendations = self._generate_recommendations(vulnerabilities)
            
            # Создаем результат если есть уязвимости
            if vulnerabilities and overall_confidence >= self.config['confidence_threshold']:
                print(f"DEBUG: Creating AdvancedDetectionResult for obj_id {obj_id}")
                combined_results.append(AdvancedDetectionResult(
                    object_id=obj_id,
                    strategies_used=strategies_used,
                    vulnerabilities=vulnerabilities,
                    overall_confidence=overall_confidence,
                    risk_score=risk_score,
                    evidence=evidence,
                    recommendations=recommendations
                ))
            else:
                print(f"DEBUG: NOT creating result for obj_id {obj_id} - vulnerabilities: {len(vulnerabilities)}, confidence: {overall_confidence}")
        
        return combined_results
    
    def _translate_vulnerability_type(self, vuln_type: str) -> str:
        """Переводит тип уязвимости на русский язык"""
        return self.VULNERABILITY_TYPES_RU.get(vuln_type, vuln_type)
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Генерирует рекомендации на основе найденных уязвимостей"""
        recommendations = []
        vuln_types = set(v['type'] for v in vulnerabilities)
        
        # Базовые рекомендации
        if 'Горизонтальный IDOR' in vuln_types:
            recommendations.append("Реализуйте валидацию прав владения для всех ресурсов")
            recommendations.append("Добавьте проверки user_id в API эндпоинтах")
        
        if 'Вертикальный IDOR' in vuln_types:
            recommendations.append("Реализуйте proper role-based access control")
            recommendations.append("Удалите административные данные из пользовательских эндпоинтов")
        
        if 'heuristic_anomaly' in vuln_types:
            recommendations.append("Исследуйте подозрительные паттерны ответов")
            recommendations.append("Стандартизируйте сообщения об ошибках и форматы ответов")
        
        if 'privilege_escalation' in vuln_types:
            recommendations.append("Исправьте уязвимости повышения привилегий")
            recommendations.append("Реализуйте строгие проверки авторизации")
        
        if 'data_exposure' in vuln_types:
            recommendations.append("Удалите чувствительные данные из API ответов")
            recommendations.append("Реализуйте фильтрацию данных на основе ролей пользователей")
        
        # Рекомендации для слепой детекции
        for vuln_type in vuln_types:
            if 'слепой' in vuln_type.lower() or 'blind' in vuln_type.lower():
                recommendations.append("Исследуйте потенциальные слепые IDOR уязвимости")
                recommendations.append("Реализуйте консистентную обработку ответов")
                break
        
        # Общие рекомендации
        recommendations.extend([
            "Реализуйте комплексное логирование попыток доступа",
            "Добавьте автоматизированное тестирование безопасности в CI/CD pipeline",
            "Регулярные аудиты безопасности и пентесты"
        ])
        
        return list(set(recommendations))  # Удаляем дубликаты
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        """Генерирует комплексный отчет"""
        if not self.detection_results:
            return {'summary': {'total_vulnerabilities': 0, 'average_confidence': 0, 'average_risk_score': 0, 'high_risk_count': 0, 'vulnerability_types': {}, 'strategies_used': {}}, 'top_recommendations': []}
        
        # Статистика
        total_objects = len(self.detection_results)
        avg_confidence = sum(r.overall_confidence for r in self.detection_results) / total_objects
        avg_risk = sum(r.risk_score for r in self.detection_results) / total_objects
        
        # Типы уязвимостей
        vulnerability_types = {}
        strategy_usage = {}
        
        for result in self.detection_results:
            for vuln in result.vulnerabilities:
                vuln_type = vuln['type']
                vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
            
            for strategy in result.strategies_used:
                strategy_usage[strategy] = strategy_usage.get(strategy, 0) + 1
        
        # Высокорисковые находки
        high_risk = [r for r in self.detection_results if r.risk_score > self.config['risk_threshold']]
        
        # Топ рекомендаций
        all_recommendations = []
        for result in self.detection_results:
            all_recommendations.extend(result.recommendations)
        
        top_recommendations = list(set(all_recommendations))[:10]  # Топ-10 уникальных рекомендаций
        
        return {
            'summary': {
                'total_vulnerabilities': total_objects,
                'average_confidence': avg_confidence,
                'average_risk_score': avg_risk,
                'high_risk_count': len(high_risk),
                'vulnerability_types': vulnerability_types,
                'strategies_used': strategy_usage
            },
            'high_risk_findings': high_risk,
            'all_findings': self.detection_results,
            'top_recommendations': top_recommendations,
            'detailed_analysis': self._get_detailed_analysis()
        }
    
    def _get_detailed_analysis(self) -> Dict[str, Any]:
        """Получает детальный анализ"""
        analysis = {
            'pattern_analysis': self.pattern_matcher.get_summary([]),
            'heuristic_analysis': 'Heuristic analysis completed',
            'differential_analysis': 'Differential analysis completed',
            'blind_analysis': self.blind_detector.generate_blind_report()
        }
        
        return analysis
