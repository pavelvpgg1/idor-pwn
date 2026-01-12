"""
Blind IDOR detection - детекция без явных признаков уязвимости
"""
import time
import random
import hashlib
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import statistics


class DetectionMethod(Enum):
    TIMING_BASED = "timing_based"
    ERROR_PATTERN = "error_pattern"
    RESPONSE_VARIANCE = "response_variance"
    BEHAVIORAL = "behavioral"
    SIDE_CHANNEL = "side_channel"


@dataclass
class BlindTestResult:
    """Результат слепого теста"""
    method: DetectionMethod
    confidence: float
    evidence: Dict[str, Any]
    test_data: Dict[str, Any]
    anomaly_score: float


class BlindIDORDetector:
    """Детектор слепых IDOR уязвимостей"""
    
    def __init__(self, session_factory):
        self.session_factory = session_factory
        self.test_results: List[BlindTestResult] = []
        
        # Пороговые значения для детекции
        self.thresholds = {
            'timing_anomaly': 0.3,  # сек
            'variance_threshold': 0.4,
            'error_pattern_threshold': 0.6,
            'behavioral_anomaly': 0.5
        }
    
    async def detect_blind_idor(self, endpoint_template: str, object_ids: List[int], 
                               context: Dict) -> List[BlindTestResult]:
        """
        Запускает все методы слепой детекции
        """
        self.test_results = []
        
        # 1. Timing-based detection
        timing_results = await self._timing_based_detection(endpoint_template, object_ids, context)
        self.test_results.extend(timing_results)
        
        # 2. Error pattern detection
        error_results = await self._error_pattern_detection(endpoint_template, object_ids, context)
        self.test_results.extend(error_results)
        
        # 3. Response variance detection
        variance_results = await self._response_variance_detection(endpoint_template, object_ids, context)
        self.test_results.extend(variance_results)
        
        # 4. Behavioral analysis
        behavioral_results = await self._behavioral_analysis(endpoint_template, object_ids, context)
        self.test_results.extend(behavioral_results)
        
        # 5. Side-channel detection
        side_channel_results = await self._side_channel_detection(endpoint_template, object_ids, context)
        self.test_results.extend(side_channel_results)
        
        return self.test_results
    
    async def _timing_based_detection(self, endpoint_template: str, object_ids: List[int], 
                                    context: Dict) -> List[BlindTestResult]:
        """Детекция на основе анализа времени ответа"""
        results = []
        session = self.session_factory(context.get('auth_token'))
        
        # Собираем временные метрики
        timing_data = {}
        
        for obj_id in object_ids:
            endpoint = endpoint_template.format(id=obj_id)
            
            # Делаем несколько запросов для усреднения
            times = []
            for _ in range(3):
                start_time = time.time()
                try:
                    response = session.get(endpoint)
                    elapsed = time.time() - start_time
                    times.append(elapsed)
                except Exception as e:
                    times.append(float('inf'))
            
            avg_time = statistics.mean(times)
            timing_data[obj_id] = {
                'avg_time': avg_time,
                'times': times,
                'status_code': response.status_code if 'response' in locals() else None
            }
        
        # Анализируем аномалии во времени
        times = [data['avg_time'] for data in timing_data.values() if data['avg_time'] != float('inf')]
        
        if len(times) > 2:
            mean_time = statistics.mean(times)
            std_dev = statistics.stdev(times)
            
            # Ищем выбросы
            anomalies = []
            for obj_id, data in timing_data.items():
                if data['avg_time'] != float('inf'):
                    z_score = abs(data['avg_time'] - mean_time) / std_dev if std_dev > 0 else 0
                    
                    if z_score > 2.0:  # 2 стандартных отклонения
                        anomalies.append({
                            'object_id': obj_id,
                            'time': data['avg_time'],
                            'z_score': z_score,
                            'difference': data['avg_time'] - mean_time
                        })
            
            if anomalies:
                confidence = min(len(anomalies) / len(object_ids), 0.8)
                results.append(BlindTestResult(
                    method=DetectionMethod.TIMING_BASED,
                    confidence=confidence,
                    evidence={
                        'timing_anomalies': anomalies,
                        'mean_time': mean_time,
                        'std_dev': std_dev
                    },
                    test_data=timing_data,
                    anomaly_score=max(a['z_score'] for a in anomalies)
                ))
        
        return results
    
    async def _error_pattern_detection(self, endpoint_template: str, object_ids: List[int], 
                                     context: Dict) -> List[BlindTestResult]:
        """Детекция на основе паттернов ошибок"""
        results = []
        session = self.session_factory(context.get('auth_token'))
        
        error_patterns = {
            'access_denied': ['access denied', 'forbidden', 'unauthorized'],
            'not_found': ['not found', 'does not exist', 'invalid'],
            'permission': ['permission', 'privilege', 'not allowed'],
            'generic': ['error', 'exception', 'failed']
        }
        
        error_data = {}
        
        for obj_id in object_ids:
            endpoint = endpoint_template.format(id=obj_id)
            
            try:
                response = session.get(endpoint)
                
                # Анализируем ответ на ошибки
                response_text = response.text.lower() if hasattr(response, 'text') else ''
                status_code = response.status_code if hasattr(response, 'status_code') else 0
                
                detected_patterns = {}
                for pattern_name, keywords in error_patterns.items():
                    matches = [kw for kw in keywords if kw in response_text]
                    if matches:
                        detected_patterns[pattern_name] = matches
                
                error_data[obj_id] = {
                    'status_code': status_code,
                    'response_length': len(response_text),
                    'detected_patterns': detected_patterns,
                    'response_preview': response_text[:100]
                }
                
            except Exception as e:
                error_data[obj_id] = {
                    'error': str(e),
                    'detected_patterns': {'exception': [str(e)[:50]]}
                }
        
        # Анализируем паттерны ошибок
        pattern_analysis = self._analyze_error_patterns(error_data)
        
        if pattern_analysis['anomalies']:
            confidence = min(len(pattern_analysis['anomalies']) / len(object_ids), 0.7)
            results.append(BlindTestResult(
                method=DetectionMethod.ERROR_PATTERN,
                confidence=confidence,
                evidence=pattern_analysis,
                test_data=error_data,
                anomaly_score=pattern_analysis['anomaly_score']
            ))
        
        return results
    
    async def _response_variance_detection(self, endpoint_template: str, object_ids: List[int], 
                                        context: Dict) -> List[BlindTestResult]:
        """Детекция на основе вариативности ответов"""
        results = []
        session = self.session_factory(context.get('auth_token'))
        
        responses = {}
        
        for obj_id in object_ids:
            endpoint = endpoint_template.format(id=obj_id)
            
            try:
                response = session.get(endpoint)
                
                # Создаем хеш ответа для сравнения
                response_hash = hashlib.md5(response.text.encode()).hexdigest()
                
                responses[obj_id] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content) if hasattr(response, 'content') else 0,
                    'response_hash': response_hash,
                    'headers_hash': hashlib.md5(str(dict(response.headers)).encode()).hexdigest()
                }
                
            except Exception as e:
                responses[obj_id] = {'error': str(e)}
        
        # Анализируем вариативность
        variance_analysis = self._analyze_response_variance(responses)
        
        if variance_analysis['anomalies']:
            confidence = min(len(variance_analysis['anomalies']) / len(object_ids), 0.6)
            results.append(BlindTestResult(
                method=DetectionMethod.RESPONSE_VARIANCE,
                confidence=confidence,
                evidence=variance_analysis,
                test_data=responses,
                anomaly_score=variance_analysis['anomaly_score']
            ))
        
        return results
    
    async def _behavioral_analysis(self, endpoint_template: str, object_ids: List[int], 
                                 context: Dict) -> List[BlindTestResult]:
        """Анализ поведенческих аномалий"""
        results = []
        session = self.session_factory(context.get('auth_token'))
        
        # Тестируем последовательные ID
        sequential_data = {}
        
        for obj_id in object_ids:
            endpoint = endpoint_template.format(id=obj_id)
            
            # Тестируем разные HTTP методы
            methods = ['GET', 'POST', 'PUT', 'DELETE']
            method_results = {}
            
            for method in methods:
                try:
                    start_time = time.time()
                    
                    if method == 'GET':
                        response = session.get(endpoint)
                    elif method == 'POST':
                        response = session.post(endpoint, json={})
                    elif method == 'PUT':
                        response = session.put(endpoint, json={})
                    elif method == 'DELETE':
                        response = session.delete(endpoint)
                    
                    elapsed = time.time() - start_time
                    
                    method_results[method] = {
                        'status_code': response.status_code,
                        'response_time': elapsed,
                        'content_length': len(response.content) if hasattr(response, 'content') else 0
                    }
                    
                except Exception as e:
                    method_results[method] = {'error': str(e)}
            
            sequential_data[obj_id] = method_results
        
        # Анализируем поведенческие аномалии
        behavioral_analysis = self._analyze_behavioral_patterns(sequential_data)
        
        if behavioral_analysis['anomalies']:
            confidence = min(len(behavioral_analysis['anomalies']) / len(object_ids), 0.5)
            results.append(BlindTestResult(
                method=DetectionMethod.BEHAVIORAL,
                confidence=confidence,
                evidence=behavioral_analysis,
                test_data=sequential_data,
                anomaly_score=behavioral_analysis['anomaly_score']
            ))
        
        return results
    
    async def _side_channel_detection(self, endpoint_template: str, object_ids: List[int], 
                                   context: Dict) -> List[BlindTestResult]:
        """Детекция через side-channel атаки"""
        results = []
        session = self.session_factory(context.get('auth_token'))
        
        # Тестируем с разными заголовками
        side_channel_data = {}
        
        for obj_id in object_ids:
            endpoint = endpoint_template.format(id=obj_id)
            
            # Базовый запрос
            try:
                base_response = session.get(endpoint)
                base_time = time.time()
            except:
                continue
            
            # Тестируем с разными заголовками
            header_tests = [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Real-IP': '192.168.1.1'},
                {'User-Agent': 'Mozilla/5.0 (compatible; Bot/1.0)'},
                {'Referer': 'http://localhost/admin'},
                {'X-Admin': 'true'}
            ]
            
            header_results = {}
            
            for headers in header_tests:
                try:
                    test_response = session.get(endpoint, headers=headers)
                    header_results[str(headers)] = {
                        'status_code': test_response.status_code,
                        'content_length': len(test_response.content) if hasattr(test_response, 'content') else 0,
                        'different_from_base': test_response.status_code != base_response.status_code
                    }
                except Exception as e:
                    header_results[str(headers)] = {'error': str(e)}
            
            side_channel_data[obj_id] = {
                'base_status': base_response.status_code,
                'header_tests': header_results
            }
        
        # Анализируем side-channel аномалии
        side_channel_analysis = self._analyze_side_channel_patterns(side_channel_data)
        
        if side_channel_analysis['anomalies']:
            confidence = min(len(side_channel_analysis['anomalies']) / len(object_ids), 0.4)
            results.append(BlindTestResult(
                method=DetectionMethod.SIDE_CHANNEL,
                confidence=confidence,
                evidence=side_channel_analysis,
                test_data=side_channel_data,
                anomaly_score=side_channel_analysis['anomaly_score']
            ))
        
        return results
    
    def _analyze_error_patterns(self, error_data: Dict) -> Dict[str, Any]:
        """Анализирует паттерны ошибок"""
        pattern_counts = {}
        anomalies = []
        
        for obj_id, data in error_data.items():
            if 'detected_patterns' in data:
                for pattern_name, matches in data['detected_patterns'].items():
                    if pattern_name not in pattern_counts:
                        pattern_counts[pattern_name] = []
                    pattern_counts[pattern_name].append(obj_id)
        
        # Ищем необычные паттерны
        for pattern_name, obj_ids in pattern_counts.items():
            if len(obj_ids) == 1:  # Паттерн встречается только один раз
                anomalies.append({
                    'pattern': pattern_name,
                    'object_id': obj_ids[0],
                    'type': 'unique_pattern'
                })
            elif len(obj_ids) > len(error_data) * 0.8:  # Паттерн встречается слишком часто
                anomalies.append({
                    'pattern': pattern_name,
                    'object_ids': obj_ids,
                    'type': 'excessive_pattern'
                })
        
        anomaly_score = len(anomalies) / len(error_data) if error_data else 0
        
        return {
            'anomalies': anomalies,
            'pattern_counts': pattern_counts,
            'anomaly_score': anomaly_score
        }
    
    def _analyze_response_variance(self, responses: Dict) -> Dict[str, Any]:
        """Анализирует вариативность ответов"""
        hash_groups = {}
        
        for obj_id, data in responses.items():
            if 'response_hash' in data:
                hash_key = data['response_hash']
                if hash_key not in hash_groups:
                    hash_groups[hash_key] = []
                hash_groups[hash_key].append(obj_id)
        
        # Ищем аномальные группы
        anomalies = []
        for hash_key, obj_ids in hash_groups.items():
            if len(obj_ids) == 1:  # Уникальный ответ
                anomalies.append({
                    'object_id': obj_ids[0],
                    'type': 'unique_response',
                    'hash': hash_key
                })
        
        # Проверяем на слишком много уникальных ответов
        unique_ratio = len([g for g in hash_groups.values() if len(g) == 1]) / len(responses)
        
        anomaly_score = unique_ratio
        if unique_ratio > 0.5:
            anomalies.append({
                'type': 'high_uniqueness',
                'unique_ratio': unique_ratio
            })
        
        return {
            'anomalies': anomalies,
            'hash_groups': {k: len(v) for k, v in hash_groups.items()},
            'anomaly_score': anomaly_score
        }
    
    def _analyze_behavioral_patterns(self, sequential_data: Dict) -> Dict[str, Any]:
        """Анализирует поведенческие паттерны"""
        anomalies = []
        
        for obj_id, methods in sequential_data.items():
            # Ищем неожиданные успешные методы
            unexpected_success = []
            
            for method, result in methods.items():
                if method in ['POST', 'PUT', 'DELETE'] and result.get('status_code') == 200:
                    unexpected_success.append(method)
            
            if unexpected_success:
                anomalies.append({
                    'object_id': obj_id,
                    'type': 'unexpected_success',
                    'methods': unexpected_success
                })
        
        anomaly_score = len(anomalies) / len(sequential_data) if sequential_data else 0
        
        return {
            'anomalies': anomalies,
            'anomaly_score': anomaly_score
        }
    
    def _analyze_side_channel_patterns(self, side_channel_data: Dict) -> Dict[str, Any]:
        """Анализирует side-channel паттерны"""
        anomalies = []
        
        for obj_id, data in side_channel_data.items():
            base_status = data['base_status']
            
            # Ищем заголовки, которые меняют ответ
            changing_headers = []
            
            for header_str, result in data['header_tests'].items():
                if result.get('different_from_base'):
                    changing_headers.append({
                        'header': header_str,
                        'new_status': result.get('status_code'),
                        'base_status': base_status
                    })
            
            if changing_headers:
                anomalies.append({
                    'object_id': obj_id,
                    'type': 'header_influence',
                    'changing_headers': changing_headers
                })
        
        anomaly_score = len(anomalies) / len(side_channel_data) if side_channel_data else 0
        
        return {
            'anomalies': anomalies,
            'anomaly_score': anomaly_score
        }
    
    def generate_blind_report(self) -> Dict[str, Any]:
        """Генерирует отчет о слепой детекции"""
        if not self.test_results:
            return {'summary': 'No blind IDOR vulnerabilities detected'}
        
        # Группируем по методам
        method_results = {}
        for result in self.test_results:
            method = result.method.value
            if method not in method_results:
                method_results[method] = []
            method_results[method].append(result)
        
        # Считаем общую статистику
        total_confidence = sum(r.confidence for r in self.test_results) / len(self.test_results)
        max_anomaly_score = max(r.anomaly_score for r in self.test_results)
        
        # Высокорисковые находки
        high_risk = [r for r in self.test_results if r.confidence > 0.6 and r.anomaly_score > 1.5]
        
        return {
            'summary': {
                'total_detections': len(self.test_results),
                'average_confidence': total_confidence,
                'max_anomaly_score': max_anomaly_score,
                'methods_used': list(method_results.keys()),
                'high_risk_count': len(high_risk)
            },
            'method_results': method_results,
            'high_risk_findings': high_risk,
            'recommendations': self._generate_blind_recommendations(method_results)
        }
    
    def _generate_blind_recommendations(self, method_results: Dict) -> List[str]:
        """Генерирует рекомендации для слепой детекции"""
        recommendations = []
        
        if 'timing_based' in method_results:
            recommendations.append("Investigate timing-based information disclosure")
            recommendations.append("Implement constant-time response handling")
        
        if 'error_pattern' in method_results:
            recommendations.append("Standardize error messages across access levels")
            recommendations.append("Remove sensitive information from error responses")
        
        if 'response_variance' in method_results:
            recommendations.append("Ensure consistent response structures")
            recommendations.append("Implement proper response filtering")
        
        if 'behavioral' in method_results:
            recommendations.append("Review and restrict HTTP method permissions")
            recommendations.append("Implement proper request validation")
        
        if 'side_channel' in method_results:
            recommendations.append("Sanitize and validate all input headers")
            recommendations.append("Implement request header validation")
        
        return recommendations
