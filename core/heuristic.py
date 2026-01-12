"""
Эвристический анализ ответов сервера для детекции IDOR
"""
import time
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ResponseType(Enum):
    SUCCESS = "success"
    ERROR = "error"
    REDIRECT = "redirect"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"


@dataclass
class ResponseMetrics:
    """Метрики HTTP ответа"""
    status_code: int
    response_time: float
    content_length: int
    content_type: str
    headers: Dict[str, str]
    body: str
    json_data: Optional[Dict] = None


class HeuristicAnalyzer:
    """Эвристический анализатор ответов"""
    
    def __init__(self):
        self.baseline_metrics: Optional[ResponseMetrics] = None
        self.response_history: List[ResponseMetrics] = []
        
        # Пороговые значения для эвристик
        self.thresholds = {
            'response_time_diff': 0.5,  # сек
            'content_length_diff': 0.3,  # %
            'similarity_threshold': 0.7,  # %
            'error_patterns': [
                r'not found',
                r'access denied',
                r'forbidden',
                r'unauthorized',
                r'permission denied'
            ]
        }
    
    def set_baseline(self, metrics: ResponseMetrics):
        """Устанавливает базовые метрики для сравнения"""
        self.baseline_metrics = metrics
        self.response_history.append(metrics)
    
    def analyze_response(self, metrics: ResponseMetrics) -> Dict[str, Any]:
        """Анализирует ответ и возвращает эвристические признаки IDOR"""
        if not self.baseline_metrics:
            return {'error': 'No baseline established'}
        
        results = {
            'is_suspicious': False,
            'confidence': 0.0,
            'indicators': [],
            'details': {}
        }
        
        # 1. Анализ времени ответа
        time_analysis = self._analyze_response_time(metrics)
        if time_analysis['is_anomaly']:
            results['indicators'].append('response_time_anomaly')
            results['details']['response_time'] = time_analysis
            results['confidence'] += 0.2
        
        # 2. Анализ размера контента
        size_analysis = self._analyze_content_size(metrics)
        if size_analysis['is_anomaly']:
            results['indicators'].append('content_size_anomaly')
            results['details']['content_size'] = size_analysis
            results['confidence'] += 0.2
        
        # 3. Анализ HTTP заголовков
        header_analysis = self._analyze_headers(metrics)
        if header_analysis['is_anomaly']:
            results['indicators'].append('header_anomaly')
            results['details']['headers'] = header_analysis
            results['confidence'] += 0.15
        
        # 4. Анализ контента
        content_analysis = self._analyze_content(metrics)
        if content_analysis['is_anomaly']:
            results['indicators'].append('content_anomaly')
            results['details']['content'] = content_analysis
            results['confidence'] += 0.25
        
        # 5. Анализ JSON структуры
        if metrics.json_data:
            json_analysis = self._analyze_json_structure(metrics)
            if json_analysis['is_anomaly']:
                results['indicators'].append('json_structure_anomaly')
                results['details']['json_structure'] = json_analysis
                results['confidence'] += 0.2
        
        # 6. Комбинированный анализ
        combined_analysis = self._combined_analysis(metrics)
        if combined_analysis['is_anomaly']:
            results['indicators'].append('combined_anomaly')
            results['details']['combined'] = combined_analysis
            results['confidence'] += 0.1
        
        # Определяем общую подозрительность
        results['is_suspicious'] = len(results['indicators']) >= 2 or results['confidence'] > 0.5
        results['confidence'] = min(results['confidence'], 0.95)
        
        self.response_history.append(metrics)
        return results
    
    def _analyze_response_time(self, metrics: ResponseMetrics) -> Dict[str, Any]:
        """Анализ времени ответа"""
        baseline_time = self.baseline_metrics.response_time
        current_time = metrics.response_time
        
        time_diff = abs(current_time - baseline_time)
        time_ratio = time_diff / baseline_time if baseline_time > 0 else 0
        
        return {
            'is_anomaly': time_diff > self.thresholds['response_time_diff'] or time_ratio > 2.0,
            'baseline_time': baseline_time,
            'current_time': current_time,
            'difference': time_diff,
            'ratio': time_ratio
        }
    
    def _analyze_content_size(self, metrics: ResponseMetrics) -> Dict[str, Any]:
        """Анализ размера контента"""
        baseline_size = self.baseline_metrics.content_length
        current_size = metrics.content_length
        
        if baseline_size == 0:
            return {'is_anomaly': False, 'reason': 'zero_baseline'}
        
        size_diff = abs(current_size - baseline_size)
        size_ratio = size_diff / baseline_size
        
        return {
            'is_anomaly': size_ratio > self.thresholds['content_length_diff'],
            'baseline_size': baseline_size,
            'current_size': current_size,
            'difference': size_diff,
            'ratio': size_ratio
        }
    
    def _analyze_headers(self, metrics: ResponseMetrics) -> Dict[str, Any]:
        """Анализ HTTP заголовков"""
        baseline_headers = self.baseline_metrics.headers
        current_headers = metrics.headers
        
        # Поиск новых заголовков
        new_headers = set(current_headers.keys()) - set(baseline_headers.keys())
        missing_headers = set(baseline_headers.keys()) - set(current_headers.keys())
        
        # Анализ специфичных заголовков безопасности
        security_headers = ['x-frame-options', 'x-content-type-options', 'x-xss-protection']
        security_changes = []
        
        for header in security_headers:
            if header in baseline_headers and header in current_headers:
                if baseline_headers[header] != current_headers[header]:
                    security_changes.append(header)
        
        # Анализ заголовков аутентификации
        auth_headers = ['authorization', 'x-auth-token', 'session']
        auth_changes = []
        
        for header in auth_headers:
            if header in baseline_headers and header in current_headers:
                if baseline_headers[header] != current_headers[header]:
                    auth_changes.append(header)
        
        is_anomaly = (len(new_headers) > 0 or len(missing_headers) > 0 or 
                     len(security_changes) > 0 or len(auth_changes) > 0)
        
        return {
            'is_anomaly': is_anomaly,
            'new_headers': list(new_headers),
            'missing_headers': list(missing_headers),
            'security_changes': security_changes,
            'auth_changes': auth_changes
        }
    
    def _analyze_content(self, metrics: ResponseMetrics) -> Dict[str, Any]:
        """Анализ контента ответа"""
        baseline_content = self.baseline_metrics.body
        current_content = metrics.body
        
        # Проверка на ошибки
        error_indicators = []
        for pattern in self.thresholds['error_patterns']:
            if pattern.lower() in current_content.lower():
                error_indicators.append(pattern)
        
        # Проверка на редиректы
        redirect_indicators = ['redirect', 'location', 'moved']
        redirect_found = any(indicator in current_content.lower() for indicator in redirect_indicators)
        
        # Проверка на HTML контент в JSON API
        html_indicators = ['<html', '<body', '<div', '<script']
        html_in_json = (metrics.content_type and 'json' in metrics.content_type.lower() and 
                       any(indicator in current_content.lower() for indicator in html_indicators))
        
        # Сходство контента
        similarity = self._calculate_similarity(baseline_content, current_content)
        
        is_anomaly = (len(error_indicators) > 0 or redirect_found or 
                     html_in_json or similarity < self.thresholds['similarity_threshold'])
        
        return {
            'is_anomaly': is_anomaly,
            'error_indicators': error_indicators,
            'redirect_found': redirect_found,
            'html_in_json': html_in_json,
            'similarity': similarity,
            'length_diff': len(current_content) - len(baseline_content)
        }
    
    def _analyze_json_structure(self, metrics: ResponseMetrics) -> Dict[str, Any]:
        """Анализ структуры JSON"""
        if not self.baseline_metrics.json_data:
            return {'is_anomaly': False, 'reason': 'no_baseline_json'}
        
        baseline_json = self.baseline_metrics.json_data
        current_json = metrics.json_data
        
        # Сравнение структуры JSON
        baseline_keys = set(self._flatten_json_keys(baseline_json))
        current_keys = set(self._flatten_json_keys(current_json))
        
        new_keys = current_keys - baseline_keys
        missing_keys = baseline_keys - current_keys
        
        # Анализ типов данных
        type_changes = []
        for key in baseline_keys & current_keys:
            baseline_value = self._get_nested_value(baseline_json, key)
            current_value = self._get_nested_value(current_json, key)
            
            if type(baseline_value) != type(current_value):
                type_changes.append(key)
        
        # Анализ значений
        value_changes = []
        for key in baseline_keys & current_keys:
            baseline_value = self._get_nested_value(baseline_json, key)
            current_value = self._get_nested_value(current_json, key)
            
            if baseline_value != current_value:
                value_changes.append(key)
        
        is_anomaly = (len(new_keys) > 0 or len(missing_keys) > 0 or 
                     len(type_changes) > 0 or len(value_changes) > 3)
        
        return {
            'is_anomaly': is_anomaly,
            'new_keys': list(new_keys),
            'missing_keys': list(missing_keys),
            'type_changes': type_changes,
            'value_changes': value_changes,
            'total_changes': len(new_keys) + len(missing_keys) + len(type_changes) + len(value_changes)
        }
    
    def _combined_analysis(self, metrics: ResponseMetrics) -> Dict[str, Any]:
        """Комбинированный анализ нескольких метрик"""
        if len(self.response_history) < 3:
            return {'is_anomaly': False, 'reason': 'insufficient_history'}
        
        # Анализ последовательности ответов
        recent_responses = self.response_history[-5:]
        
        # Проверка на паттерны в статус кодах
        status_codes = [r.status_code for r in recent_responses]
        status_variance = len(set(status_codes)) > 1
        
        # Проверка на паттерны во времени ответа
        response_times = [r.response_time for r in recent_responses]
        time_variance = max(response_times) - min(response_times) > 1.0
        
        # Проверка на паттерны в размере контента
        content_sizes = [r.content_length for r in recent_responses]
        size_variance = max(content_sizes) - min(content_sizes) > 1000
        
        is_anomaly = status_variance or time_variance or size_variance
        
        return {
            'is_anomaly': is_anomaly,
            'status_variance': status_variance,
            'time_variance': time_variance,
            'size_variance': size_variance,
            'recent_status_codes': status_codes[-3:],
            'avg_response_time': sum(response_times[-3:]) / 3
        }
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Вычисляет сходство двух текстов"""
        if not text1 or not text2:
            return 0.0
        
        # Простая метрика сходства на основе общих слов
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        intersection = words1 & words2
        union = words1 | words2
        
        return len(intersection) / len(union) if union else 0.0
    
    def _flatten_json_keys(self, data: Dict, prefix: str = '') -> List[str]:
        """Разворачивает вложенные ключи JSON в плоский список"""
        keys = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.append(full_key)
                
                if isinstance(value, dict):
                    keys.extend(self._flatten_json_keys(value, full_key))
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            keys.extend(self._flatten_json_keys(item, f"{full_key}[{i}]"))
        
        return keys
    
    def _get_nested_value(self, data: Dict, key_path: str):
        """Получает значение по вложенному пути"""
        keys = key_path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        
        return current
    
    def create_metrics(self, response) -> ResponseMetrics:
        """Создает метрики из HTTP ответа"""
        import json
        
        content_length = len(response.content) if hasattr(response, 'content') else 0
        content_type = response.headers.get('content-type', '') if hasattr(response, 'headers') else ''
        
        json_data = None
        try:
            if content_type and 'json' in content_type.lower():
                json_data = response.json() if hasattr(response, 'json') else None
        except:
            pass
        
        return ResponseMetrics(
            status_code=response.status_code if hasattr(response, 'status_code') else 0,
            response_time=getattr(response, 'elapsed', 0.0),
            content_length=content_length,
            content_type=content_type,
            headers=dict(response.headers) if hasattr(response, 'headers') else {},
            body=response.text if hasattr(response, 'text') else '',
            json_data=json_data
        )
