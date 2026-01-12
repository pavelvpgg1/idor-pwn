"""
Продвинутые паттерны для детекции IDOR уязвимостей
"""
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum


class IDORType(Enum):
    HORIZONTAL = "горизонтальный"  # Доступ к данным других пользователей
    VERTICAL = "вертикальный"      # Доступ с повышением привилегий
    CONTEXT_DEPENDENT = "контекстно-зависимый"  # Зависит от контекста
    BLIND = "слепой"            # Слепая детекция


class IDORPattern:
    """Базовый класс для паттернов IDOR"""
    
    def __init__(self, name: str, description: str, idor_type: IDORType):
        self.name = name
        self.description = description
        self.idor_type = idor_type
        self.confidence = 0.0
    
    def analyze(self, response_data: Dict, baseline_data: Dict, 
                context: Dict) -> Tuple[bool, float, Dict]:
        """
        Анализирует данные на наличие IDOR
        Returns: (is_idor, confidence, details)
        """
        raise NotImplementedError


class HorizontalIDORPattern(IDORPattern):
    """Паттерн для горизонтального IDOR"""
    
    def __init__(self):
        super().__init__(
            "Горизонтальный IDOR",
            "Доступ к данным других пользователей на том же уровне привилегий",
            IDORType.HORIZONTAL
        )
    
    def analyze(self, response_data: Dict, baseline_data: Dict, 
                context: Dict) -> Tuple[bool, float, Dict]:
        is_idor = False
        confidence = 0.0
        details = {}
        
        # Проверка поля владельца
        owner_field = context.get('ownership_field', 'owner_id')
        current_user_id = context.get('current_user_id')
        
        if owner_field in response_data:
            owner_id = response_data[owner_field]
            if owner_id != current_user_id:
                is_idor = True
                confidence = 0.8
                details = {
                    'owner_field': owner_field,
                    'current_user_id': current_user_id,
                    'accessed_owner_id': owner_id,
                    'evidence': f"Accessed data owned by user {owner_id} as user {current_user_id}"
                }
        
        return is_idor, confidence, details


class VerticalIDORPattern(IDORPattern):
    """Паттерн для вертикального IDOR"""
    
    def __init__(self):
        super().__init__(
            "Вертикальный IDOR", 
            "Доступ с повышением привилегий или к административным функциям",
            IDORType.VERTICAL
        )
    
    def analyze(self, response_data: Dict, baseline_data: Dict, 
                context: Dict) -> Tuple[bool, float, Dict]:
        is_idor = False
        confidence = 0.0
        details = {}
        
        # Проверка на административные поля
        admin_fields = ['is_admin', 'role', 'permissions', 'access_level']
        sensitive_fields = ['salary', 'ssn', 'credit_card', 'internal_notes']
        
        found_admin_fields = []
        found_sensitive_fields = []
        
        for field in admin_fields:
            if field in response_data and response_data[field] not in [None, False, 0, 'user']:
                found_admin_fields.append(field)
        
        for field in sensitive_fields:
            if field in response_data:
                found_sensitive_fields.append(field)
        
        if found_admin_fields or found_sensitive_fields:
            is_idor = True
            confidence = 0.7 if found_admin_fields else 0.6
            details = {
                'admin_fields': found_admin_fields,
                'sensitive_fields': found_sensitive_fields,
                'evidence': f"Accessed privileged data: {found_admin_fields + found_sensitive_fields}"
            }
        
        return is_idor, confidence, details


class ContextDependentIDORPattern(IDORPattern):
    """Паттерн для контекстно-зависимого IDOR"""
    
    def __init__(self):
        super().__init__(
            "Контекстно-зависимый IDOR",
            "IDOR зависящий от бизнес-контекста или состояния",
            IDORType.CONTEXT_DEPENDENT
        )
    
    def analyze(self, response_data: Dict, baseline_data: Dict, 
                context: Dict) -> Tuple[bool, float, Dict]:
        is_idor = False
        confidence = 0.0
        details = {}
        
        # Проверка временных/статусных полей
        status_fields = ['status', 'state', 'approved', 'published', 'active']
        temporal_fields = ['created_at', 'updated_at', 'expires_at']
        
        status_issues = []
        temporal_issues = []
        
        for field in status_fields:
            if field in response_data:
                value = response_data[field]
                if value in ['approved', 'published', 'active'] and context.get('user_role') != 'admin':
                    status_issues.append(f"Accessed {field}={value} as non-admin")
        
        # Сравнение временных меток
        for field in temporal_fields:
            if field in response_data and field in baseline_data:
                if response_data[field] != baseline_data[field]:
                    temporal_issues.append(f"Different {field} values")
        
        if status_issues or temporal_issues:
            is_idor = True
            confidence = 0.5
            details = {
                'status_issues': status_issues,
                'temporal_issues': temporal_issues,
                'evidence': status_issues + temporal_issues
            }
        
        return is_idor, confidence, details


class BlindIDORPattern(IDORPattern):
    """Паттерн для слепой детекции IDOR"""
    
    def __init__(self):
        super().__init__(
            "Слепая детекция IDOR",
            "Детекция IDOR через косвенные признаки",
            IDORType.BLIND
        )
    
    def analyze(self, response_data: Dict, baseline_data: Dict, 
                context: Dict) -> Tuple[bool, float, Dict]:
        is_idor = False
        confidence = 0.0
        details = {}
        
        # Анализ структуры ответа
        response_keys = set(response_data.keys())
        baseline_keys = set(baseline_data.keys())
        
        # Новые поля в ответе
        new_fields = response_keys - baseline_keys
        # Отсутствующие поля
        missing_fields = baseline_keys - response_keys
        
        # Анализ значений
        value_differences = {}
        for key in response_keys & baseline_keys:
            if response_data[key] != baseline_data[key]:
                value_differences[key] = {
                    'baseline': baseline_data[key],
                    'current': response_data[key]
                }
        
        # Эвристики для слепой детекции
        indicators = []
        
        if len(new_fields) > 0:
            indicators.append(f"New fields detected: {list(new_fields)}")
            confidence += 0.2
        
        if len(missing_fields) > 0:
            indicators.append(f"Missing fields: {list(missing_fields)}")
            confidence += 0.1
        
        if len(value_differences) > 3:  # Много различий
            indicators.append(f"Significant value differences: {len(value_differences)} fields")
            confidence += 0.3
        
        # Проверка на ID-like поля
        id_fields = [k for k in response_data.keys() if re.match(r'.*id$', k, re.IGNORECASE)]
        if len(id_fields) > 1:
            indicators.append(f"Multiple ID fields: {id_fields}")
            confidence += 0.2
        
        if confidence > 0.4:
            is_idor = True
            details = {
                'new_fields': list(new_fields),
                'missing_fields': list(missing_fields),
                'value_differences': value_differences,
                'id_fields': id_fields,
                'indicators': indicators
            }
        
        return is_idor, min(confidence, 0.8), details


class PatternMatcher:
    """Основной класс для матчинга паттернов IDOR"""
    
    def __init__(self):
        self.patterns = [
            HorizontalIDORPattern(),
            VerticalIDORPattern(),
            ContextDependentIDORPattern(),
            BlindIDORPattern()
        ]
    
    def analyze(self, response_data: Dict, baseline_data: Dict, 
                context: Dict) -> List[Dict]:
        """
        Анализирует данные с помощью всех паттернов
        Returns: List of detected IDOR instances
        """
        results = []
        
        for pattern in self.patterns:
            is_idor, confidence, details = pattern.analyze(
                response_data, baseline_data, context
            )
            
            if is_idor:
                results.append({
                    'pattern': pattern.name,
                    'type': pattern.idor_type.value,
                    'confidence': confidence,
                    'details': details,
                    'description': pattern.description,
                    'type_ru': pattern.idor_type.value  # Добавляем русский вариант
                })
        
        return results
    
    def get_summary(self, results: List[Dict]) -> Dict:
        """Возвращает сводку результатов анализа"""
        if not results:
            return {'total': 0, 'types': [], 'max_confidence': 0.0}
        
        types = list(set(r['type'] for r in results))
        max_confidence = max(r['confidence'] for r in results)
        
        return {
            'total': len(results),
            'types': types,
            'max_confidence': max_confidence,
            'high_confidence': len([r for r in results if r['confidence'] > 0.7])
        }
