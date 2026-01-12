"""
Дифференциальный анализ с разными уровнями доступа
"""
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import time


class AccessLevel(Enum):
    GUEST = "guest"
    USER = "user"
    PREMIUM = "premium"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


@dataclass
class AccessContext:
    """Контекст доступа пользователя"""
    user_id: int
    access_level: AccessLevel
    auth_token: str
    permissions: List[str]
    session_data: Dict[str, Any]


@dataclass
class DifferentialResult:
    """Результат дифференциального анализа"""
    object_id: int
    vulnerability_type: str
    confidence: float
    access_level_diff: Dict[str, Any]
    evidence: Dict[str, Any]
    risk_score: float


class DifferentialAnalyzer:
    """Дифференциальный анализатор IDOR уязвимостей"""
    
    def __init__(self, session_factory):
        self.session_factory = session_factory
        self.access_contexts: Dict[AccessLevel, AccessContext] = {}
        self.results: List[DifferentialResult] = []
        
        # Веса для расчета риска
        self.risk_weights = {
            'privilege_escalation': 0.4,
            'data_exposure': 0.3,
            'functionality_access': 0.2,
            'bypass_authorization': 0.1
        }
    
    def setup_access_contexts(self, contexts: Dict[AccessLevel, AccessContext]):
        """Настраивает контексты для разных уровней доступа"""
        self.access_contexts = contexts
    
    async def analyze_endpoint(self, endpoint_template: str, object_ids: List[int]) -> List[DifferentialResult]:
        """
        Анализирует эндпоинт с разными уровнями доступа
        endpoint_template: "/api/orders/{id}"
        """
        self.results = []
        
        for obj_id in object_ids:
            result = await self._analyze_object_access(endpoint_template, obj_id)
            if result:
                self.results.append(result)
        
        return self.results
    
    async def _analyze_object_access(self, endpoint_template: str, object_id: int) -> Optional[DifferentialResult]:
        """Анализирует доступ к объекту с разных уровней"""
        access_results = {}
        
        # Собираем данные со всех уровней доступа
        for access_level, context in self.access_contexts.items():
            try:
                session = self.session_factory(context.auth_token)
                endpoint = endpoint_template.format(id=object_id)
                
                start_time = time.time()
                response = session.get(endpoint)
                response_time = time.time() - start_time
                
                access_results[access_level.value] = {
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'content_length': len(response.content) if hasattr(response, 'content') else 0,
                    'data': response.json() if response.status_code == 200 and hasattr(response, 'json') else None,
                    'headers': dict(response.headers) if hasattr(response, 'headers') else {},
                    'accessible': response.status_code == 200
                }
                
            except Exception as e:
                access_results[access_level.value] = {
                    'error': str(e),
                    'accessible': False
                }
        
        # Анализируем дифференциальные признаки
        return self._analyze_differential_patterns(object_id, access_results)
    
    def _analyze_differential_patterns(self, object_id: int, access_results: Dict[str, Dict]) -> Optional[DifferentialResult]:
        """Анализирует дифференциальные паттерны"""
        
        # 1. Проверка на повышение привилегий
        privilege_escalation = self._check_privilege_escalation(access_results)
        
        # 2. Проверка на утечку данных
        data_exposure = self._check_data_exposure(access_results)
        
        # 3. Проверка на обход авторизации
        auth_bypass = self._check_authorization_bypass(access_results)
        
        # 4. Проверка на функциональный доступ
        functionality_access = self._check_functionality_access(access_results)
        
        # Комбинируем результаты
        vulnerability_type = None
        confidence = 0.0
        evidence = {}
        risk_score = 0.0
        
        if privilege_escalation['detected']:
            vulnerability_type = "privilege_escalation"
            confidence = privilege_escalation['confidence']
            evidence['privilege_escalation'] = privilege_escalation
            risk_score += self.risk_weights['privilege_escalation'] * confidence
        
        if data_exposure['detected']:
            vulnerability_type = vulnerability_type or "data_exposure"
            confidence = max(confidence, data_exposure['confidence'])
            evidence['data_exposure'] = data_exposure
            risk_score += self.risk_weights['data_exposure'] * data_exposure['confidence']
        
        if auth_bypass['detected']:
            vulnerability_type = vulnerability_type or "auth_bypass"
            confidence = max(confidence, auth_bypass['confidence'])
            evidence['auth_bypass'] = auth_bypass
            risk_score += self.risk_weights['bypass_authorization'] * auth_bypass['confidence']
        
        if functionality_access['detected']:
            vulnerability_type = vulnerability_type or "functionality_access"
            confidence = max(confidence, functionality_access['confidence'])
            evidence['functionality_access'] = functionality_access
            risk_score += self.risk_weights['functionality_access'] * functionality_access['confidence']
        
        if vulnerability_type and confidence > 0.3:
            return DifferentialResult(
                object_id=object_id,
                vulnerability_type=vulnerability_type,
                confidence=confidence,
                access_level_diff=access_results,
                evidence=evidence,
                risk_score=min(risk_score, 1.0)
            )
        
        return None
    
    def _check_privilege_escalation(self, access_results: Dict[str, Dict]) -> Dict[str, Any]:
        """Проверка на повышение привилегий"""
        detected = False
        confidence = 0.0
        details = {}
        
        # Сравниваем доступ обычного пользователя с администратором
        user_access = access_results.get('user', {})
        admin_access = access_results.get('admin', {})
        
        if user_access.get('accessible') and admin_access.get('accessible'):
            user_data = user_access.get('data', {})
            admin_data = admin_access.get('data', {})
            
            # Ищем поля, которые есть у админа, но нет у пользователя
            admin_only_fields = set(admin_data.keys()) - set(user_data.keys())
            
            # Ищем поля с разными значениями
            different_fields = {}
            for key in set(user_data.keys()) & set(admin_data.keys()):
                if user_data[key] != admin_data[key]:
                    different_fields[key] = {
                        'user_value': user_data[key],
                        'admin_value': admin_data[key]
                    }
            
            if admin_only_fields or different_fields:
                detected = True
                confidence = 0.7 if admin_only_fields else 0.5
                details = {
                    'admin_only_fields': list(admin_only_fields),
                    'different_fields': different_fields,
                    'evidence': f"User accessed admin-level data: {len(admin_only_fields) + len(different_fields)} fields"
                }
        
        # Проверка на доступ гостя к пользовательским данным
        guest_access = access_results.get('guest', {})
        if guest_access.get('accessible') and user_access.get('accessible'):
            detected = True
            confidence = max(confidence, 0.8)
            details['guest_access'] = "Guest accessed user-restricted data"
        
        return {
            'detected': detected,
            'confidence': confidence,
            'details': details
        }
    
    def _check_data_exposure(self, access_results: Dict[str, Dict]) -> Dict[str, Any]:
        """Проверка на утечку данных"""
        detected = False
        confidence = 0.0
        details = {}
        
        # Ищем чувствительные поля в ответах
        sensitive_fields = ['password', 'ssn', 'credit_card', 'email', 'phone', 'address']
        exposed_fields = []
        
        for level, result in access_results.items():
            if result.get('data'):
                data = result['data']
                for field in sensitive_fields:
                    if field in data and data[field]:
                        exposed_fields.append({
                            'field': field,
                            'access_level': level,
                            'value_preview': str(data[field])[:10] + "..." if len(str(data[field])) > 10 else str(data[field])
                        })
        
        if exposed_fields:
            detected = True
            confidence = 0.6
            details = {
                'exposed_fields': exposed_fields,
                'evidence': f"Sensitive data exposed: {len(exposed_fields)} fields"
            }
        
        return {
            'detected': detected,
            'confidence': confidence,
            'details': details
        }
    
    def _check_authorization_bypass(self, access_results: Dict[str, Dict]) -> Dict[str, Any]:
        """Проверка на обход авторизации"""
        detected = False
        confidence = 0.0
        details = {}
        
        # Ищем несоответствия в статус кодах
        status_codes = {}
        for level, result in access_results.items():
            status_codes[level] = result.get('status_code', 0)
        
        # Если гость имеет доступ, а пользователь нет - это подозрительно
        guest_status = status_codes.get('guest', 0)
        user_status = status_codes.get('user', 0)
        
        if guest_status == 200 and user_status != 200:
            detected = True
            confidence = 0.8
            details = {
                'bypass_type': 'guest_access_higher_than_user',
                'guest_status': guest_status,
                'user_status': user_status,
                'evidence': f"Guest has 200 access but user gets {user_status}"
            }
        
        # Если все уровни доступа имеют одинаковый доступ
        unique_statuses = set(status_codes.values())
        if len(unique_statuses) == 1 and 200 in unique_statuses:
            detected = True
            confidence = 0.6
            details = {
                'bypass_type': 'uniform_access',
                'evidence': "All access levels have identical permissions"
            }
        
        return {
            'detected': detected,
            'confidence': confidence,
            'details': details
        }
    
    def _check_functionality_access(self, access_results: Dict[str, Dict]) -> Dict[str, Any]:
        """Проверка на функциональный доступ"""
        detected = False
        confidence = 0.0
        details = {}
        
        # Анализируем размеры ответов
        response_sizes = {}
        for level, result in access_results.items():
            response_sizes[level] = result.get('content_length', 0)
        
        # Ищем аномалии в размерах ответов
        if len(response_sizes) > 1:
            sizes = list(response_sizes.values())
            max_size = max(sizes)
            min_size = min(sizes)
            
            if max_size > 0 and min_size > 0:
                size_ratio = max_size / min_size
                
                # Если один ответ значительно больше других
                if size_ratio > 3.0:
                    detected = True
                    confidence = 0.5
                    details = {
                        'size_anomaly': True,
                        'size_ratio': size_ratio,
                        'response_sizes': response_sizes,
                        'evidence': f"Response size ratio anomaly: {size_ratio:.2f}"
                    }
        
        # Анализируем время ответа
        response_times = {}
        for level, result in access_results.items():
            response_times[level] = result.get('response_time', 0.0)
        
        if len(response_times) > 1:
            times = list(response_times.values())
            max_time = max(times)
            min_time = min(times)
            
            if max_time > 0 and min_time > 0:
                time_ratio = max_time / min_time
                
                # Если один ответ значительно медленнее
                if time_ratio > 2.0:
                    detected = True
                    confidence = max(confidence, 0.4)
                    details['time_anomaly'] = {
                        'time_ratio': time_ratio,
                        'response_times': response_times
                    }
        
        return {
            'detected': detected,
            'confidence': confidence,
            'details': details
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """Генерирует отчет о дифференциальном анализе"""
        if not self.results:
            return {'summary': 'No vulnerabilities detected'}
        
        # Сортируем по риску
        sorted_results = sorted(self.results, key=lambda x: x.risk_score, reverse=True)
        
        # Статистика
        vulnerability_types = {}
        total_risk = 0.0
        
        for result in self.results:
            vuln_type = result.vulnerability_type
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
            total_risk += result.risk_score
        
        return {
            'summary': {
                'total_vulnerabilities': len(self.results),
                'average_risk_score': total_risk / len(self.results),
                'max_risk_score': max(r.risk_score for r in self.results),
                'vulnerability_types': vulnerability_types
            },
            'high_risk_findings': [r for r in sorted_results if r.risk_score > 0.7],
            'all_findings': sorted_results,
            'recommendations': self._generate_recommendations(vulnerability_types)
        }
    
    def _generate_recommendations(self, vuln_types: Dict[str, int]) -> List[str]:
        """Генерирует рекомендации на основе найденных уязвимостей"""
        recommendations = []
        
        if 'privilege_escalation' in vuln_types:
            recommendations.append("Implement proper role-based access control (RBAC)")
            recommendations.append("Add authorization checks for privileged operations")
        
        if 'data_exposure' in vuln_types:
            recommendations.append("Remove sensitive fields from API responses")
            recommendations.append("Implement data filtering based on user roles")
        
        if 'auth_bypass' in vuln_types:
            recommendations.append("Fix authorization logic inconsistencies")
            recommendations.append("Implement proper session management")
        
        if 'functionality_access' in vuln_types:
            recommendations.append("Review and restrict functionality access")
            recommendations.append("Implement feature-level permissions")
        
        return recommendations
