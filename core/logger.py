"""
Логгер для детекции IDOR с детальной информацией о процессе
"""
import time
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum


class LogLevel(Enum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    DEBUG = "debug"


@dataclass
class LogEntry:
    """Запись в логе"""
    timestamp: float
    level: LogLevel
    message: str
    details: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'level': self.level.value,
            'message': self.message,
            'details': self.details or {}
        }


class ScanLogger:
    """Логгер процесса сканирования"""
    
    def __init__(self):
        self.logs: List[LogEntry] = []
        self.start_time: float = None
        self.current_object_id: int = None
        self.total_objects: int = 0
        self.processed_objects: int = 0
        
    def start_scan(self, total_objects: int):
        """Начинает сканирование"""
        self.start_time = time.time()
        self.total_objects = total_objects
        self.processed_objects = 0
        self.logs = []
        
        self.info(f"🚀 Начинаем сканирование {total_objects} объектов", {
            'total_objects': total_objects,
            'start_time': self.start_time
        })
    
    def finish_scan(self):
        """Завершает сканирование"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        self.success(f"✅ Сканирование завершено за {elapsed:.2f} секунд", {
            'elapsed_time': elapsed,
            'total_processed': self.processed_objects
        })
    
    def start_object(self, object_id: int):
        """Начинает обработку объекта"""
        self.current_object_id = object_id
        self.debug(f"🔍 Анализируем объект #{object_id}", {
            'object_id': object_id,
            'progress': f"{self.processed_objects}/{self.total_objects}"
        })
    
    def finish_object(self, object_id: int, vulnerabilities_found: int):
        """Завершает обработку объекта"""
        self.processed_objects += 1
        
        if vulnerabilities_found > 0:
            self.warning(f"⚠️ Объект #{object_id}: найдено {vulnerabilities_found} уязвимостей", {
                'object_id': object_id,
                'vulnerabilities_found': vulnerabilities_found
            })
        else:
            self.debug(f"✅ Объект #{object_id}: уязвимостей не найдено", {
                'object_id': object_id
            })
    
    def info(self, message: str, details: Dict[str, Any] = None):
        """Информационное сообщение"""
        self._log(LogLevel.INFO, message, details)
    
    def success(self, message: str, details: Dict[str, Any] = None):
        """Сообщение об успехе"""
        self._log(LogLevel.SUCCESS, message, details)
    
    def warning(self, message: str, details: Dict[str, Any] = None):
        """Предупреждение"""
        self._log(LogLevel.WARNING, message, details)
    
    def error(self, message: str, details: Dict[str, Any] = None):
        """Ошибка"""
        self._log(LogLevel.ERROR, message, details)
    
    def debug(self, message: str, details: Dict[str, Any] = None):
        """Отладочное сообщение"""
        self._log(LogLevel.DEBUG, message, details)
    
    def strategy_start(self, strategy_name: str):
        """Начало работы стратегии"""
        self.info(f"🔧 Запускаем стратегию: {strategy_name}", {
            'strategy': strategy_name
        })
    
    def strategy_result(self, strategy_name: str, results_count: int):
        """Результат работы стратегии"""
        if results_count > 0:
            self.success(f"🎯 Стратегия {strategy_name} нашла {results_count} проблем", {
                'strategy': strategy_name,
                'results_count': results_count
            })
        else:
            self.debug(f"🔍 Стратегия {strategy_name} не нашла проблем", {
                'strategy': strategy_name
            })
    
    def vulnerability_found(self, object_id: int, vuln_type: str, confidence: float):
        """Найдена уязвимость"""
        self.warning(f"🚨 Найдена уязвимость! Объект #{object_id}: {vuln_type} (уровень риска: {confidence:.2f})", {
            'object_id': object_id,
            'vulnerability_type': vuln_type,
            'confidence': confidence
        })
    
    def request_made(self, method: str, url: str, status_code: int, response_time: float):
        """Логирование HTTP запроса"""
        self.debug(f"📡 {method} {url} -> {status_code} ({response_time:.3f}s)", {
            'method': method,
            'url': url,
            'status_code': status_code,
            'response_time': response_time
        })
    
    def _log(self, level: LogLevel, message: str, details: Dict[str, Any] = None):
        """Добавляет запись в лог"""
        entry = LogEntry(
            timestamp=time.time(),
            level=level,
            message=message,
            details=details
        )
        self.logs.append(entry)
    
    def get_logs(self) -> List[Dict[str, Any]]:
        """Возвращает все логи"""
        return [log.to_dict() for log in self.logs]
    
    def get_progress(self) -> Dict[str, Any]:
        """Возвращает информацию о прогрессе"""
        return {
            'total_objects': self.total_objects,
            'processed_objects': self.processed_objects,
            'progress_percentage': (self.processed_objects / self.total_objects * 100) if self.total_objects > 0 else 0,
            'current_object': self.current_object_id,
            'elapsed_time': time.time() - self.start_time if self.start_time else 0
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Возвращает сводку логов"""
        level_counts = {}
        for log in self.logs:
            level = log.level.value
            level_counts[level] = level_counts.get(level, 0) + 1
        
        return {
            'total_logs': len(self.logs),
            'level_counts': level_counts,
            'progress': self.get_progress()
        }
