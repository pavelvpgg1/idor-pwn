#!/usr/bin/env python3
"""
Конфигурации для различных окружений
Автор: Смирных Павел Ильич, 2026
"""

import os
from typing import Dict, Any


class EnvironmentConfig:
    """Базовый класс конфигурации окружения"""
    
    def __init__(self, name: str):
        self.name = name
    
    def get_detector_config(self) -> Dict[str, Any]:
        """Конфигурация детектора"""
        return {}
    
    def get_web_config(self) -> Dict[str, Any]:
        """Конфигурация веб-приложения"""
        return {}
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Конфигурация логирования"""
        return {}


class DevelopmentConfig(EnvironmentConfig):
    """Конфигурация для разработки"""
    
    def __init__(self):
        super().__init__("development")
    
    def get_detector_config(self) -> Dict[str, Any]:
        return {
            'enable_pattern_matching': True,
            'enable_heuristic_analysis': True,
            'enable_differential_analysis': True,
            'enable_blind_detection': True,
            'confidence_threshold': 0.3,  # Низкий порог для тестирования
            'risk_threshold': 0.3
        }
    
    def get_web_config(self) -> Dict[str, Any]:
        return {
            'debug': True,
            'host': '127.0.0.1',
            'port': 8000,
            'auto_reload': True
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        return {
            'level': 'DEBUG',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': 'logs/development.log'
        }


class ProductionConfig(EnvironmentConfig):
    """Конфигурация для продакшена"""
    
    def __init__(self):
        super().__init__("production")
    
    def get_detector_config(self) -> Dict[str, Any]:
        return {
            'enable_pattern_matching': True,
            'enable_heuristic_analysis': True,
            'enable_differential_analysis': True,
            'enable_blind_detection': True,
            'confidence_threshold': 0.7,  # Высокий порог для продакшена
            'risk_threshold': 0.8
        }
    
    def get_web_config(self) -> Dict[str, Any]:
        return {
            'debug': False,
            'host': '0.0.0.0',
            'port': 80,
            'auto_reload': False
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        return {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': 'logs/production.log'
        }


class TestingConfig(EnvironmentConfig):
    """Конфигурация для тестирования"""
    
    def __init__(self):
        super().__init__("testing")
    
    def get_detector_config(self) -> Dict[str, Any]:
        return {
            'enable_pattern_matching': True,
            'enable_heuristic_analysis': True,
            'enable_differential_analysis': False,  # Отключено для скорости
            'enable_blind_detection': True,
            'confidence_threshold': 0.1,  # Минимальный порог
            'risk_threshold': 0.1
        }
    
    def get_web_config(self) -> Dict[str, Any]:
        return {
            'debug': True,
            'host': '127.0.0.1',
            'port': 8001,
            'auto_reload': False
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        return {
            'level': 'DEBUG',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': 'logs/testing.log'
        }


class CompetitionConfig(EnvironmentConfig):
    """Конфигурация для соревнований (ВсОШ)"""
    
    def __init__(self):
        super().__init__("competition")
    
    def get_detector_config(self) -> Dict[str, Any]:
        return {
            'enable_pattern_matching': True,
            'enable_heuristic_analysis': True,
            'enable_differential_analysis': True,
            'enable_blind_detection': True,
            'confidence_threshold': 0.5,  # Сбалансированный порог
            'risk_threshold': 0.6
        }
    
    def get_web_config(self) -> Dict[str, Any]:
        return {
            'debug': False,
            'host': '127.0.0.1',
            'port': 8000,
            'auto_reload': False
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        return {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'file': 'logs/competition.log'
        }


# Реестр конфигураций
CONFIGS = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'competition': CompetitionConfig
}


def get_config(env_name: str = None) -> EnvironmentConfig:
    """
    Получение конфигурации для указанного окружения
    
    Args:
        env_name: Имя окружения. Если None, используется переменная окружения IDOR_ENV
        
    Returns:
        EnvironmentConfig: Конфигурация окружения
    """
    if env_name is None:
        env_name = os.getenv('IDOR_ENV', 'development')
    
    if env_name not in CONFIGS:
        raise ValueError(f"Неизвестное окружение: {env_name}. Доступные: {list(CONFIGS.keys())}")
    
    return CONFIGS[env_name]()


def get_current_config() -> EnvironmentConfig:
    """Получение текущей конфигурации"""
    return get_config()


# Примеры использования
if __name__ == "__main__":
    # Демонстрация конфигураций
    environments = ['development', 'production', 'testing', 'competition']
    
    print("🔧 Конфигурации IDOR Pwn")
    print("=" * 50)
    
    for env_name in environments:
        config = get_config(env_name)
        print(f"\n📁 Окружение: {config.name}")
        
        detector_config = config.get_detector_config()
        print(f"   Порог уверенности: {detector_config['confidence_threshold']}")
        print(f"   Порог риска: {detector_config['risk_threshold']}")
        
        web_config = config.get_web_config()
        print(f"   Веб-порт: {web_config['port']}")
        print(f"   Debug режим: {web_config['debug']}")
        
        logging_config = config.get_logging_config()
        print(f"   Уровень логов: {logging_config['level']}")
    
    print("\n✅ Конфигурации загружены успешно!")
