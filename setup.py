#!/usr/bin/env python3
"""
Скрипт установки и настройки IDOR Pwn
Автор: Смирных Павел Ильич, 2026
"""

import os
import sys
import subprocess
import platform
from pathlib import Path


def check_python_version():
    """Проверка версии Python"""
    print("🐍 Проверка версии Python...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Требуется Python 3.8+, установлена версия {version.major}.{version.minor}")
        return False
    
    print(f"✅ Версия Python: {version.major}.{version.minor}.{version.micro}")
    return True


def create_virtual_env():
    """Создание виртуального окружения"""
    print("📦 Создание виртуального окружения...")
    
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("ℹ️ Виртуальное окружение уже существует")
        return True
    
    try:
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("✅ Виртуальное окружение создано")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка создания виртуального окружения: {e}")
        return False


def get_venv_python():
    """Получение пути к Python в виртуальном окружении"""
    system = platform.system().lower()
    
    if system == "windows":
        return Path("venv/Scripts/python.exe")
    else:
        return Path("venv/bin/python")


def get_venv_pip():
    """Получение пути к pip в виртуальном окружении"""
    system = platform.system().lower()
    
    if system == "windows":
        return Path("venv/Scripts/pip.exe")
    else:
        return Path("venv/bin/pip")


def install_dependencies():
    """Установка зависимостей"""
    print("📚 Установка зависимостей...")
    
    pip_path = get_venv_pip()
    requirements_path = Path("requirements.txt")
    
    if not requirements_path.exists():
        print("❌ Файл requirements.txt не найден")
        return False
    
    try:
        subprocess.run([str(pip_path), "install", "-r", str(requirements_path)], check=True)
        print("✅ Зависимости установлены")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка установки зависимостей: {e}")
        return False


def create_directories():
    """Создание необходимых директорий"""
    print("📁 Создание директорий...")
    
    directories = [
        "logs",
        "data",
        "reports",
        "examples/output"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"   📁 {directory}")
    
    print("✅ Директории созданы")
    return True


def setup_gitignore():
    """Настройка .gitignore"""
    print("🔒 Настройка .gitignore...")
    
    gitignore_path = Path(".gitignore")
    
    if gitignore_path.exists():
        print("ℹ️ .gitignore уже существует")
        return True
    
    gitignore_content = """# Виртуальное окружение
venv/
env/
.venv/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Логи
logs/
*.log

# Данные и отчеты
data/
reports/
examples/output/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# LaTeX
*.aux
*.log
*.toc
*.out
*.bbl
*.blg
*.fdb_latexmk
*.fls
*.synctex.gz

# Временные файлы
*.tmp
*.temp
"""
    
    try:
        gitignore_path.write_text(gitignore_content)
        print("✅ .gitignore создан")
        return True
    except Exception as e:
        print(f"❌ Ошибка создания .gitignore: {e}")
        return False


def test_installation():
    """Тестирование установки"""
    print("🧪 Тестирование установки...")
    
    python_path = get_venv_python()
    
    # Тест импорта основных модулей
    test_script = """
import sys
sys.path.append('.')

try:
    from core.advanced_detector import AdvancedIDORDetector
    from auth.session import Session
    from core.patterns import PatternMatcher
    print("✅ Основные модули импортированы успешно")
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    sys.exit(1)

try:
    import flask
    import requests
    import yaml
    print("✅ Внешние зависимости доступны")
except ImportError as e:
    print(f"❌ Ошибка импорта зависимостей: {e}")
    sys.exit(1)

print("✅ Тестирование пройдено")
"""
    
    try:
        result = subprocess.run([str(python_path), "-c", test_script], 
                              capture_output=True, text=True, check=True)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Тестирование не пройдено: {e}")
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr)
        return False


def create_run_scripts():
    """Создание скриптов для запуска"""
    print("🚀 Создание скриптов запуска...")
    
    system = platform.system().lower()
    
    # Windows batch файл
    if system == "windows":
        run_script = """@echo off
echo Запуск IDOR Pwn...
call venv\\Scripts\\activate
python web\\app.py
pause
"""
        script_path = Path("run.bat")
        try:
            script_path.write_text(run_script)
            print("   📄 run.bat создан")
        except Exception as e:
            print(f"❌ Ошибка создания run.bat: {e}")
    
    # Linux/Mac shell скрипт
    else:
        run_script = """#!/bin/bash
echo "Запуск IDOR Pwn..."
source venv/bin/activate
python web/app.py
"""
        script_path = Path("run.sh")
        try:
            script_path.write_text(run_script)
            script_path.chmod(0o755)  # Сделать исполняемым
            print("   📄 run.sh создан")
        except Exception as e:
            print(f"❌ Ошибка создания run.sh: {e}")
    
    return True


def print_success_message():
    """Вывод сообщения об успешной установке"""
    print("\n" + "=" * 60)
    print("🎉 Установка IDOR Pwn завершена успешно!")
    print("=" * 60)
    
    system = platform.system().lower()
    
    print("\n📋 Следующие шаги:")
    print("1. Активируйте виртуальное окружение:")
    
    if system == "windows":
        print("   venv\\Scripts\\activate")
    else:
        print("   source venv/bin/activate")
    
    print("\n2. Запустите уязвимый API для тестирования:")
    print("   python victim_api.py")
    
    print("\n3. Запустите веб-интерфейс:")
    if system == "windows":
        print("   run.bat")
    else:
        print("   ./run.sh")
    
    print("\n4. Откройте в браузере:")
    print("   http://127.0.0.1:8000")
    
    print("\n📚 Дополнительная информация:")
    print("   • Документация: docs/README.md")
    print("   • Примеры: examples/basic_usage.py")
    print("   • Конфигурация: config/environments.py")
    
    print("\n🛡️ IDOR Pwn готов к использованию!")


def main():
    """Главная функция установки"""
    print("🛡️ Установка IDOR Pwn")
    print("Автор: Смирных Павел Ильич, 2026")
    print("=" * 50)
    
    steps = [
        ("Проверка версии Python", check_python_version),
        ("Создание виртуального окружения", create_virtual_env),
        ("Установка зависимостей", install_dependencies),
        ("Создание директорий", create_directories),
        ("Настройка .gitignore", setup_gitignore),
        ("Создание скриптов запуска", create_run_scripts),
        ("Тестирование установки", test_installation)
    ]
    
    for step_name, step_func in steps:
        print(f"\n📍 {step_name}...")
        if not step_func():
            print(f"❌ Установка прервана на шаге: {step_name}")
            return False
    
    print_success_message()
    return True


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n❌ Установка отменена пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Непредвиденная ошибка: {e}")
        sys.exit(1)
