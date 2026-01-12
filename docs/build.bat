@echo off
REM Batch файл для компиляции LaTeX документов
REM Аналог Makefile для Windows
REM Автор: Смирных Павел Ильич, 2026

setlocal enabledelayedexpansion

set MAIN=report
set PRESENTATION=presentation

if "%1"=="" goto help
if "%1"=="all" goto all
if "%1"=="quick" goto quick
if "%1"=="clean" goto clean
if "%1"=="view" goto view
if "%1"=="presentation" goto presentation
if "%1"=="help" goto help

:help
echo.
echo 📚 Batch скрипт для компиляции LaTeX документов
echo Автор: Смирных Павел Ильич, 2026
echo.
echo Использование:
echo    build.bat [цель]
echo.
echo Доступные цели:
echo    all         - Компиляция всех документов (по умолчанию)
echo    quick       - Быстрая компиляция без библиографии
echo    clean       - Очистка временных файлов
echo    view        - Просмотр скомпилированных документов
echo    presentation - Компиляция только презентации
echo    help        - Показать эту справку
echo.
echo Примеры:
echo    build.bat all
echo    build.bat clean
echo    build.bat view
echo.
goto end

:check_latex
where pdflatex >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ pdflatex не найден. Установите MiKTeX или TeX Live
    exit /b 1
)
goto :eof

:compile_report
echo 📚 Компиляция пояснительной записки...
echo    Первая компиляция...
pdflatex -interaction=nonstopmode %MAIN%.tex >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Ошибка первой компиляции
    exit /b 1
)

echo    Компиляция библиографии...
bibtex %MAIN% >nul 2>&1

echo    Вторая компиляция...
pdflatex -interaction=nonstopmode %MAIN%.tex >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Ошибка второй компиляции
    exit /b 1
)

echo    Третья компиляция...
pdflatex -interaction=nonstopmode %MAIN%.tex >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Ошибка третьей компиляции
    exit /b 1
)

if exist %MAIN%.pdf (
    echo ✅ Пояснительная записка успешно скомпилирована!
    for %%I in (%MAIN%.pdf) do echo    Размер файла: %%~zI байт
) else (
    echo ❌ PDF файл не создан
    exit /b 1
)
goto :eof

:compile_presentation
echo 🎯 Компиляция презентации...
pdflatex -interaction=nonstopmode %PRESENTATION%.tex >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Ошибка компиляции презентации
    exit /b 1
)

if exist %PRESENTATION%.pdf (
    echo ✅ Презентация успешно скомпилирована!
    for %%I in (%PRESENTATION%.pdf) do echo    Размер файла: %%~zI байт
) else (
    echo ❌ PDF файл не создан
    exit /b 1
)
goto :eof

:all
call :check_latex
if %errorlevel% neq 1 (
    echo 🚀 Компиляция всех документов...
    call :compile_report
    set report_success=%errorlevel%
    call :compile_presentation
    set presentation_success=%errorlevel%
    
    if !report_success! equ 0 if !presentation_success! equ 0 (
        echo 🎉 Все документы успешно скомпилированы!
    ) else (
        echo ❌ Некоторые документы не удалось скомпилировать
        exit /b 1
    )
)
goto end

:quick
call :check_latex
if %errorlevel% neq 1 (
    echo ⚡ Быстрая компиляция...
    pdflatex -interaction=nonstopmode %MAIN%.tex >nul 2>&1
    if %errorlevel% equ 0 (
        echo ✅ Быстрая компиляция завершена
    ) else (
        echo ❌ Ошибка быстрой компиляции
        exit /b 1
    )
)
goto end

:clean
echo 🧹 Очистка временных файлов...
del /Q *.aux *.log *.toc *.out *.bbl *.blg *.fls *.fdb_latexmk *.synctex.gz 2>nul
echo ✅ Временные файлы удалены
goto end

:view
if exist %MAIN%.pdf (
    echo 👀 Открытие %MAIN%.pdf...
    start %MAIN%.pdf
)
if exist %PRESENTATION%.pdf (
    echo 👀 Открытие %PRESENTATION%.pdf...
    start %PRESENTATION%.pdf
)
goto end

:presentation
call :check_latex
if %errorlevel% neq 1 (
    call :compile_presentation
)
goto end

:end
echo.
echo 🎉 Операция завершена!
echo.
