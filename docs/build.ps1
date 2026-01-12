# PowerShell скрипт для компиляции LaTeX документов
# Аналог Makefile для Windows
# Автор: Смирных Павел Ильич, 2026

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("all", "quick", "clean", "view", "presentation", "help")]
    [string]$Target = "help"
)

$MAIN = "report"
$PRESENTATION = "presentation"
$PDF_READER = "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"  # Укажите ваш PDF reader

function Write-Color-Output {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Test-LaTeX-Command {
    try {
        $null = Get-Command pdflatex -ErrorAction Stop
        return $true
    }
    catch {
        Write-Color-Output "❌ pdflatex не найден. Установите MiKTeX или TeX Live" "Red"
        return $false
    }
}

function Compile-Report {
    Write-Color-Output "📚 Компиляция пояснительной записки..." "Yellow"
    
    # Первая компиляция
    Write-Color-Output "   Первая компиляция..." "Gray"
    $result = Start-Process -FilePath "pdflatex" -ArgumentList "-interaction=nonstopmode", "$MAIN.tex" -Wait -PassThru -NoNewWindow
    if ($result.ExitCode -ne 0) {
        Write-Color-Output "❌ Ошибка первой компиляции" "Red"
        return $false
    }
    
    # Компиляция библиографии
    Write-Color-Output "   Компиляция библиографии..." "Gray"
    $result = Start-Process -FilePath "bibtex" -ArgumentList "$MAIN" -Wait -PassThru -NoNewWindow
    if ($result.ExitCode -ne 0) {
        Write-Color-Output "⚠️ Предупреждение при компиляции библиографии" "Yellow"
    }
    
    # Вторая компиляция
    Write-Color-Output "   Вторая компиляция..." "Gray"
    $result = Start-Process -FilePath "pdflatex" -ArgumentList "-interaction=nonstopmode", "$MAIN.tex" -Wait -PassThru -NoNewWindow
    if ($result.ExitCode -ne 0) {
        Write-Color-Output "❌ Ошибка второй компиляции" "Red"
        return $false
    }
    
    # Третья компиляция
    Write-Color-Output "   Третья компиляция..." "Gray"
    $result = Start-Process -FilePath "pdflatex" -ArgumentList "-interaction=nonstopmode", "$MAIN.tex" -Wait -PassThru -NoNewWindow
    if ($result.ExitCode -ne 0) {
        Write-Color-Output "❌ Ошибка третьей компиляции" "Red"
        return $false
    }
    
    # Проверка результата
    if (Test-Path "$MAIN.pdf") {
        Write-Color-Output "✅ Пояснительная записка успешно скомпилирована!" "Green"
        $size = [math]::Round((Get-Item "$MAIN.pdf").Length / 1MB, 2)
        Write-Color-Output "   Размер файла: $size MB" "Gray"
        return $true
    } else {
        Write-Color-Output "❌ PDF файл не создан" "Red"
        return $false
    }
}

function Compile-Presentation {
    Write-Color-Output "🎯 Компиляция презентации..." "Yellow"
    
    $result = Start-Process -FilePath "pdflatex" -ArgumentList "-interaction=nonstopmode", "$PRESENTATION.tex" -Wait -PassThru -NoNewWindow
    if ($result.ExitCode -ne 0) {
        Write-Color-Output "❌ Ошибка компиляции презентации" "Red"
        return $false
    }
    
    if (Test-Path "$PRESENTATION.pdf") {
        Write-Color-Output "✅ Презентация успешно скомпилирована!" "Green"
        $size = [math]::Round((Get-Item "$PRESENTATION.pdf").Length / 1MB, 2)
        Write-Color-Output "   Размер файла: $size MB" "Gray"
        return $true
    } else {
        Write-Color-Output "❌ PDF файл не создан" "Red"
        return $false
    }
}

function Clean-TempFiles {
    Write-Color-Output "🧹 Очистка временных файлов..." "Yellow"
    
    $tempFiles = @("*.aux", "*.log", "*.toc", "*.out", "*.bbl", "*.blg", "*.fls", "*.fdb_latexmk", "*.synctex.gz")
    
    foreach ($pattern in $tempFiles) {
        Remove-Item -Path $pattern -Force -ErrorAction SilentlyContinue
    }
    
    Write-Color-Output "✅ Временные файлы удалены" "Green"
}

function View-PDF {
    param([string]$FileName)
    
    if (Test-Path $FileName) {
        Write-Color-Output "👀 Открытие $FileName..." "Yellow"
        
        # Попытка открыть с помощью системной программы по умолчанию
        try {
            Start-Process -FilePath $FileName
        }
        catch {
            Write-Color-Output "❌ Не удалось открыть PDF файл" "Red"
        }
    } else {
        Write-Color-Output "❌ Файл $FileName не найден" "Red"
    }
}

function Show-Help {
    Write-Color-Output "📚 PowerShell скрипт для компиляции LaTeX документов" "Cyan"
    Write-Color-Output "Автор: Смирных Павел Ильич, 2026" "Gray"
    Write-Host ""
    Write-Color-Output "Использование:" "White"
    Write-Host "   .\build.ps1 [цель]"
    Write-Host ""
    Write-Color-Output "Доступные цели:" "White"
    Write-Host "   all         - Компиляция всех документов (по умолчанию)"
    Write-Host "   quick       - Быстрая компиляция без библиографии"
    Write-Host "   clean       - Очистка временных файлов"
    Write-Host "   view        - Просмотр скомпилированных документов"
    Write-Host "   presentation - Компиляция только презентации"
    Write-Host "   help        - Показать эту справку"
    Write-Host ""
    Write-Color-Output "Примеры:" "White"
    Write-Host "   .\build.ps1 all"
    Write-Host "   .\build.ps1 clean"
    Write-Host "   .\build.ps1 view"
}

# Основная логика
if (-not (Test-LaTeX-Command)) {
    exit 1
}

switch ($Target) {
    "all" {
        Write-Color-Output "🚀 Компиляция всех документов..." "Cyan"
        $reportSuccess = Compile-Report
        $presentationSuccess = Compile-Presentation
        
        if ($reportSuccess -and $presentationSuccess) {
            Write-Color-Output "🎉 Все документы успешно скомпилированы!" "Green"
        } else {
            Write-Color-Output "❌ Некоторые документы не удалось скомпилировать" "Red"
            exit 1
        }
    }
    
    "quick" {
        Write-Color-Output "⚡ Быстрая компиляция..." "Cyan"
        $result = Start-Process -FilePath "pdflatex" -ArgumentList "-interaction=nonstopmode", "$MAIN.tex" -Wait -PassThru -NoNewWindow
        if ($result.ExitCode -eq 0 -and (Test-Path "$MAIN.pdf")) {
            Write-Color-Output "✅ Быстрая компиляция завершена" "Green"
        } else {
            Write-Color-Output "❌ Ошибка быстрой компиляции" "Red"
            exit 1
        }
    }
    
    "clean" {
        Clean-TempFiles
    }
    
    "view" {
        if (Test-Path "$MAIN.pdf") {
            View-PDF "$MAIN.pdf"
        }
        if (Test-Path "$PRESENTATION.pdf") {
            View-PDF "$PRESENTATION.pdf"
        }
    }
    
    "presentation" {
        Compile-Presentation
    }
    
    "help" {
        Show-Help
    }
    
    default {
        Show-Help
    }
}
