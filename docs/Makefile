# Makefile для компиляции LaTeX документа
# Автор: Смирных Павел Ильич

# Основные файлы
MAIN = report
TEX = $(MAIN).tex
PDF = $(MAIN).pdf
AUX = $(MAIN).aux
LOG = $(MAIN).log
TOC = $(MAIN).toc
OUT = $(MAIN).out

# Компилятор
LATEX = pdflatex
BIBTEX = bibtex
LATEX_FLAGS = -interaction=nonstopmode -shell-escape

# Цели
.PHONY: all clean view help

all: $(PDF)

# Компиляция документа (двойной проход для оглавления)
$(PDF): $(TEX)
	$(LATEX) $(LATEX_FLAGS) $(TEX)
	$(BIBTEX) $(MAIN)
	$(LATEX) $(LATEX_FLAGS) $(TEX)
	$(LATEX) $(LATEX_FLAGS) $(TEX)

# Очистка временных файлов
clean:
	rm -f $(AUX) $(LOG) $(TOC) $(OUT) *.bbl *.blg *.fls *.fdb_latexmk *.synctex.gz

# Просмотр PDF файла
view: $(PDF)
	if command -v xdg-open > /dev/null 2>&1; then \
		xdg-open $(PDF); \
	elif command -v open > /dev/null 2>&1; then \
		open $(PDF); \
	elif command -s start > /dev/null 2>&1; then \
		start $(PDF); \
	else \
		echo "Не удалось найти программу для просмотра PDF"; \
	fi

# Быстрая компиляция (без библиографии)
quick: $(TEX)
	$(LATEX) $(LATEX_FLAGS) $(TEX)

# Проверка орфографии (если установлен aspell)
spellcheck:
	if command -v aspell > /dev/null 2>&1; then \
		aspell -c -r --lang=russian $(TEX); \
	else \
		echo "Aspell не установлен. Установите aspell для проверки орфографии."; \
	fi

# Подсчет статистики
stats:
	@echo "=== Статистика документа ==="
	@echo "Страниц: $$(pdfinfo $(PDF) 2>/dev/null | grep Pages | awk '{print $$2}' || echo 'N/A')"
	@echo "Слов: $$(pdftotext $(PDF) - 2>/dev/null | wc -w || echo 'N/A')"
	@echo "Символов: $$(pdftotext $(PDF) - 2>/dev/null | wc -m || echo 'N/A')"
	@echo "Размер файла: $$(ls -lh $(PDF) 2>/dev/null | awk '{print $$5}' || echo 'N/A')"

# Создание архива с документом
archive: $(PDF)
	tar -czf $(MAIN)_archive.tar.gz $(PDF) $(TEX) Makefile README.md

# Помощь
help:
	@echo "Доступные цели:"
	@echo "  all        - Компиляция полного документа (по умолчанию)"
	@echo "  quick      - Быстрая компиляция без библиографии"
	@echo "  clean      - Очистка временных файлов"
	@echo "  view       - Просмотр PDF файла"
	@echo "  spellcheck - Проверка орфографии"
	@echo "  stats      - Статистика документа"
	@echo "  archive    - Создание архива с документом"
	@echo "  help       - Показать эту справку"
