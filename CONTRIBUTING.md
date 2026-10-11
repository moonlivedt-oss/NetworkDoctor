# Участие в разработке

Спасибо за интерес к Сетевому доктору! Код - Python 3.10+ и PyQt6.

## Быстрый цикл

```powershell
git clone https://github.com/moonlivedt-oss/NetworkDoctor.git
cd NetworkDoctor
py -m pip install -e ".[dev]"
Запуск.bat          # окно (диагностика и быстрая починка)
py -m pytest -q     # тесты (то же гоняет CI на Windows, Python 3.11 и 3.12)
```

## Правила

- Сетевая логика - в `netdoctor/net/` без Qt, окно (`app.py`, `ui/`) только вызывает её.
  Чистую логику (разбор вывода команд, классификации) покрывайте тестами в `tests/` - без сети и
  без настоящих вызовов PowerShell.
- Команды - списком аргументов, без `shell=True`; значения в PowerShell - через `ps_quote`,
  хосты - через `valid_host`; утилиты - по полному пути из `System32`.
- Всё, что меняет систему, показывает, что произойдёт, просит согласия и делает бэкап в
  `logs/backups`.
- Видимый текст - по-русски, без эмодзи. Изменения - в `CHANGELOG.md`.

## Релиз

Версия - в `pyproject.toml` и `netdoctor/__init__.py`. Создайте релиз с тегом `vX.Y`
(`gh release create vX.Y`): CI соберёт `NetworkDoctor.exe` и приложит его к релизу с SHA256.
