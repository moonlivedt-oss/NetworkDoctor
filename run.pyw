# -*- coding: utf-8 -*-
"""Launcher NetworkDoctor.

Запускает пакет `netdoctor` из корня проекта. Отдельный файл нужен, чтобы
автозапуск и .bat-файлы могли стартовать приложение по абсолютному пути,
не завися от текущей папки. Расширение .pyw → запуск через pythonw без консоли.

Флаг --tray (для автозапуска) стартует приложение свёрнутым в трей.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netdoctor.app import main  # noqa: E402 — после правки sys.path

if __name__ == "__main__":
    main()
