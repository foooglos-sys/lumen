"""Настройки сайта, которые админ меняет в админке.

Значения хранятся в таблице settings. Пока ключ ни разу не сохраняли, берётся значение
по умолчанию: из DEFAULTS ниже, а если там нет — из config.py.
В шаблонах всё доступно как cfg.ИМЯ, в коде — как settings.current().ИМЯ.
"""
import json

from flask import g

import config
from db import get_db

DEFAULTS = {
    "HERO_LINE": "Играй по-своему",
    "HERO_IMAGE": "",
    "CABINET_IMAGE": "",
    "ADMIN_IMAGE": "",
    "FUNPAY_URL": "https://funpay.com/",
    "CRYSTALPAY_LOGIN": "",
    "CRYSTALPAY_SECRET": "",
    "SBP_PHONE": "+7 (999) 000-00-00",
    "SBP_BANK": "Т-Банк / Сбер",
    "ADVANTAGES": [
        {"icon": "item/clock_00", "title": "Стабильный FPS",
         "text": "Оптимизации рендера и чанков из коробки. На слабых ноутбуках разница заметна с первой минуты."},
        {"icon": "item/filled_map", "title": "Свой интерфейс",
         "text": "Каждый элемент HUD двигается прямо в игре: размер, прозрачность, привязка к краям экрана."},
        {"icon": "item/compass_00", "title": "Одна сборка на все версии",
         "text": "От 1.16.5 до 1.21.11. Лаунчер сам скачает нужную версию игры и Java."},
    ],
    "FAQ": [
        {"q": "Какие версии поддерживаются?",
         "a": "Java Edition 1.16.5 – 1.21.11. Нужную версию выбираете в лаунчере, всё остальное он скачает сам."},
        {"q": "Можно ли пользоваться на двух компьютерах?",
         "a": "Ключ привязывается к одному ПК. Сменить компьютер можно в кабинете — бесплатно раз в 7 дней."},
        {"q": "Что будет, когда подписка закончится?",
         "a": "Клиент перестанет запускаться. Продлите — и всё заработает как было, ключ останется тем же."},
        {"q": "Оплатил, но ничего не пришло",
         "a": "Подписка активируется сразу после оплаты. Если в кабинете её нет — откройте тикет с номером заказа, разберёмся."},
    ],
}

# ключ -> (подпись, тип, подсказка). Типы: str, text, int, bool, url, status, image, advantages, faq
FIELDS = {
    "CLIENT_NAME": ("Название клиента", "str", "Логотип, заголовок первого экрана, вкладка браузера"),
    "HERO_LINE": ("Первая строка заголовка", "str", "Вторая строка всегда «вместе с <название>»"),
    "CLIENT_TAGLINE": ("Подзаголовок", "text", "Текст под заголовком на главной"),
    "HERO_IMAGE": ("Фон первого экрана", "image", "JPG, PNG или WebP до 8 МБ. Лучше 1920×1080 и темнее"),
    "VIDEO_URL": ("Видео обзор", "url", "Ссылка на YouTube или прямая ссылка на .mp4 / .webm. Пусто — блок скрыт"),
    "CLIENT_VERSION": ("Версия клиента", "str", "Например 2.4.1"),
    "MC_VERSIONS": ("Версии Minecraft", "str", "Например 1.16.5 – 1.21.4"),
    "CLIENT_STATUS": ("Статус клиента", "status", ""),
    "UPDATED_AT": ("Последнее обновление", "str", "Показывается в статистике на главной, например «24 сентября»"),
    "DOWNLOAD_URL": ("Ссылка на лаунчер", "url", "Выдаётся только пользователям с активной подпиской"),
    "DISCORD_URL": ("Discord", "url", ""),
    "TELEGRAM_URL": ("Telegram", "url", ""),
    "FUNPAY_URL": ("Ссылка на FunPay", "url", "Профиль продавца или общий лот. Если у товара своя ссылка на лот — используется она"),
    "CRYSTALPAY_LOGIN": ("CrystalPay Login", "str", "Логин кассы CrystalPay (crystalpay.io)"),
    "CRYSTALPAY_SECRET": ("CrystalPay Secret", "str", "Секретный ключ кассы CrystalPay (Salt 1)"),
    "SBP_PHONE": ("Телефон для СБП (прямой)", "str", "Номер телефона для ручного перевода по СБП"),
    "SBP_BANK": ("Банк для СБП", "str", "Банк получателя (Т-Банк, Сбер и т.д.)"),
    "CABINET_IMAGE": ("Баннер в кабинете", "image", "Показывается над профилем игрока"),
    "ADMIN_IMAGE": ("Баннер в админке", "image", "Показывается на обзоре админки"),
    "HWID_RESET_DAYS": ("Бесплатный сброс HWID раз в, дней", "int", ""),
    "ADVANTAGES": ("Преимущества на главной", "advantages", ""),
    "FAQ": ("Частые вопросы", "faq", ""),
}

SECTIONS = [
    ("Главная", ["CLIENT_NAME", "HERO_LINE", "CLIENT_TAGLINE", "HERO_IMAGE", "VIDEO_URL"]),
    ("Клиент", ["CLIENT_VERSION", "MC_VERSIONS", "CLIENT_STATUS", "UPDATED_AT", "DOWNLOAD_URL"]),
    ("Ссылки", ["DISCORD_URL", "TELEGRAM_URL"]),
    ("Оплата и лицензии", ["FUNPAY_URL", "CRYSTALPAY_LOGIN", "CRYSTALPAY_SECRET", "SBP_PHONE", "SBP_BANK", "HWID_RESET_DAYS"]),
    ("Картинки", ["CABINET_IMAGE", "ADMIN_IMAGE"]),
    ("Преимущества", ["ADVANTAGES"]),
    ("Вопросы", ["FAQ"]),
]

# картинки по умолчанию для полей типа image (лежат в static/)
IMAGE_DEFAULTS = {"HERO_IMAGE": "img/hero-night.jpg", "CABINET_IMAGE": "img/cabinet.jpg", "ADMIN_IMAGE": "img/admin.jpg"}

STATUSES = {"ok": "Работает", "update": "Выходит обновление", "down": "Временно недоступен"}


def default(key):
    if key in DEFAULTS:
        return DEFAULTS[key]
    return getattr(config, key)


def _decode(key, raw):
    kind = FIELDS[key][1]
    if kind == "int":
        return int(raw)
    if kind == "bool":
        return raw == "1"
    if kind in ("advantages", "faq"):
        return json.loads(raw)
    return raw


def _encode(key, value):
    kind = FIELDS[key][1]
    if kind == "bool":
        return "1" if value else "0"
    if kind in ("advantages", "faq"):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


class SiteSettings:
    """cfg.ИМЯ: сначала сохранённое в админке, потом значение по умолчанию, потом config.py."""

    def __init__(self, saved):
        self._saved = saved

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name in self._saved:
            return self._saved[name]
        if name in DEFAULTS:
            return DEFAULTS[name]
        return getattr(config, name)

    @property
    def CLIENT_STATUS_TEXT(self):
        return STATUSES


def current():
    if "site_settings" not in g:
        saved = {}
        for row in get_db().execute("SELECT key, value FROM settings"):
            if row["key"] in FIELDS:
                try:
                    saved[row["key"]] = _decode(row["key"], row["value"])
                except (ValueError, TypeError):
                    pass  # битое значение — остаётся значение по умолчанию
        g.site_settings = SiteSettings(saved)
    return g.site_settings


def save(values):
    db = get_db()
    db.executemany(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [(k, _encode(k, v)) for k, v in values.items() if k in FIELDS],
    )
    db.commit()
    g.pop("site_settings", None)
