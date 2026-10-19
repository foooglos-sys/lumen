"""Значения по умолчанию и то, что нельзя менять из админки.

Название, тексты, версии, статус, ссылки, видео, фон, преимущества, вопросы,
товары и промокоды настраиваются в админке (/admin → Настройки, Товары, Промокоды).
Здесь они только стартовые: действуют, пока в админке ничего не сохранено.
"""
import os

CLIENT_NAME = "Lumen"
CLIENT_TAGLINE = "Клиент для Minecraft, который не мешает играть: чистый интерфейс и стабильный FPS на любом железе."
CLIENT_VERSION = "2.4.1"
MC_VERSIONS = "1.16.5 – 1.21.11"
# "ok" — работает, "update" — выходит обновление, "down" — временно недоступен
CLIENT_STATUS = "ok"
UPDATED_AT = "24 сентября"

# Прямая ссылка на лаунчер (выдаётся только с активной подпиской)
DOWNLOAD_URL = "https://example.com/lumen-launcher.exe"

DISCORD_URL = "https://discord.gg/"
TELEGRAM_URL = "https://t.me/"

# Главные владельцы (роль owner): доступ ко всему. Через сайт их не снять — только здесь.
# Остальные роли, включая owner, выдаёт владелец в панели → Пользователи.
# Добавлять только уже зарегистрированные ники.
OWNERS = {"Dozzya"}

# Ютубер: скидка его промокода и сколько промокодов он может создать
YOUTUBER_PROMO_DISCOUNT = 5
YOUTUBER_PROMO_LIMIT = 1

# Сброс HWID бесплатно раз в столько дней (чаще — платно в магазине)
HWID_RESET_DAYS = 7

# Стартовые промокоды для новой базы: промокод -> скидка в процентах
PROMOCODES = {"DUSK10": 10, "START": 5}

# Видео на главной: ссылка на YouTube (watch / youtu.be / shorts) или прямая ссылка на .mp4 / .webm.
# Сейчас стоит официальный трейлер Minecraft как заглушка — заменить на обзор клиента.
VIDEO_URL = "https://www.youtube.com/watch?v=LtgmcmhKO8s"

# Картинки: текстуры из ресурсов игры
TEXTURES_URL = "https://raw.githubusercontent.com/InventivetalentDev/minecraft-assets/1.20.1/assets/minecraft/textures"

DATABASE = os.path.join(os.path.dirname(__file__), "site.db")


def _secret_key():
    """Ключ подписи сессий: из переменной SECRET_KEY, иначе случайный, один раз созданный в .secret_key.
    Кто знает этот ключ — может войти под любым аккаунтом, поэтому в коде его быть не должно."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(os.path.dirname(__file__), ".secret_key")
    try:
        with open(path, encoding="ascii") as f:
            key = f.read().strip()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        pass
    import secrets
    key = secrets.token_hex(32)
    with open(path, "w", encoding="ascii") as f:
        f.write(key)
    return key


SECRET_KEY = _secret_key()


def _signing_key():
    """Ключ Ed25519 для подписи ответов лаунчеру: из переменной SIGNING_KEY (hex), иначе .signing_key.
    Открытая половина пишется в signing_key.pub — её вшивают в лаунчер при сборке.
    Сменили ключ — старые лаунчеры перестанут доверять сайту, нужна пересборка."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    here = os.path.dirname(__file__)
    path = os.path.join(here, ".signing_key")
    raw = os.environ.get("SIGNING_KEY")
    if raw is None and os.path.exists(path):
        with open(path, encoding="ascii") as f:
            raw = f.read().strip()
    if raw is None:
        key = Ed25519PrivateKey.generate()
        with open(path, "w", encoding="ascii") as f:
            f.write(key.private_bytes_raw().hex())
    else:
        # битый ключ — падаем, а не генерируем новый: иначе все выданные лаунчеры молча сломаются
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw))
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    with open(os.path.join(here, "signing_key.pub"), "w", encoding="ascii") as f:
        f.write(pub + "\n")
    return key


SIGNING_KEY = _signing_key()

# За nginx / Cloudflare: 1 — брать IP игрока из X-Forwarded-For (иначе лимиты попыток считаются на IP прокси)
TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"
# Сайт открыт по https: кука сессии уходит только по https
HTTPS = os.environ.get("HTTPS") == "1"
