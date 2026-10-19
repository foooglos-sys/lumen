import sqlite3

from flask import g

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS client_bans (
    user_id INTEGER PRIMARY KEY,
    hwid TEXT,
    actor_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS client_bans_hwid ON client_bans(hwid);
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY,
    nick           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email          TEXT,
    password_hash  TEXT NOT NULL,
    license_key    TEXT UNIQUE,
    sub_until      TEXT,              -- NULL: нет подписки, '9999-12-31': навсегда
    hwid           TEXT,
    hwid_reset_at  TEXT,
    role           TEXT,              -- NULL: игрок; 'youtuber', 'admin', 'owner' (+ всегда owner из config.OWNERS)
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS products (
    id        INTEGER PRIMARY KEY,
    category  TEXT NOT NULL,
    slug      TEXT NOT NULL UNIQUE,
    name      TEXT NOT NULL,
    price     INTEGER NOT NULL,
    old_price INTEGER,
    days      INTEGER,                -- дней подписки, 0 — навсегда, NULL — не подписка
    blurb     TEXT NOT NULL,
    perks     TEXT NOT NULL DEFAULT '',
    icon      TEXT NOT NULL,
    tag       TEXT,
    sort      INTEGER NOT NULL DEFAULT 0,
    active    INTEGER NOT NULL DEFAULT 1,  -- 0: скрыт из магазина (удалять нельзя, если есть заказы)
    funpay_url TEXT                        -- ссылка на лот FunPay; пусто — общая ссылка из настроек
);

CREATE TABLE IF NOT EXISTS orders (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    price      INTEGER NOT NULL,
    promo      TEXT,
    status     TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tickets (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    category   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY,
    ticket_id  INTEGER NOT NULL REFERENCES tickets(id),
    user_id    INTEGER NOT NULL REFERENCES users(id),
    body       TEXT NOT NULL,
    is_staff   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ключи активации продаются на FunPay; генерируются папками, активированный ключ удаляется
CREATE TABLE IF NOT EXISTS key_folders (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    days       INTEGER NOT NULL,          -- 0: навсегда
    created    INTEGER NOT NULL,          -- сколько ключей сгенерировано
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS activation_keys (
    code       TEXT PRIMARY KEY,
    folder_id  INTEGER NOT NULL REFERENCES key_folders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS key_activations (
    id           INTEGER PRIMARY KEY,
    code         TEXT NOT NULL,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    days         INTEGER NOT NULL,
    folder_name  TEXT NOT NULL,
    activated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS promocodes (
    code       TEXT PRIMARY KEY COLLATE NOCASE,
    discount   INTEGER NOT NULL,          -- скидка в процентах
    max_uses   INTEGER,                   -- NULL: без ограничений
    uses       INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,                      -- 'YYYY-MM-DD' включительно, NULL: бессрочный
    active     INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER REFERENCES users(id),   -- кто создал (ютуберу видны только свои)
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- журнал действий: входы, активации, всё, что делает команда в админке
CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    user_id    INTEGER,
    nick       TEXT,
    action     TEXT NOT NULL,
    details    TEXT NOT NULL DEFAULT '',
    ip         TEXT
);
CREATE INDEX IF NOT EXISTS logs_action ON logs (action);
"""

# Стартовые товары для пустой базы. Дальше они редактируются в админке.
# category, slug, name, price, old_price, days, blurb, perks, icon (путь текстуры), tag, sort
PRODUCTS = [
    ("subs", "month", "30 дней", 199, None, 30,
     "Попробовать и понять, ваше ли это.",
     "Все модули и обновления\nВсе версии игры\nПоддержка в тикетах", "item/iron_ingot", None, 1),
    ("subs", "quarter", "90 дней", 449, 597, 90,
     "На сезон. Выходит на четверть дешевле.",
     "Всё из 30 дней\nРанний доступ к бета-сборкам\nОдин бесплатный сброс HWID сверху", "item/gold_ingot", "Берут чаще всего", 2),
    ("subs", "lifetime", "Навсегда", 1290, None, 0,
     "Один раз — и забыть про продления.",
     "Всё из 90 дней\nВсе будущие версии\nПриоритет в поддержке\nРоль в Discord", "item/nether_star", None, 3),
    ("extra", "hwid-reset", "Сброс HWID", 99, None, None,
     "Сменили ПК раньше, чем прошла неделя с прошлого сброса.", "", "item/name_tag", None, 10),
]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(config.DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(config.DATABASE)
    existed = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    conn.executescript(SCHEMA)
    # база, созданная до появления почты, получает колонку без пересоздания
    if "email" not in {row[1] for row in conn.execute("PRAGMA table_info(users)")}:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users (email COLLATE NOCASE)")
    if "role" not in {row[1] for row in conn.execute("PRAGMA table_info(users)")}:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT")
    if "created_by" not in {row[1] for row in conn.execute("PRAGMA table_info(promocodes)")}:
        conn.execute("ALTER TABLE promocodes ADD COLUMN created_by INTEGER REFERENCES users(id)")
    product_cols = {row[1] for row in conn.execute("PRAGMA table_info(products)")}
    if "active" not in product_cols:
        conn.execute("ALTER TABLE products ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
    if "funpay_url" not in product_cols:
        conn.execute("ALTER TABLE products ADD COLUMN funpay_url TEXT")
    # стартовые товары и промокоды кладутся только в только что созданную таблицу,
    # дальше ими управляет админка (и удалённое не воскресает после перезапуска)
    if "products" not in existed:
        conn.executemany(
            "INSERT INTO products (category, slug, name, price, old_price, days, blurb, perks, icon, tag, sort)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            PRODUCTS,
        )
    if "promocodes" not in existed:
        conn.executemany("INSERT INTO promocodes (code, discount) VALUES (?, ?)",
                         getattr(config, "PROMOCODES", {}).items())
    conn.execute("UPDATE users SET role = NULL WHERE LOWER(nick) = 'globalklap'")
    conn.commit()
    conn.close()
