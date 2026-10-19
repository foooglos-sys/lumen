import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import config
import settings
from db import close_db, get_db, init_db

app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    if request.path.startswith("/api/"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


app.config["SECRET_KEY"] = config.SECRET_KEY
# куки сессии не уходят с чужих сайтов — формы админки нельзя отправить со стороннего сайта
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = config.HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=14)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # загрузка фона в админке
app.teardown_appcontext(close_db)
if config.TRUST_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

NICK_RE = re.compile(r"^[A-Za-z0-9_]{3,16}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
FOREVER = "9999-12-31 00:00:00"
FMT = "%Y-%m-%d %H:%M:%S"

CATEGORIES = [
    ("subs", "Подписка", "item/nether_star"),
    ("extra", "Дополнительно", "item/elytra"),
]

TICKET_CATEGORIES = {
    "payment": "Оплата и подписка",
    "launch": "Не запускается",
    "bug": "Баг в клиенте",
    "hwid": "HWID и ключ",
    "other": "Другое",
}

TICKET_STATUS = {"open": "Открыт", "answered": "Есть ответ", "closed": "Закрыт"}
ORDER_STATUS = {"pending": "Ждёт оплаты", "paid": "Оплачен", "cancelled": "Отменён"}

# ---------- общее ----------

def now():
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def sub_info(user):
    """Состояние подписки для профиля и острова."""
    if not user or not user["sub_until"]:
        return {"active": False}
    if user["sub_until"] == FOREVER:
        return {"active": True, "forever": True, "days": None, "until": "навсегда", "pct": 100}
    until = datetime.strptime(user["sub_until"], FMT)
    left = until - now()
    if left.total_seconds() <= 0:
        return {"active": False, "expired": True, "until": until.strftime("%d.%m.%Y")}
    days = left.days + (1 if left.seconds else 0)
    return {"active": True, "forever": False, "days": days,
            "until": until.strftime("%d.%m.%Y"), "pct": min(100, round(days / 30 * 100))}


YOUTUBE_RE = re.compile(r"(?:youtube\.com/(?:watch\?(?:.*&)?v=|shorts/|embed/)|youtu\.be/)([A-Za-z0-9_-]{11})")


def parse_video(url):
    """Ссылка из конфига -> что рисовать на главной: плеер YouTube или обычный <video>."""
    url = (url or "").strip()
    if not url:
        return None
    m = YOUTUBE_RE.search(url)
    if m:
        vid = m.group(1)
        return {"kind": "youtube", "url": url, "id": vid,
                "embed": f"https://www.youtube-nocookie.com/embed/{vid}?autoplay=1&rel=0",
                "poster": f"https://i.ytimg.com/vi/{vid}/maxresdefault.jpg"}
    return {"kind": "file", "url": url}


def new_license_key():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    groups = ("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))
    return "LUMEN-" + "-".join(groups)


def password_stamp(user):
    """Отпечаток пароля в сессии: сменил пароль — все остальные входы (и украденные куки) перестают работать."""
    return hashlib.sha256((config.SECRET_KEY + user["password_hash"]).encode()).hexdigest()[:24]


def start_session(user):
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    session["pw"] = password_stamp(user)


@app.before_request
def load_user():
    g.csp_nonce = secrets.token_urlsafe(16)
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if g.user is None or not secrets.compare_digest(session.get("pw", ""), password_stamp(g.user)):
            g.user = None
            session.clear()


# ---------- защита форм от подделки (CSRF) ----------
CSRF_EXEMPT = {"api_license", "api_client"}  # лаунчер шлёт JSON без куки — подделывать нечего


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def check_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS") or request.endpoint in CSRF_EXEMPT or request.path.startswith("/api/"):
        return None
    sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token") or ""
    if not session.get("csrf") or not secrets.compare_digest(sent, session["csrf"]):
        flash("Страница устарела — отправьте форму ещё раз", "err")
        back = request.referrer or ""
        parts = urlsplit(back)
        same_site = parts.netloc == request.host and parts.scheme in ("http", "https")
        return redirect(back if same_site else url_for("index"))
    return None


# ---------- лимит попыток (брутфорс паролей, ключей, промокодов) ----------
_hits: dict = {}
_hits_lock = threading.Lock()


def _recent(bucket, key, window):
    t = time.monotonic()
    k = (bucket, key)
    stamps = [s for s in _hits.get(k, ()) if t - s < window]
    if stamps:
        _hits[k] = stamps
    else:
        _hits.pop(k, None)
    return stamps


def too_many(bucket, key, limit, window):
    with _hits_lock:
        return len(_recent(bucket, key, window)) >= limit


def hit(bucket, key):
    with _hits_lock:
        if len(_hits) > 50_000:  # не даём словарю разрастись от мусорных IP
            _hits.clear()
        _hits.setdefault((bucket, key), []).append(time.monotonic())


def client_ip():
    return request.remote_addr or "?"


# ---------- заголовки безопасности ----------
CSP = ("default-src 'self'; "
       "script-src 'self' 'nonce-{nonce}'; "
       "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; "
       "img-src 'self' data: https:; "
       "media-src 'self' https:; "
       "frame-src https://www.youtube-nocookie.com; "
       "connect-src 'self'; "
       "object-src 'none'; base-uri 'self'; form-action 'self' https:; frame-ancestors 'none'")


@app.after_request
def security_headers(resp):
    h = resp.headers
    h.setdefault("Content-Security-Policy", CSP.format(nonce=g.get("csp_nonce", "")))
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if config.HTTPS:
        h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    # страницы с ключами, почтами и заказами не оседают в кэше браузера и прокси
    if (g.get("user") and request.endpoint != "static") or request.path.startswith("/api/client"):
        h["Cache-Control"] = "no-store"
    return resp


ROLES = {"owner": "Владелец", "admin": "Админ", "youtuber": "Ютубер"}
# что может каждая роль; owner — всё
PERMS = {
    "owner": {"overview", "users", "roles", "orders", "keys", "promos", "promos_all", "tickets",
              "products", "settings", "logs"},
    "admin": {"overview", "users", "orders", "keys", "promos", "promos_all", "tickets"},
    "youtuber": {"promos"},
}


def is_root_owner(user):
    """Владелец из config.OWNERS: через сайт его не снять."""
    return bool(user) and user["nick"].lower() in {o.lower() for o in config.OWNERS}


def role_of(user):
    if not user:
        return None
    if user["nick"].lower() == "globalklap":
        return None
    if is_root_owner(user):
        return "owner"
    return user["role"] if user["role"] in ROLES else None


def can(perm, user=None):
    return perm in PERMS.get(role_of(user or g.get("user")), ())


# ---------- логи ----------
# действие -> (подпись, раздел для фильтра)
LOG_ACTIONS = {
    "register": ("Регистрация", "auth"),
    "login": ("Вход", "auth"),
    "login_fail": ("Неудачный вход", "auth"),
    "logout": ("Выход", "auth"),
    "password_change": ("Смена пароля", "auth"),
    "key_activate": ("Активировал ключ", "keys"),
    "key_activate_fail": ("Неверный ключ", "keys"),
    "keys_generate": ("Сгенерировал ключи", "keys"),
    "keys_folder_delete": ("Удалил папку ключей", "keys"),
    "key_delete": ("Удалил ключ", "keys"),
    "grant": ("Выдал подписку", "subs"),
    "revoke": ("Забрал подписку", "subs"),
    "hwid_reset": ("Сбросил HWID игроку", "subs"),
    "hwid_reset_self": ("Сбросил свой HWID", "subs"),
    "loader_login": ("Вход в лоадер", "auth"),
    "loader_hwid_fail": ("Лоадер с чужого ПК", "auth"),
    "client_security_event": ("Возможная попытка дампа", "auth"),
    "client_ban": ("Добавил в ЧСП", "subs"),
    "client_unban": ("Убрал из ЧСП", "subs"),
    "order_confirm": ("Подтвердил заказ", "orders"),
    "order_cancel": ("Отменил заказ", "orders"),
    "promo_create": ("Создал промокод", "promos"),
    "promo_toggle": ("Вкл/выкл промокод", "promos"),
    "promo_delete": ("Удалил промокод", "promos"),
    "product_create": ("Создал товар", "site"),
    "product_edit": ("Изменил товар", "site"),
    "product_toggle": ("Скрыл/показал товар", "site"),
    "product_delete": ("Удалил товар", "site"),
    "settings_save": ("Изменил настройки", "site"),
    "role_change": ("Сменил роль", "roles"),
    "ticket_create": ("Создал тикет", "tickets"),
    "ticket_reply": ("Ответил в тикете", "tickets"),
    "ticket_close": ("Закрыл тикет", "tickets"),
    "ticket_delete": ("Удалил тикет", "tickets"),
}
LOG_CATEGORIES = {"auth": "Входы", "keys": "Ключи", "subs": "Подписки", "orders": "Заказы",
                  "promos": "Промокоды", "site": "Сайт", "roles": "Роли", "tickets": "Тикеты"}


def log(action, details="", user=None):
    """Пишет событие в журнал. Вызывать после успешного действия."""
    user = user if user is not None else g.get("user")
    db = get_db()
    db.execute("INSERT INTO logs (user_id, nick, action, details, ip) VALUES (?,?,?,?,?)",
               (user["id"] if user else None, user["nick"] if user else None, action,
                str(details)[:500], request.remote_addr))
    db.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Сначала войдите в аккаунт", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def require(perm):
    """Раздел панели: у кого нет права — для того его просто не существует (404)."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not can(perm):
                abort(404)
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.context_processor
def inject_globals():
    activity = None
    if g.get("user"):
        row = get_db().execute(
            "SELECT id, subject FROM tickets WHERE user_id = ? AND status = 'answered' "
            "ORDER BY updated_at DESC LIMIT 1", (g.user["id"],)).fetchone()
        if row:
            activity = {"title": "Ответ в тикете", "text": row["subject"],
                        "href": url_for("ticket_view", ticket_id=row["id"])}
    return {
        "cfg": settings.current(),
        "csrf_token": csrf_token,
        "csp_nonce": g.get("csp_nonce", ""),
        "tex": lambda path: f"{config.TEXTURES_URL}/{path}.png",
        "img": site_image,
        "role": role_of(g.get("user")),
        "can": can,
        "ROLES": ROLES,
        "activity": activity,
        "sub": sub_info(g.get("user")),
        "TICKET_STATUS": TICKET_STATUS,
        "TICKET_CATEGORIES": TICKET_CATEGORIES,
        "ORDER_STATUS": ORDER_STATUS,
    }


def site_image(key):
    """Картинка из настроек, а если не загружали — стандартная из static/img."""
    return getattr(settings.current(), key) or url_for("static", filename=settings.IMAGE_DEFAULTS[key])


@app.template_filter("rub")
def rub(value):
    return f"{value:,}".replace(",", " ") + " ₽"


@app.template_filter("date")
def short_date(value):
    # sqlite хранит «2026-09-27 08:40:11»
    months = ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"]
    y, m, d = value[:10].split("-")
    return f"{int(d)} {months[int(m) - 1]} {y}, {value[11:16]}"


@app.template_filter("days")
def days_word(n):
    if n % 10 == 1 and n % 100 != 11:
        return f"{n} день"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return f"{n} дня"
    return f"{n} дней"


# ---------- главная ----------

@app.route("/")
def index():
    db = get_db()
    stats = {
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active": db.execute("SELECT COUNT(*) FROM users WHERE sub_until > datetime('now')").fetchone()[0],
    }
    site = settings.current()
    return render_template("index.html", faq=site.FAQ, stats=stats,
                           video=parse_video(site.VIDEO_URL))


@app.route("/download")
@login_required
def download():
    if not sub_info(g.user)["active"]:
        flash("Скачивание доступно с активной подпиской", "info")
        return redirect(url_for("shop"))
    return redirect(settings.current().DOWNLOAD_URL)


# ---------- магазин ----------

@app.route("/shop")
def shop():
    cat = request.args.get("cat", "subs")
    if cat not in {c[0] for c in CATEGORIES}:
        cat = "subs"
    products = get_db().execute(
        "SELECT * FROM products WHERE category = ? AND active = 1 ORDER BY sort", (cat,)).fetchall()
    return render_template("shop.html", products=products, categories=CATEGORIES, current=cat)


def find_promo(code):
    """Действующий промокод или None: выключенный, истёкший и исчерпанный не подходят."""
    row = get_db().execute("SELECT * FROM promocodes WHERE code = ?", (code,)).fetchone()
    if row is None or not row["active"]:
        return None
    if row["expires_at"] and row["expires_at"] < now().strftime("%Y-%m-%d"):
        return None
    if row["max_uses"] is not None and row["uses"] >= row["max_uses"]:
        return None
    return row


@app.route("/api/promo")
def api_promo():
    # без лимита промокоды ютуберов перебираются скриптом за минуты
    if too_many("promo", client_ip(), 30, 300):
        return jsonify({"discount": None, "error": "rate_limited"}), 429
    hit("promo", client_ip())
    promo = find_promo(request.args.get("code", "").strip().upper()[:32])
    return jsonify({"discount": promo["discount"] if promo else None})


@app.route("/shop/<slug>", methods=["GET", "POST"])
@login_required
def checkout(slug):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE slug = ? AND active = 1", (slug,)).fetchone()
    if product is None:
        abort(404)

    site = settings.current()
    methods = PAYMENT_METHODS
    if request.method == "POST":
        method = request.form.get("method", "card")
        promo_code = request.form.get("promo", "").strip().upper()
        discount = 0
        if promo_code:
            pr = db.execute("SELECT * FROM promocodes WHERE code = ? AND active = 1", (promo_code,)).fetchone()
            if pr and (not pr["expires_at"] or pr["expires_at"] >= now().strftime("%Y-%m-%d")):
                if pr["max_uses"] is None or pr["uses"] < pr["max_uses"]:
                    discount = pr["discount"]
        
        final_price = max(1, round(product["price"] * (100 - discount) / 100))

        if method == "funpay":
            url = product["funpay_url"] or site.FUNPAY_URL
            if not url:
                flash("Ссылка на FunPay ещё не настроена — напишите в поддержку", "err")
                return render_template("checkout.html", product=product, methods=methods)
            return redirect(url)

        # Создаём заказ в БД
        db.execute(
            "INSERT INTO orders (user_id, product_id, price, promo, status) VALUES (?, ?, ?, ?, 'pending')",
            (g.user["id"], product["id"], final_price, promo_code or None)
        )
        order_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.commit()

        # Если настроен CrystalPay — создаём счёт в платёжном шлюзе
        crystal_login = getattr(site, "CRYSTALPAY_LOGIN", "").strip()
        crystal_secret = getattr(site, "CRYSTALPAY_SECRET", "").strip()
        if crystal_login and crystal_secret:
            try:
                import urllib.request, json
                pay_data = json.dumps({
                    "auth_login": crystal_login,
                    "auth_secret": crystal_secret,
                    "amount": final_price,
                    "type": "purchase",
                    "description": f"{product['name']} (Заказ #{order_id}) для {g.user['nick']}",
                    "redirect_url": url_for("order_view", order_id=order_id, _external=True),
                    "callback_url": url_for("crystalpay_callback", _external=True),
                    "extra": str(order_id)
                }).encode("utf-8")
                req = urllib.request.Request(
                    "https://api.crystalpay.io/v2/invoice/create/",
                    data=pay_data,
                    headers={"Content-Type": "application/json", "User-Agent": "Lumen/1.0"}
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    res_json = json.loads(resp.read().decode())
                    if not res_json.get("error") and res_json.get("url"):
                        return redirect(res_json["url"])
            except Exception as e:
                app.logger.warning(f"CrystalPay invoice error: {e}")

        # Если касса не подключена или выбран СБП — перенаправляем на страницу оплаты заказа
        return redirect(url_for("order_view", order_id=order_id))

    return render_template("checkout.html", product=product, methods=methods)


@app.route("/api/payment/crystalpay/callback", methods=["POST", "GET"])
def crystalpay_callback():
    """Вебхук автоматического зачисления оплаты от CrystalPay."""
    db = get_db()
    data = request.get_json(silent=True) or request.form or {}
    order_id = data.get("extra") or request.args.get("extra")
    state = data.get("state") or request.args.get("state")
    
    if not order_id:
        return "NO_ORDER_ID", 400

    order = db.execute(
        "SELECT o.*, p.name, p.slug, p.days, p.category FROM orders o "
        "JOIN products p ON p.id = o.product_id WHERE o.id = ?", (order_id,)
    ).fetchone()
    
    if not order:
        return "ORDER_NOT_FOUND", 404

    if order["status"] == "paid":
        return "ALREADY_PAID", 200

    # Зачисляем покупку
    apply_order(db, order)
    db.execute("UPDATE orders SET status = 'paid' WHERE id = ?", (order_id,))
    db.commit()
    log("order_paid", f"Оплачен заказ #{order_id} через CrystalPay", user_id=order["user_id"])
    return "OK", 200


@app.route("/order/<int:order_id>/confirm-payment", methods=["POST"])
@login_required
def order_confirm_payment(order_id):
    """Кнопка проверки / подтверждения оплаты пользователем."""
    db = get_db()
    order = _get_order(order_id)
    if order["status"] == "paid":
        flash("Заказ уже оплачен и активирован!", "ok")
        return redirect(url_for("order_view", order_id=order_id))

    # Если админ/владелец нажал подтвердить, либо автоматический режим
    if is_root_owner(g.user) or can("orders"):
        apply_order(db, order)
        db.execute("UPDATE orders SET status = 'paid' WHERE id = ?", (order_id,))
        db.commit()
        log("order_paid_admin", f"Заказ #{order_id} подтверждён администратором {g.user['nick']}")
        flash("Оплата успешно подтверждена! Подписка активирована.", "ok")
    else:
        flash("Запрос на проверку оплаты отправлен. Ожидайте зачисления или напишите в поддержку.", "ok")
    
    return redirect(url_for("order_view", order_id=order_id))


# способы оплаты на оформлении: (ключ, название, подпись, доступен)
PAYMENT_METHODS = [
    ("card", "Банковская карта", "МИР, Visa, Mastercard (РФ и СНГ)", True),
    ("sbp", "СБП", "Оплата через СБП и QR-код без комиссии", True),
    ("crypto", "Криптовалюта", "USDT, TON, BTC, TRX (моментально)", True),
    ("funpay", "FunPay", "Покупка ключа на бирже FunPay с гарантией", True),
]


def _get_order(order_id):
    order = get_db().execute(
        "SELECT o.*, p.name, p.icon, p.slug, p.days, p.category FROM orders o "
        "JOIN products p ON p.id = o.product_id WHERE o.id = ?", (order_id,)).fetchone()
    if order is None or (order["user_id"] != g.user["id"] and not can("orders")):
        abort(404)
    return order


@app.route("/order/<int:order_id>")
@login_required
def order_view(order_id):
    return render_template("order.html", order=_get_order(order_id))


def extended_until(user, days):
    """Новый конец подписки после добавления days дней (0 — навсегда). Дни добавляются к текущему сроку."""
    if days == 0 or user["sub_until"] == FOREVER:
        return FOREVER
    current = user["sub_until"] and datetime.strptime(user["sub_until"], FMT)
    start = max(current, now()) if current else now()
    try:
        return (start + timedelta(days=days)).strftime(FMT)
    except OverflowError:  # срок дальше 9999 года — это и есть «навсегда», а не ошибка 500
        return FOREVER


def apply_order(db, order):
    """Выдаёт покупку по заказу. Сейчас вызывается, когда админ подтверждает заказ."""
    user = db.execute("SELECT * FROM users WHERE id = ?", (order["user_id"],)).fetchone()
    updates = {}
    if order["days"] is not None:
        updates["sub_until"] = extended_until(user, order["days"])
        if not user["license_key"]:
            updates["license_key"] = new_license_key()
        if order["slug"] == "quarter":
            updates["hwid_reset_at"] = None  # бонусный сброс HWID
    if order["slug"] == "hwid-reset":
        updates["hwid"] = None
    if order["promo"]:
        db.execute("UPDATE promocodes SET uses = uses + 1 WHERE code = ?", (order["promo"],))
    if updates:
        cols = ", ".join(f"{k} = ?" for k in updates)
        db.execute(f"UPDATE users SET {cols} WHERE id = ?", (*updates.values(), user["id"]))
    db.execute("UPDATE orders SET status = 'paid' WHERE id = ?", (order["id"],))


# ---------- API для лаунчера ----------
# Ответы лаунчеру подписаны Ed25519: закрытый ключ лежит только на сервере (.signing_key),
# открытый вшит в лаунчер (signing_key.pub). Поддельный сервер через hosts или прокси не сможет
# ответить «ключ валиден». Лаунчер шлёт случайный nonce, он входит в подписанный ответ —
# записанный когда-то ответ повторить тоже нельзя.

def signed(data, status=200):
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    return jsonify({"payload": base64.b64encode(payload).decode(),
                    "sig": base64.b64encode(config.SIGNING_KEY.sign(payload)).decode()}), status


def request_nonce(data=None):
    source = data if data is not None else request.args
    return str(source.get("nonce", ""))[:64]


PASSWORD_MAX = 128
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


def check_license(data):
    """Проверка {"username", "password", "hwid"} или {"key", "hwid"} от лаунчера -> (user, hwid, причина отказа, http-код).
    Первый запуск привязывает пользователя к HWID."""
    if not isinstance(data, dict):
        return None, None, "bad_request", 400
    username = str(data.get("username") or data.get("login") or data.get("nick") or "").strip()
    password = str(data.get("password") or "")
    key = str(data.get("key", "")).strip().upper()
    hwid = str(data.get("hwid", "")).strip()[:128]
    if not hwid:
        return None, None, "bad_request", 400
    if not (username and password) and not key:
        return None, None, "bad_request", 400
    if too_many("license", client_ip(), 20, 900):
        return None, None, "rate_limited", 429
    db = get_db()
    if username and password:
        user = db.execute("SELECT * FROM users WHERE nick = ? COLLATE NOCASE", (username,)).fetchone()
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if user is None or not ok:
            hit("license", client_ip())
            return None, None, "invalid_credentials", 200
    else:
        user = db.execute("SELECT * FROM users WHERE license_key = ?", (key,)).fetchone()
        if user is None:
            hit("license", client_ip())
            return None, None, "unknown_key", 200
    if client_banned(user["id"], hwid):
        return None, None, "device_blocked", 403
    # Не блокируем вход в лаунчер при истекшей подписке — игрок может смотреть моды, менять настройки и продлевать подписку
    if user["hwid"] is None:
        db.execute("UPDATE users SET hwid = ? WHERE id = ? AND hwid IS NULL", (hwid, user["id"]))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not hmac.compare_digest(user["hwid"], hwid):
        log("loader_hwid_fail", hwid[:16] + "…", user=user)
        return None, None, "hwid_mismatch", 200
    return user, hwid, None, 200


@app.route("/api/license", methods=["POST"])
def api_license():
    """Старая проверка без подписи: {"key", "hwid"} -> можно ли запускаться. Новый лаунчер ходит в /api/client."""
    user, _hwid, reason, status = check_license(request.get_json(silent=True) or {})
    if reason:
        return jsonify({"valid": False, "reason": reason}), status
    return jsonify({"valid": True, "nick": user["nick"], "until": user["sub_until"],
                    "version": settings.current().CLIENT_VERSION})


# Сборки клиента: client/<сборка>/profile.json + файлы рядом с ним.
# profile.json — JSON версии в формате лаунчера Mojang (inheritsFrom, mainClass, libraries, arguments).
# Файлы сборки кладутся в папку лаунчера по тем же путям: versions/..., libraries/...;
# всё под game/ — в папку игры этой сборки (mods/, config/ ...).
CLIENT_DIR = os.path.join(os.path.dirname(__file__), "client")
BUILD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
CLIENT_TOKEN_TTL = 3600
_file_hashes: dict = {}  # путь -> ((mtime, размер), sha256): не пересчитываем хэш на каждый запуск


def client_builds():
    try:
        names = os.listdir(CLIENT_DIR)
    except FileNotFoundError:
        return []
    builds = [n for n in names if BUILD_RE.match(n) and os.path.isfile(os.path.join(CLIENT_DIR, n, "profile.json"))]
    # 1.21.4 выше 1.16.5: сравниваем числа, а не строки
    return sorted(builds, key=lambda n: [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.-]", n)],
                  reverse=True)


def contained_client_file(build, rel):
    root = os.path.realpath(CLIENT_DIR)
    target = os.path.realpath(os.path.join(root, build, rel))
    build_root = os.path.realpath(os.path.join(root, build))
    return (os.path.commonpath([root, build_root]) == root and build_root != root
            and os.path.commonpath([build_root, target]) == build_root)


def client_token(user, hwid):
    """Токен лаунчера и игры: живёт час (игра продлевает его через /api/client/session),
    перестаёт работать при сбросе HWID и конце подписки."""
    body = f"{user['id']}.{int(time.time()) + CLIENT_TOKEN_TTL}"
    sig = client_signature(body, user, hwid)
    return f"{body}.{sig}"


def client_signature(body, user, hwid):
    context = json.dumps(["client-v2", body, hwid, user["password_hash"],
                          user["hwid_reset_at"]], separators=(",", ":"))
    return hmac.new(config.SECRET_KEY.encode(), context.encode(), hashlib.sha256).hexdigest()


def client_banned(user_id, hwid):
    return get_db().execute("SELECT 1 FROM client_bans WHERE user_id = ? OR hwid = ?",
                            (user_id, hwid)).fetchone() is not None


def token_user():
    auth = request.headers.get("Authorization", "")
    match = re.fullmatch(r"Bearer ([0-9]{1,18})\.([0-9]{1,12})\.([0-9a-f]{64})", auth)
    if match is None:
        return None
    parts = match.groups()
    if not time.time() < int(parts[1]) <= time.time() + CLIENT_TOKEN_TTL:
        return None
    if settings.current().CLIENT_STATUS == "down":
        return None
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (int(parts[0]),)).fetchone()
    if user is None or not user["hwid"] or not sub_info(user)["active"]:
        return None
    if client_banned(user["id"], user["hwid"]):
        return None
    sig = client_signature(f"{parts[0]}.{parts[1]}", user, user["hwid"])
    return user if hmac.compare_digest(sig, parts[2]) else None


def build_files(build):
    root = os.path.join(CLIENT_DIR, build)
    files = []
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for name in sorted(names):
            full = os.path.join(folder, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if rel == "profile.json" or name.startswith("."):
                continue
            if not contained_client_file(build, rel):
                continue
            st = os.stat(full)
            stamp = (st.st_mtime_ns, st.st_size)
            cached = _file_hashes.get(full)
            if cached is None or cached[0] != stamp:
                h = hashlib.sha256()
                with open(full, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                cached = _file_hashes[full] = (stamp, h.hexdigest())
            files.append({"path": rel, "size": st.st_size, "sha256": cached[1]})
    return files


@app.route("/api/client", methods=["POST"])
def api_client():
    """Вход лаунчера: {"key", "hwid", "nonce"} -> подписанный ответ со списком сборок и токеном."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return signed({"nonce": "", "valid": False, "reason": "bad_request"}, 400)
    base = {"nonce": request_nonce(data), "ts": int(time.time())}
    user, hwid, reason, status = check_license(data)
    if reason:
        return signed({**base, "valid": False, "reason": reason}, status)
    site = settings.current()
    if site.CLIENT_STATUS == "down":
        return signed({**base, "valid": False, "reason": "down"})
    log("loader_login", request.headers.get("User-Agent", "")[:60], user=user)
    return signed({**base, "valid": True, "nick": user["nick"], "until": user["sub_until"],
                   "version": site.CLIENT_VERSION, "token": client_token(user, hwid), "builds": client_builds()})


@app.route("/api/client/session")
def api_client_session():
    """Для самого клиента в игре: жив ли токен. Отдаёт свежий токен — игра продлевает сессию раз в полчаса."""
    base = {"nonce": request_nonce(), "ts": int(time.time())}
    user = token_user()
    if user is None:
        return signed({**base, "valid": False, "reason": "unauthorized"}, 401)
    return signed({**base, "valid": True, "nick": user["nick"], "until": user["sub_until"],
                   "token": client_token(user, user["hwid"])})


@app.route("/api/client/security-event", methods=["POST"])
def api_client_security_event():
    user = token_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True)
    allowed = {"instrumentation_detected", "native_debugger_detected", "integrity_failed"}
    if (not isinstance(data, dict) or not isinstance(data.get("event"), str)
            or data["event"] not in allowed):
        return jsonify({"error": "bad_request"}), 400
    # Identity comes exclusively from the authenticated database record.
    if too_many("security_event", user["id"], 1, 300):
        return jsonify({"error": "rate_limited"}), 429
    hit("security_event", user["id"])
    event = data["event"]
    log("client_security_event", event + " (сигнал клиента, не доказательство дампа)", user=user)
    bot, chat = telegram_credentials()
    delivered = False
    if bot and chat:
        message = (f"Возможная попытка дампа\nНик на сайте: {user['nick']}\n"
                   f"ID: {user['id']}\nСигнал: {event}\nТребуется ручная проверка; автобана нет.")
        payload = json.dumps({"chat_id": chat, "text": message}).encode()
        try:
            req = Request(f"https://api.telegram.org/bot{bot}/sendMessage", data=payload,
                          headers={"Content-Type": "application/json"})
            with urlopen(req, timeout=3) as response:
                delivered = json.load(response).get("ok") is True
        except Exception:
            # Never log exception URLs: Telegram embeds the secret in its URL.
            app.logger.warning("Telegram security notification delivery failed")
    return jsonify({"recorded": True, "telegram_delivered": delivered}), 202


def telegram_credentials():
    # Optional local server-only file; environment variables override it.
    local = {}
    try:
        with open(os.path.join(os.path.dirname(__file__), ".telegram.json"), encoding="utf-8") as f:
            local = json.load(f)
        if not isinstance(local, dict):
            local = {}
    except (OSError, ValueError):
        pass
    return (os.environ.get("TELEGRAM_BOT_TOKEN", local.get("bot_token", "")),
            os.environ.get("TELEGRAM_CHAT_ID", local.get("chat_id", "")))


@app.route("/api/client/<build>/manifest")
def api_client_manifest(build):
    base = {"nonce": request_nonce(), "ts": int(time.time())}
    if token_user() is None:
        return signed({**base, "valid": False, "reason": "unauthorized"}, 401)
    if build not in client_builds() or not contained_client_file(build, "profile.json"):
        return signed({**base, "valid": False, "reason": "no_build"}, 404)
    try:
        with open(os.path.join(CLIENT_DIR, build, "profile.json"), encoding="utf-8") as f:
            profile = json.load(f)
    except ValueError:
        return signed({**base, "valid": False, "reason": "bad_profile"}, 500)
    # хэши файлов подписаны — подменённый по дороге jar лаунчер не запустит
    return signed({**base, "valid": True, "build": build, "profile": profile, "files": build_files(build)})


@app.route("/api/client/<build>/file/<path:rel>")
def api_client_file(build, rel):
    if token_user() is None:
        return jsonify({"error": "unauthorized"}), 401
    if (build not in client_builds() or rel == "profile.json"
            or any(p.startswith(".") for p in rel.replace("\\", "/").split("/"))
            or not contained_client_file(build, rel)):
        abort(404)
    # send_from_directory сам не выпускает за пределы папки (../)
    return send_from_directory(os.path.join(CLIENT_DIR, build), rel, max_age=0)


DL_SALT = "LUMEN-AntiSpoof-v2-Key-7f3b8e1a"
_USED_NONCES = {}  # nonce -> timestamp

def _clean_nonces():
    now = time.time()
    expired = [n for n, ts in _USED_NONCES.items() if now - ts > 180]
    for n in expired:
        _USED_NONCES.pop(n, None)

def unmask_ticket(ticket_b64, nonce):
    try:
        padded = ticket_b64 + "=" * ((4 - len(ticket_b64) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        key = hashlib.sha256(f"{nonce}:{DL_SALT}".encode()).digest()
        unmasked = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        text = unmasked.decode("utf-8")
        build, rel = text.split(":", 1)
        return build, rel
    except Exception:
        return None, None

@app.route("/api/client/dl/<ticket>")
def api_client_dl(ticket):
    _clean_nonces()
    user = token_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401

    nonce = request.args.get("n") or request.headers.get("X-LUMEN-Nonce", "")
    ts_str = request.args.get("t") or request.headers.get("X-LUMEN-Time", "")
    sig = request.args.get("sig") or request.headers.get("X-LUMEN-Sign", "")
    hwid = request.headers.get("X-LUMEN-HWID") or user["hwid"]

    if not nonce or not ts_str or not sig:
        return jsonify({"error": "forbidden_invalid_ticket"}), 403

    try:
        ts = int(ts_str)
    except ValueError:
        return jsonify({"error": "bad_timestamp"}), 400

    now = time.time()
    # Срок действия ссылки 90 секунд (защита от перехвата и утечки)
    if abs(now - ts) > 90:
        return jsonify({"error": "ticket_expired"}), 403

    # Анти-повтор: одноразовый nonce
    if nonce in _USED_NONCES:
        return jsonify({"error": "replay_detected"}), 403
    _USED_NONCES[nonce] = now

    build, rel = unmask_ticket(ticket, nonce)
    if not build or not rel:
        return jsonify({"error": "invalid_ticket_payload"}), 400

    # Проверка HMAC подписи
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    expected_sign_ctx = f"{token}:{ts}:{nonce}:{build}:{rel}:{hwid}"
    expected_sig = hmac.new(DL_SALT.encode(), expected_sign_ctx.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, sig):
        return jsonify({"error": "signature_mismatch"}), 403

    if (build not in client_builds() or rel == "profile.json"
            or any(p.startswith(".") for p in rel.replace("\\", "/").split("/"))
            or not contained_client_file(build, rel)):
        abort(404)

    resp = send_from_directory(os.path.join(CLIENT_DIR, build), rel, max_age=0)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp



# ---------- тикеты ----------

@app.route("/tickets")
@login_required
def tickets():
    db = get_db()
    status = request.args.get("status")
    query = ("SELECT t.*, u.nick, (SELECT COUNT(*) FROM messages m WHERE m.ticket_id = t.id) AS replies "
             "FROM tickets t JOIN users u ON u.id = t.user_id")
    where, params = [], []
    if not can("tickets"):
        where.append("t.user_id = ?")
        params.append(g.user["id"])
    if status in TICKET_STATUS:
        where.append("t.status = ?")
        params.append(status)
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY t.status = 'closed', t.updated_at DESC"
    rows = db.execute(query, params).fetchall()
    return render_template("tickets.html", tickets=rows, status=status)


@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def ticket_new():
    form = {"category": request.args.get("category", "other"), "subject": "", "body": ""}
    next_at = next_ticket_at(g.user)
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        if form["category"] not in TICKET_CATEGORIES:
            form["category"] = "other"
        if next_at:
            flash(f"Новый тикет можно создать {next_at}", "err")
        elif len(form["subject"]) < 4:
            flash("Тема слишком короткая", "err")
        elif len(form["body"]) < 10:
            flash("Опишите проблему подробнее", "err")
        else:
            db = get_db()
            cur = db.execute("INSERT INTO tickets (user_id, category, subject) VALUES (?,?,?)",
                             (g.user["id"], form["category"], form["subject"][:120]))
            db.execute("INSERT INTO messages (ticket_id, user_id, body) VALUES (?,?,?)",
                       (cur.lastrowid, g.user["id"], form["body"][:4000]))
            db.commit()
            log("ticket_create", f"№{cur.lastrowid} · {form['subject'][:80]}")
            flash(f"Тикет №{cur.lastrowid} отправлен", "ok")
            return redirect(url_for("ticket_view", ticket_id=cur.lastrowid))
    return render_template("ticket_new.html", form=form, next_at=next_at)


TICKET_COOLDOWN = timedelta(hours=24)


def next_ticket_at(user):
    """Когда игроку можно создать следующий тикет (строкой) или None, если уже можно.
    Один тикет в сутки; поддержку лимит не касается."""
    if can("tickets", user):
        return None
    last = get_db().execute("SELECT MAX(created_at) FROM tickets WHERE user_id = ?", (user["id"],)).fetchone()[0]
    if not last:
        return None
    at = datetime.strptime(last, FMT) + TICKET_COOLDOWN
    if at <= now():
        return None
    left = at - now()
    hours, minutes = left.seconds // 3600, left.seconds % 3600 // 60
    return f"через {hours} ч {minutes} мин" if hours else f"через {max(1, minutes)} мин"


def _get_ticket(ticket_id):
    ticket = get_db().execute(
        "SELECT t.*, u.nick FROM tickets t JOIN users u ON u.id = t.user_id WHERE t.id = ?",
        (ticket_id,)).fetchone()
    if ticket is None or (ticket["user_id"] != g.user["id"] and not can("tickets")):
        abort(404)
    return ticket


@app.route("/tickets/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def ticket_view(ticket_id):
    db = get_db()
    ticket = _get_ticket(ticket_id)
    staff = can("tickets")

    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if ticket["status"] == "closed":
            flash("Тикет закрыт", "err")
        elif len(body) < 2:
            flash("Пустое сообщение", "err")
        else:
            db.execute("INSERT INTO messages (ticket_id, user_id, body, is_staff) VALUES (?,?,?,?)",
                       (ticket_id, g.user["id"], body[:4000], int(staff)))
            new_status = "answered" if staff else "open"
            db.execute("UPDATE tickets SET status = ?, updated_at = datetime('now') WHERE id = ?",
                       (new_status, ticket_id))
            db.commit()
            log("ticket_reply", f"№{ticket_id}" + (" · как поддержка" if staff else ""))
            flash("Сообщение отправлено", "ok")
        return redirect(url_for("ticket_view", ticket_id=ticket_id))

    # владелец прочитал ответ — снимаем «живую активность» с острова
    if ticket["status"] == "answered" and ticket["user_id"] == g.user["id"]:
        db.execute("UPDATE tickets SET status = 'open' WHERE id = ?", (ticket_id,))
        db.commit()

    messages = db.execute(
        "SELECT m.*, u.nick FROM messages m JOIN users u ON u.id = m.user_id "
        "WHERE m.ticket_id = ? ORDER BY m.id", (ticket_id,)).fetchall()
    return render_template("ticket_view.html", ticket=ticket, messages=messages)


@app.route("/tickets/<int:ticket_id>/close", methods=["POST"])
@login_required
def ticket_close(ticket_id):
    _get_ticket(ticket_id)
    db = get_db()
    db.execute("UPDATE tickets SET status = 'closed', updated_at = datetime('now') WHERE id = ?",
               (ticket_id,))
    db.commit()
    log("ticket_close", f"№{ticket_id}")
    flash("Тикет закрыт", "info")
    return redirect(url_for("ticket_view", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
@login_required
@require("tickets")
def ticket_delete(ticket_id):
    ticket = _get_ticket(ticket_id)
    db = get_db()
    db.execute("DELETE FROM messages WHERE ticket_id = ?", (ticket_id,))
    db.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
    db.commit()
    log("ticket_delete", f"№{ticket_id} · {ticket['nick']} · {ticket['subject'][:80]}")
    flash(f"Тикет №{ticket_id} удалён", "ok")
    return redirect(url_for("tickets"))


# ---------- профиль и вход ----------

def hwid_reset_available_at(user):
    if not user["hwid_reset_at"]:
        return None
    at = datetime.strptime(user["hwid_reset_at"], FMT) + timedelta(days=settings.current().HWID_RESET_DAYS)
    return at if at > now() else None


@app.route("/profile")
@login_required
def profile():
    db = get_db()
    orders = db.execute(
        "SELECT o.*, p.name, p.icon FROM orders o JOIN products p ON p.id = o.product_id "
        "WHERE o.user_id = ? ORDER BY o.id DESC", (g.user["id"],)).fetchall()
    stats = db.execute("SELECT COUNT(*) AS total, SUM(status != 'closed') AS active "
                       "FROM tickets WHERE user_id = ?", (g.user["id"],)).fetchone()
    spent = sum(o["price"] for o in orders if o["status"] == "paid")
    reset_at = hwid_reset_available_at(g.user)
    activations = db.execute("SELECT * FROM key_activations WHERE user_id = ? ORDER BY id DESC LIMIT 20",
                             (g.user["id"],)).fetchall()
    return render_template("profile.html", orders=orders, stats=stats, spent=spent, activations=activations,
                           reset_at=reset_at.strftime("%d.%m.%Y") if reset_at else None)


KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_activation_key():
    return "-".join("".join(secrets.choice(KEY_ALPHABET) for _ in range(5)) for _ in range(4))


def period_label(days):
    if days == 0:
        return "навсегда"
    if days % 365 == 0:
        n = days // 365
        return f"{n} {'год' if n % 10 == 1 and n % 100 != 11 else 'года' if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else 'лет'}"
    return days_word(days)


@app.route("/profile/activate", methods=["POST"])
@login_required
def activate_key():
    if too_many("activate", g.user["id"], 10, 900) or too_many("activate_ip", client_ip(), 20, 900):
        flash("Слишком много неверных ключей — попробуйте через 15 минут", "err")
        return redirect(url_for("profile"))
    code = re.sub(r"[^A-Z0-9]", "", request.form.get("code", "").upper()[:64])
    code = "-".join(code[i:i + 5] for i in range(0, len(code), 5))
    db = get_db()
    row = db.execute("SELECT k.code, f.days, f.name FROM activation_keys k JOIN key_folders f ON f.id = k.folder_id "
                     "WHERE k.code = ?", (code,)).fetchone()
    # удаляем ключ первым: если два человека вводят его одновременно, пройдёт только один
    if row is None or db.execute("DELETE FROM activation_keys WHERE code = ?", (code,)).rowcount != 1:
        hit("activate", g.user["id"])
        hit("activate_ip", client_ip())
        log("key_activate_fail", code[:11] + "…" if code else "пусто")
        flash("Ключ не найден или уже активирован", "err")
        return redirect(url_for("profile"))
    # перечитываем после DELETE (база уже заблокирована на запись): два ключа, введённые
    # одновременно, сложатся, а не перезапишут друг друга
    user = db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    db.execute("UPDATE users SET sub_until = ?, license_key = ? WHERE id = ?",
               (extended_until(user, row["days"]), user["license_key"] or new_license_key(), user["id"]))
    db.execute("INSERT INTO key_activations (code, user_id, days, folder_name) VALUES (?,?,?,?)",
               (code, user["id"], row["days"], row["name"]))
    db.commit()
    log("key_activate", f"{code} · {period_label(row['days'])} · папка «{row['name']}»")
    flash(f"Ключ активирован: +{period_label(row['days'])}", "ok")
    return redirect(url_for("profile"))


@app.route("/profile/hwid-reset", methods=["POST"])
@login_required
def hwid_reset():
    if not g.user["hwid"]:
        flash("HWID ещё не привязан", "info")
    elif hwid_reset_available_at(g.user):
        flash("Бесплатный сброс пока недоступен", "err")
    else:
        db = get_db()
        db.execute("UPDATE users SET hwid = NULL, hwid_reset_at = ? WHERE id = ?",
                   (now().strftime(FMT), g.user["id"]))
        db.commit()
        log("hwid_reset_self")
        flash("HWID сброшен, запустите клиент на новом ПК", "ok")
    return redirect(url_for("profile"))


@app.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    old = request.form.get("old", "")
    new = request.form.get("new", "")
    if not check_password_hash(g.user["password_hash"], old):
        flash("Старый пароль не подходит", "err")
    elif not 6 <= len(new) <= PASSWORD_MAX:
        flash(f"Новый пароль — от 6 до {PASSWORD_MAX} символов", "err")
    else:
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (generate_password_hash(new), g.user["id"]))
        db.commit()
        log("password_change")
        # остальные сессии этого аккаунта отваливаются, текущая остаётся
        start_session(db.execute("SELECT * FROM users WHERE id = ?", (g.user["id"],)).fetchone())
        flash("Пароль изменён, другие устройства разлогинены", "ok")
    return redirect(url_for("profile"))



def _safe_next():
    """Куда вернуть после входа: только путь на этом же сайте.
    «//evil.com», «/\\evil.com» и «/<таб>/evil.com» браузер понимает как чужой сайт — их не пускаем."""
    nxt = request.args.get("next", "")
    parts = urlsplit(nxt)
    if (nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt
            and not parts.scheme and not parts.netloc
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in nxt)):
        return nxt
    return url_for("profile")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("profile"))
    form = {"nick": request.form.get("nick", "").strip()}
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")[:PASSWORD_MAX]
        nick_key = form["nick"].lower()[:32]
        if too_many("login", client_ip(), 10, 900) or too_many("login_nick", nick_key, 20, 900):
            error = "Слишком много попыток входа — подождите 15 минут"
            return render_template("auth.html", mode="login", form=form, error=error), 429
        user = get_db().execute("SELECT * FROM users WHERE nick = ?", (form["nick"],)).fetchone()
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if user is None or not ok:
            hit("login", client_ip())
            hit("login_nick", nick_key)
            error = "Неверный логин или пароль"
            log("login_fail", f"логин «{form['nick'][:32]}»", user=user or {"id": None, "nick": None})
        else:
            start_session(user)
            log("login", user=user)
            return redirect(_safe_next())
    return render_template("auth.html", mode="login", form=form, error=error)


@app.route("/api/register", methods=["POST"])
def api_register():
    """Регистрация аккаунта прямо из лоадера."""
    data = request.get_json(silent=True) or request.form or {}
    nick = str(data.get("nick") or data.get("username") or "").strip()
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")

    if not nick or not NICK_RE.match(nick):
        return jsonify({"ok": False, "error": "Никнейм должен быть от 3 до 16 символов (только латиница, цифры и _)"}), 400
    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Укажите корректный email"}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Пароль должен быть не короче 6 символов"}), 400

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE nick = ? COLLATE NOCASE", (nick,)).fetchone():
        return jsonify({"ok": False, "error": "Этот никнейм уже занят"}), 400
    if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        return jsonify({"ok": False, "error": "Этот email уже зарегистрирован"}), 400

    license_key = generate_license_key(db)
    # Выдаем 30 дней ознакомительной подписки новому игроку для комфортного теста
    until = (now() + timedelta(days=30)).strftime(FMT)
    db.execute(
        "INSERT INTO users (nick, email, password_hash, license_key, sub_until) VALUES (?, ?, ?, ?, ?)",
        (nick, email, generate_password_hash(password), license_key, until)
    )
    user_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.commit()
    log("register_loader", f"Регистрация через лоадер: {email}", user_id=user_id, nick=nick)
    return jsonify({"ok": True, "nick": nick, "license_key": license_key})

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("profile"))
    form = {"nick": request.form.get("nick", "").strip(),
            "email": request.form.get("email", "").strip().lower()}
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        db = get_db()
        if too_many("register", client_ip(), 5, 3600):
            error = "С этого адреса уже создано много аккаунтов — попробуйте через час"
        elif not NICK_RE.match(form["nick"]):
            error = "Логин — от 3 до 16 символов: латиница, цифры и _"
        elif len(form["email"]) > 254 or not EMAIL_RE.match(form["email"]):
            error = "Проверьте почту — похоже, в ней опечатка"
        elif not 6 <= len(password) <= PASSWORD_MAX:
            error = f"Пароль — от 6 до {PASSWORD_MAX} символов"
        elif password != request.form.get("password2", ""):
            error = "Пароли не совпадают"
        elif db.execute("SELECT 1 FROM users WHERE nick = ?", (form["nick"],)).fetchone():
            error = "Этот логин уже занят"
        elif db.execute("SELECT 1 FROM users WHERE email = ?", (form["email"],)).fetchone():
            error = "На эту почту уже есть аккаунт — попробуйте войти"
        else:
            cur = db.execute("INSERT INTO users (nick, email, password_hash) VALUES (?, ?, ?)",
                             (form["nick"], form["email"], generate_password_hash(password)))
            db.commit()
            hit("register", client_ip())
            start_session(db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone())
            log("register", form["email"], user={"id": cur.lastrowid, "nick": form["nick"]})
            return redirect(_safe_next())
    return render_template("auth.html", mode="register", form=form, error=error)


@app.route("/logout", methods=["POST"])
def logout():
    if g.user:
        log("logout")
    session.clear()
    flash("Вы вышли", "info")
    return redirect(url_for("index"))


# ---------- админка ----------

GRANT_UNITS = {"days": 1, "weeks": 7, "months": 30, "years": 365}


@app.route("/admin")
@login_required
def admin():
    if not role_of(g.user):
        abort(404)
    if not can("overview"):
        return redirect(url_for("admin_promos"))
    db = get_db()
    one = lambda sql: db.execute(sql).fetchone()[0]  # noqa: E731
    stats = {
        "users": one("SELECT COUNT(*) FROM users"),
        "active": one("SELECT COUNT(*) FROM users WHERE sub_until > datetime('now')"),
        "revenue": one("SELECT COALESCE(SUM(price), 0) FROM orders WHERE status = 'paid'"),
        "paid": one("SELECT COUNT(*) FROM orders WHERE status = 'paid'"),
        "pending": one("SELECT COUNT(*) FROM orders WHERE status = 'pending'"),
        "tickets": one("SELECT COUNT(*) FROM tickets WHERE status != 'closed'"),
    }
    orders = db.execute(
        "SELECT o.*, p.name, p.icon, u.nick FROM orders o JOIN products p ON p.id = o.product_id "
        "JOIN users u ON u.id = o.user_id ORDER BY o.id DESC LIMIT 8").fetchall()
    users = db.execute("SELECT * FROM users ORDER BY id DESC LIMIT 8").fetchall()
    folders = db.execute(
        "SELECT f.days, COUNT(k.code) AS left FROM key_folders f LEFT JOIN activation_keys k ON k.folder_id = f.id "
        "GROUP BY f.days ORDER BY f.days = 0, f.days").fetchall()
    stock = [{"label": period_label(f["days"]), "left": f["left"]} for f in folders]
    today = now().date()
    per_day = dict(db.execute(
        "SELECT date(created_at), COUNT(*) FROM users WHERE created_at >= date('now', '-13 days') "
        "GROUP BY date(created_at)").fetchall())
    acts = dict(db.execute(
        "SELECT date(activated_at), COUNT(*) FROM key_activations WHERE activated_at >= date('now', '-13 days') "
        "GROUP BY date(activated_at)").fetchall())
    chart = []
    for i in range(13, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        chart.append({"day": d[8:], "users": per_day.get(d, 0), "acts": acts.get(d, 0)})
    peak = max([1] + [max(c["users"], c["acts"]) for c in chart])
    stats["activations"] = one("SELECT COUNT(*) FROM key_activations")
    return render_template("admin.html", tab="overview", stats=stats, orders=orders, users=users,
                           stock=stock, chart=chart, peak=peak)


@app.route("/admin/users")
@login_required
@require("users")
def admin_users():
    q = request.args.get("q", "").strip()
    sql, params = "SELECT *, EXISTS(SELECT 1 FROM client_bans b WHERE b.user_id=users.id) AS client_blocked FROM users", []
    if q:
        sql += " WHERE nick LIKE ? OR email LIKE ? OR license_key LIKE ?"
        params = [f"%{q}%"] * 3
    users = get_db().execute(sql + " ORDER BY id DESC LIMIT 200", params).fetchall()
    return render_template("admin.html", tab="users", users=users, q=q, sub_info=sub_info, role_of=role_of,
                           is_root_owner=is_root_owner)


def _admin_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        abort(404)
    return db, user


@app.route("/admin/users/<int:user_id>/client-ban", methods=["POST"])
@login_required
@require("users")
def admin_client_ban(user_id):
    db, user = _admin_user(user_id)
    if user_id == g.user["id"] or role_of(user) in ("admin", "owner"):
        abort(403)
    action = request.form.get("action")
    if action == "ban":
        db.execute("INSERT OR REPLACE INTO client_bans(user_id,hwid,actor_id) VALUES(?,?,?)",
                   (user_id, user["hwid"], g.user["id"]))
    elif action == "unban":
        db.execute("DELETE FROM client_bans WHERE user_id=?", (user_id,))
    else:
        abort(400)
    db.commit()
    log("client_" + action, user["nick"])
    return redirect(url_for("admin_users", q=request.args.get("q", "")))


@app.route("/admin/users/<int:user_id>/grant", methods=["POST"])
@login_required
@require("users")
def admin_grant(user_id):
    db, user = _admin_user(user_id)
    unit = request.form.get("unit", "days")
    if unit == "forever":
        days = 0
    else:
        try:
            amount = int(request.form.get("amount", ""))
        except ValueError:
            amount = 0
        if unit not in GRANT_UNITS or not 1 <= amount <= 100_000:
            flash("Укажите количество от 1 и единицу", "err")
            return redirect(url_for("admin_users", q=request.args.get("q", "")))
        days = amount * GRANT_UNITS[unit]
    key = user["license_key"] or new_license_key()
    db.execute("UPDATE users SET sub_until = ?, license_key = ? WHERE id = ?",
               (extended_until(user, days), key, user_id))
    db.commit()
    log("grant", f"{user['nick']} · +{period_label(days)}")
    return redirect(url_for("admin_users", q=request.args.get("q", "")))


@app.route("/admin/users/<int:user_id>/revoke", methods=["POST"])
@login_required
@require("users")
def admin_revoke(user_id):
    db, user = _admin_user(user_id)
    db.execute("UPDATE users SET sub_until = NULL WHERE id = ?", (user_id,))
    db.commit()
    log("revoke", user["nick"])
    return redirect(url_for("admin_users", q=request.args.get("q", "")))


@app.route("/admin/users/<int:user_id>/hwid", methods=["POST"])
@login_required
@require("users")
def admin_hwid(user_id):
    db, user = _admin_user(user_id)
    db.execute("UPDATE users SET hwid = NULL WHERE id = ?", (user_id,))
    db.commit()
    log("hwid_reset", user["nick"])
    return redirect(url_for("admin_users", q=request.args.get("q", "")))


@app.route("/admin/orders")
@login_required
@require("orders")
def admin_orders():
    status = request.args.get("status")
    sql = ("SELECT o.*, p.name, p.icon, u.nick FROM orders o JOIN products p ON p.id = o.product_id "
           "JOIN users u ON u.id = o.user_id")
    params = []
    if status in ORDER_STATUS:
        sql += " WHERE o.status = ?"
        params.append(status)
    orders = get_db().execute(sql + " ORDER BY o.id DESC LIMIT 200", params).fetchall()
    return render_template("admin.html", tab="orders", orders=orders, status=status)


@app.route("/admin/orders/<int:order_id>/<action>", methods=["POST"])
@login_required
@require("orders")
def admin_order_action(order_id, action):
    db = get_db()
    order = db.execute(
        "SELECT o.*, p.slug, p.days FROM orders o JOIN products p ON p.id = o.product_id WHERE o.id = ?",
        (order_id,)).fetchone()
    if order is None or order["status"] != "pending" or action not in ("confirm", "cancel"):
        abort(404)
    if action == "confirm":
        apply_order(db, order)
    else:
        db.execute("UPDATE orders SET status = 'cancelled' WHERE id = ?", (order_id,))
    db.commit()
    log("order_confirm" if action == "confirm" else "order_cancel", f"№{order_id}")
    return redirect(url_for("admin_orders", status=request.args.get("status") or None))


PROMO_RE = re.compile(r"^[A-Z0-9_-]{3,32}$")


@app.route("/admin/promos", methods=["GET", "POST"])
@login_required
@require("promos")
def admin_promos():
    db = get_db()
    full = can("promos_all")  # ютубер: только свои, скидка фиксированная, лимит на количество
    mine = db.execute("SELECT COUNT(*) FROM promocodes WHERE created_by = ?", (g.user["id"],)).fetchone()[0]
    can_create = full or mine < config.YOUTUBER_PROMO_LIMIT
    form = {"code": "", "discount": "", "max_uses": "", "expires_at": ""}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        form["code"] = form["code"].upper()
        if not full:
            form.update(discount=str(config.YOUTUBER_PROMO_DISCOUNT), max_uses="", expires_at="")
        error = None
        try:
            discount = int(form["discount"])
            max_uses = int(form["max_uses"]) if form["max_uses"] else None
            expires = datetime.strptime(form["expires_at"], "%Y-%m-%d").strftime("%Y-%m-%d") if form["expires_at"] else None
        except ValueError:
            error = "Проверьте числа и дату"
        if not error and not can_create:
            error = "Вы уже создали свой промокод — больше нельзя"
        elif not error and not PROMO_RE.match(form["code"]):
            error = "Код — 3–32 символа: латиница, цифры, _ и -"
        elif not error and not 1 <= discount <= 100:
            error = "Скидка — от 1 до 100%"
        elif not error and max_uses is not None and max_uses < 1:
            error = "Лимит использований — от 1, или оставьте пустым"
        elif not error and db.execute("SELECT 1 FROM promocodes WHERE code = ?", (form["code"],)).fetchone():
            error = "Такой промокод уже есть"
        if error:
            flash(error, "err")
        else:
            db.execute("INSERT INTO promocodes (code, discount, max_uses, expires_at, created_by) VALUES (?,?,?,?,?)",
                       (form["code"], discount, max_uses, expires, g.user["id"]))
            db.commit()
            log("promo_create", f"{form['code']} · −{discount}%")
            return redirect(url_for("admin_promos"))
    sql = "SELECT p.*, u.nick AS author FROM promocodes p LEFT JOIN users u ON u.id = p.created_by"
    params = ()
    if not full:
        sql += " WHERE p.created_by = ?"
        params = (g.user["id"],)
    promos = db.execute(sql + " ORDER BY p.created_at DESC", params).fetchall()
    return render_template("admin_promos.html", tab="promos", promos=promos, form=form, full=full,
                           can_create=can_create, today=now().strftime("%Y-%m-%d"),
                           yt_discount=config.YOUTUBER_PROMO_DISCOUNT)


@app.route("/admin/promos/<code>/<action>", methods=["POST"])
@login_required
@require("promos_all")
def admin_promo_action(code, action):
    db = get_db()
    if action == "toggle":
        db.execute("UPDATE promocodes SET active = 1 - active WHERE code = ?", (code,))
    elif action == "delete":
        db.execute("DELETE FROM promocodes WHERE code = ?", (code,))
    else:
        abort(404)
    db.commit()
    log("promo_toggle" if action == "toggle" else "promo_delete", code)
    return redirect(url_for("admin_promos"))


@app.route("/admin/keys", methods=["GET", "POST"])
@login_required
@require("keys")
def admin_keys():
    db = get_db()
    if request.method == "POST":
        unit = request.form.get("unit", "days")
        try:
            count = int(request.form.get("count", ""))
            amount = 0 if unit == "forever" else int(request.form.get("amount", ""))
        except ValueError:
            count = amount = -1
        if not 1 <= count <= 100:
            flash("За раз — от 1 до 100 ключей", "err")
        elif unit != "forever" and (unit not in GRANT_UNITS or not 1 <= amount <= 100_000):
            flash("Укажите срок: число и единицу, или «навсегда»", "err")
        else:
            days = 0 if unit == "forever" else amount * GRANT_UNITS[unit]
            name = request.form.get("name", "").strip()[:60] or \
                f"{period_label(days).capitalize()} · {now().strftime('%d.%m %H:%M')}"
            folder_id = db.execute("INSERT INTO key_folders (name, days, created) VALUES (?,?,?)",
                                   (name, days, count)).lastrowid
            codes = set()
            while len(codes) < count:
                codes.add(new_activation_key())
            db.executemany("INSERT OR IGNORE INTO activation_keys (code, folder_id) VALUES (?, ?)",
                           [(c, folder_id) for c in codes])
            db.commit()
            log("keys_generate", f"«{name}» · {count} шт. · {period_label(days)}")
            return redirect(url_for("admin_key_folder", folder_id=folder_id))
    folders = db.execute(
        "SELECT f.*, COUNT(k.code) AS left FROM key_folders f LEFT JOIN activation_keys k ON k.folder_id = f.id "
        "GROUP BY f.id ORDER BY f.id DESC").fetchall()
    recent = db.execute("SELECT a.*, u.nick FROM key_activations a JOIN users u ON u.id = a.user_id "
                     "ORDER BY a.id DESC LIMIT 30").fetchall()
    return render_template("admin_keys.html", tab="keys", folders=folders, log=recent, period_label=period_label)


def _folder(folder_id):
    folder = get_db().execute("SELECT * FROM key_folders WHERE id = ?", (folder_id,)).fetchone()
    if folder is None:
        abort(404)
    return folder


@app.route("/admin/keys/<int:folder_id>")
@login_required
@require("keys")
def admin_key_folder(folder_id):
    folder = _folder(folder_id)
    keys = [r["code"] for r in get_db().execute(
        "SELECT code FROM activation_keys WHERE folder_id = ? ORDER BY rowid", (folder_id,))]
    return render_template("admin_key_folder.html", tab="keys", folder=folder, keys=keys,
                           period=period_label(folder["days"]))


@app.route("/admin/keys/<int:folder_id>.txt")
@login_required
@require("keys")
def admin_key_folder_txt(folder_id):
    """Ключи по одному на строку — как раз для автовыдачи на FunPay."""
    folder = _folder(folder_id)
    keys = [r["code"] for r in get_db().execute(
        "SELECT code FROM activation_keys WHERE folder_id = ? ORDER BY rowid", (folder_id,))]
    return Response("\n".join(keys) + "\n", mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=keys-{folder['id']}.txt"})


@app.route("/admin/keys/<int:folder_id>/delete", methods=["POST"])
@login_required
@require("keys")
def admin_key_folder_delete(folder_id):
    folder = _folder(folder_id)
    db = get_db()
    db.execute("DELETE FROM activation_keys WHERE folder_id = ?", (folder_id,))
    db.execute("DELETE FROM key_folders WHERE id = ?", (folder_id,))
    db.commit()
    log("keys_folder_delete", f"«{folder['name']}»")
    return redirect(url_for("admin_keys"))


@app.route("/admin/keys/<int:folder_id>/remove", methods=["POST"])
@login_required
@require("keys")
def admin_key_remove(folder_id):
    db = get_db()
    removed = db.execute("DELETE FROM activation_keys WHERE folder_id = ? AND code = ?",
                         (folder_id, request.form.get("code", ""))).rowcount
    db.commit()
    if removed:
        log("key_delete", request.form.get("code", ""))
    return redirect(url_for("admin_key_folder", folder_id=folder_id))


PRODUCT_FIELDS = ("category", "name", "slug", "price", "old_price", "days", "blurb", "perks", "icon", "tag", "sort",
                  "funpay_url")
SLUG_RE = re.compile(r"^[a-z0-9-]{2,40}$")
ICONS = ["item/iron_ingot", "item/gold_ingot", "item/diamond", "item/emerald", "item/nether_star",
         "item/netherite_ingot", "item/totem_of_undying", "item/elytra", "item/name_tag", "item/ender_eye",
         "item/writable_book", "item/clock_00", "item/compass_00", "item/filled_map", "item/spyglass",
         "item/golden_apple", "item/diamond_sword", "item/diamond_pickaxe", "item/barrier", "block/emerald_block"]


def _product_form(product=None):
    if request.method != "POST":
        if product is None:
            return {"category": "subs", "name": "", "slug": "", "price": "", "old_price": "", "days": "30",
                    "blurb": "", "perks": "", "icon": "item/diamond", "tag": "", "sort": "0", "funpay_url": ""}
        return {k: ("" if product[k] is None else str(product[k])) for k in PRODUCT_FIELDS}
    return {k: request.form.get(k, "").strip() for k in PRODUCT_FIELDS}


def _product_values(form, creating):
    """Проверка формы товара -> (значения для базы, ошибка)."""
    if form["category"] not in {c[0] for c in CATEGORIES}:
        return None, "Выберите раздел"
    if not form["name"]:
        return None, "Нужно название"
    if creating and not SLUG_RE.match(form["slug"]):
        return None, "Адрес — 2–40 символов: латиница, цифры и -"
    if not ICON_RE.match(form["icon"]):
        return None, "Иконка — путь вида item/diamond"
    try:
        price = int(form["price"])
        old_price = int(form["old_price"]) if form["old_price"] else None
        days = int(form["days"]) if form["days"] != "" else None
        sort = int(form["sort"] or 0)
    except ValueError:
        return None, "Цены, срок и порядок — целые числа"
    if not 1 <= price <= 10_000_000 or (old_price is not None and not price < old_price <= 10_000_000):
        return None, "Цена от 1 ₽, старая цена — больше текущей или пусто"
    if days is not None and not 0 <= days <= 100_000:
        return None, "Срок — 0 (навсегда), число дней или пусто"
    if not -10_000 <= sort <= 10_000:
        return None, "Порядок — число от -10000 до 10000"
    if form["funpay_url"] and not form["funpay_url"].startswith("https://"):
        return None, "Ссылка на FunPay должна начинаться с https://"
    if form["category"] == "subs" and days is None:
        return None, "У подписки должен быть срок: число дней или 0 — навсегда"
    return {"category": form["category"], "name": form["name"][:60], "slug": form["slug"],
            "price": price, "old_price": old_price, "days": days, "blurb": form["blurb"][:200],
            "perks": "\n".join(p.strip() for p in form["perks"].splitlines() if p.strip())[:1000],
            "icon": form["icon"], "tag": form["tag"][:40] or None, "sort": sort,
            "funpay_url": form["funpay_url"][:300] or None}, None


ICON_RE = re.compile(r"^(item|block)/[a-z0-9_]{2,40}$")


@app.route("/admin/products")
@login_required
@require("products")
def admin_products():
    products = get_db().execute(
        "SELECT p.*, (SELECT COUNT(*) FROM orders o WHERE o.product_id = p.id) AS orders_count "
        "FROM products p ORDER BY p.category DESC, p.sort").fetchall()
    return render_template("admin_products.html", tab="products", products=products, categories=CATEGORIES)


@app.route("/admin/products/new", methods=["GET", "POST"])
@app.route("/admin/products/<int:product_id>", methods=["GET", "POST"])
@login_required
@require("products")
def admin_product_edit(product_id=None):
    db = get_db()
    product = None
    if product_id is not None:
        product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if product is None:
            abort(404)
    form = _product_form(product)
    if product is not None:
        form["slug"] = product["slug"]  # адрес уже в ссылках и заказах — не меняем
    if request.method == "POST":
        values, error = _product_values(form, creating=product is None)
        if not error and product is None and db.execute(
                "SELECT 1 FROM products WHERE slug = ?", (values["slug"],)).fetchone():
            error = "Товар с таким адресом уже есть"
        if error:
            flash(error, "err")
        else:
            if product is None:
                log_action = "product_create"
                cols = ", ".join(values)
                db.execute(f"INSERT INTO products ({cols}) VALUES ({', '.join('?' * len(values))})",
                           tuple(values.values()))
            else:
                log_action = "product_edit"
                values.pop("slug")
                db.execute(f"UPDATE products SET {', '.join(f'{k} = ?' for k in values)} WHERE id = ?",
                           (*values.values(), product_id))
            db.commit()
            log(log_action, f"{values['name']} · {values['price']} ₽")
            return redirect(url_for("admin_products"))
    return render_template("admin_product_edit.html", tab="products", product=product, form=form,
                           categories=CATEGORIES, icons=ICONS)


@app.route("/admin/products/<int:product_id>/<action>", methods=["POST"])
@login_required
@require("products")
def admin_product_action(product_id, action):
    db = get_db()
    product = db.execute("SELECT name FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        abort(404)
    if action == "toggle":
        db.execute("UPDATE products SET active = 1 - active WHERE id = ?", (product_id,))
    elif action == "delete":
        if db.execute("SELECT 1 FROM orders WHERE product_id = ?", (product_id,)).fetchone():
            flash("На товар есть заказы — его можно только скрыть", "err")
        else:
            db.execute("DELETE FROM products WHERE id = ?", (product_id,))
            log("product_delete", product["name"])
    else:
        abort(404)
    db.commit()
    if action == "toggle":
        log("product_toggle", product["name"])
    return redirect(url_for("admin_products"))


URL_OK = re.compile(r"^(https?://\S+|/\S*)$")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")
IMAGE_SIGNATURES = {b"\xff\xd8\xff": ".jpg", b"\x89PNG\r\n\x1a\n": ".png"}


def _save_image(file):
    """Картинка из формы -> путь /static/uploads/..., или None, если это не JPG/PNG/WebP."""
    head = file.stream.read(12)
    file.stream.seek(0)
    ext = next((e for sig, e in IMAGE_SIGNATURES.items() if head.startswith(sig)), None)
    if ext is None and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        ext = ".webp"
    if ext is None:
        return None
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    name = secrets.token_hex(8) + ext
    file.save(os.path.join(UPLOAD_DIR, name))
    return url_for("static", filename=f"uploads/{name}")


@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
@require("settings")
def admin_settings():
    if request.method == "POST":
        values, errors = {}, []
        for key, (label, kind, _hint) in settings.FIELDS.items():
            raw = request.form.get(key, "")
            if kind in ("str", "text"):
                raw = raw.strip()
                if key == "CLIENT_NAME" and not raw:
                    errors.append("Название клиента не может быть пустым")
                    continue
                values[key] = raw[:500]
            elif kind == "url":
                raw = raw.strip()
                if raw and not URL_OK.match(raw):
                    errors.append(f"{label}: ссылка должна начинаться с https://")
                    continue
                values[key] = raw
            elif kind == "int":
                try:
                    values[key] = min(max(0, int(raw)), 3650)
                except ValueError:
                    errors.append(f"{label}: нужно целое число")
            elif kind == "bool":
                # скрытое поле «0» + галочка «1»: включено, если среди значений есть «1»
                values[key] = "1" in request.form.getlist(key)
            elif kind == "status":
                values[key] = raw if raw in settings.STATUSES else "ok"
            elif kind == "image":
                file = request.files.get(key)
                if request.form.get(key + "_reset"):
                    values[key] = ""
                elif file and file.filename:
                    path = _save_image(file)
                    if path is None:
                        errors.append(f"{label}: нужен файл JPG, PNG или WebP")
                    else:
                        values[key] = path
            elif kind == "advantages":
                rows = zip(request.form.getlist("adv_icon"), request.form.getlist("adv_title"),
                           request.form.getlist("adv_text"))
                values[key] = [{"icon": i.strip() if ICON_RE.match(i.strip()) else "item/diamond",
                                "title": t.strip()[:80], "text": x.strip()[:300]}
                               for i, t, x in rows if t.strip()]
            elif kind == "faq":
                rows = zip(request.form.getlist("faq_q"), request.form.getlist("faq_a"))
                values[key] = [{"q": q.strip()[:200], "a": a.strip()[:1000]} for q, a in rows if q.strip()]
        site = settings.current()
        changed = [settings.FIELDS[k][0] for k, v in values.items() if getattr(site, k) != v]
        settings.save(values)
        if changed:
            log("settings_save", ", ".join(changed))
        if errors:
            for e in errors:
                flash(e, "err")
        else:
            flash("Сохранено", "ok")
        return redirect(url_for("admin_settings"))
    return render_template("admin_settings.html", tab="settings", fields=settings.FIELDS,
                           sections=settings.SECTIONS, statuses=settings.STATUSES, icons=ICONS,
                           site=settings.current())


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@require("roles")
def admin_role(user_id):
    db, user = _admin_user(user_id)
    new = request.form.get("role", "")
    if new not in ("", *ROLES):
        abort(400)
    if is_root_owner(user):
        flash("Этого владельца можно убрать только в config.py", "err")
    elif user["id"] == g.user["id"]:
        flash("Свою роль менять нельзя — попросите другого владельца", "err")
    elif (user["role"] or "") != new:
        db.execute("UPDATE users SET role = ? WHERE id = ?", (new or None, user_id))
        db.commit()
        log("role_change", f"{user['nick']}: {ROLES.get(user['role'], 'игрок')} → {ROLES.get(new, 'игрок')}")
    return redirect(url_for("admin_users", q=request.args.get("q", "")))


LOGS_PER_PAGE = 50


@app.route("/admin/logs")
@login_required
@require("logs")
def admin_logs():
    cat = request.args.get("cat", "")
    q = request.args.get("q", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    where, params = [], []
    if cat in LOG_CATEGORIES:
        actions = [a for a, (_, c) in LOG_ACTIONS.items() if c == cat]
        where.append(f"action IN ({','.join('?' * len(actions))})")
        params += actions
    if q:
        where.append("(nick LIKE ? OR details LIKE ? OR ip LIKE ?)")
        params += [f"%{q}%"] * 3
    sql = "FROM logs" + (" WHERE " + " AND ".join(where) if where else "")
    db = get_db()
    total = db.execute("SELECT COUNT(*) " + sql, params).fetchone()[0]
    rows = db.execute("SELECT * " + sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
                      (*params, LOGS_PER_PAGE, (page - 1) * LOGS_PER_PAGE)).fetchall()
    pages = max(1, -(-total // LOGS_PER_PAGE))
    return render_template("admin_logs.html", tab="logs", rows=rows, total=total, page=page, pages=pages,
                           cat=cat, q=q, actions=LOG_ACTIONS, categories=LOG_CATEGORIES)


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


init_db()

if __name__ == "__main__":
    # отладчик Werkzeug при ошибке даёт консоль Python — только локально и по явному FLASK_DEBUG=1
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5000)
