// подтверждения и автоотправка вместо onsubmit/onchange в разметке:
// текст из базы попадает в атрибут data-*, а не в код — XSS через название папки/товара невозможен,
// и CSP может запрещать inline-обработчики
document.addEventListener("submit", (e) => {
  const msg = e.target.dataset?.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});
document.addEventListener("change", (e) => {
  if (e.target.matches?.("[data-autosubmit]")) e.target.form?.submit();
});

(() => {
  const island = document.getElementById("island");
  const nav = island.querySelector(".bar-nav");
  const ink = island.querySelector(".bar-ink");

  // ---------- бегущее подчёркивание под ссылками ----------
  function labelCenter(link) {
    const text = [...link.childNodes].find((n) => n.nodeType === 3 && n.textContent.trim());
    const range = document.createRange();
    range.selectNodeContents(text);
    const r = range.getBoundingClientRect();
    return r.left - nav.getBoundingClientRect().left + r.width / 2;
  }
  function moveInk(link, instant) {
    if (!link) { ink.style.opacity = "0"; return; }
    if (instant) ink.style.transition = "none";
    ink.style.transform = `translateX(${labelCenter(link) - 10}px)`;
    ink.style.opacity = "1";
    if (instant) { void ink.offsetWidth; ink.style.transition = ""; }
  }
  const active = () => nav.querySelector("a.on");
  nav.querySelectorAll("a").forEach((a) => a.addEventListener("mouseenter", () => moveInk(a)));
  nav.addEventListener("mouseleave", () => moveInk(active()));
  const placeInk = () => moveInk(active(), true);
  window.addEventListener("resize", placeInk);

  // подчёркивание стартует с того места, где было на прошлой странице, и переезжает к текущей вкладке
  let prevInk = null;
  try { prevInk = sessionStorage.getItem("ink"); } catch {}
  if (prevInk && active()) {
    ink.style.transition = "none";
    ink.style.transform = prevInk;
    ink.style.opacity = "1";
    void ink.offsetWidth;
    ink.style.transition = "";
    requestAnimationFrame(() => requestAnimationFrame(() => moveInk(active())));
  } else {
    placeInk();
  }
  document.fonts?.ready.then(() => moveInk(active()));
  window.addEventListener("pagehide", () => {
    try {
      if (ink.style.opacity === "1") sessionStorage.setItem("ink", ink.style.transform);
      else sessionStorage.removeItem("ink");
    } catch {}
  });

  // ---------- появление блоков при прокрутке ----------
  // блок проявляется, как только его верх поднялся выше низа экрана —
  // так ничего не остаётся невидимым даже после прыжка по якорю
  let pending = [...document.querySelectorAll(".reveal")];
  function checkReveals() {
    const edge = innerHeight * 0.92;
    pending = pending.filter((el) => {
      if (el.getBoundingClientRect().top > edge) return true;
      el.classList.add("is-in");
      el.querySelectorAll("[data-count]").forEach(countUp);
      return false;
    });
    if (!pending.length) window.removeEventListener("scroll", onRevealScroll);
  }
  const onRevealScroll = () => checkReveals();
  window.addEventListener("scroll", onRevealScroll, { passive: true });
  window.addEventListener("resize", onRevealScroll);
  checkReveals();

  function countUp(el) {
    const target = Number(el.dataset.count);
    if (!target || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const start = performance.now();
    const step = (t) => {
      const k = Math.min(1, (t - start) / 1200);
      el.textContent = Math.round(target * (1 - Math.pow(1 - k, 3))).toLocaleString("ru-RU");
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  // ---------- переходы между страницами без View Transitions (Firefox и старые браузеры) ----------
  if (!("PageRevealEvent" in window)) {
    const root = document.documentElement;
    root.classList.add("page-enter");
    window.addEventListener("pageshow", (e) => { if (e.persisted) root.classList.remove("page-leave"); });
    document.addEventListener("click", (e) => {
      const a = e.target.closest("a[href]");
      if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      if (a.target === "_blank" || a.hasAttribute("download")) return;
      const url = new URL(a.href, location.href);
      if (url.origin !== location.origin) return;
      if (url.pathname === location.pathname && url.hash) return;
      e.preventDefault();
      root.classList.add("page-leave");
      setTimeout(() => { location.href = url.href; }, 190);
    });
  }

  // ---------- после прокрутки бар становится плотнее ----------
  const onScroll = () => island.classList.toggle("scrolled", window.scrollY > 40);
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  // ---------- копирование: подтверждение прямо на кнопке ----------
  document.querySelectorAll("[data-copy]").forEach((b) =>
    b.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(b.dataset.copy); } catch { return; }
      const label = b.textContent;
      b.textContent = "Скопировано";
      setTimeout(() => { b.textContent = label; }, 1400);
    }));

  // ---------- промокод на оформлении ----------
  const checkout = document.querySelector("[data-checkout][data-promo-url]");
  if (checkout) {
    const base = Number(checkout.dataset.price);
    const total = checkout.querySelector("[data-total]");
    const promo = checkout.querySelector("[name=promo]");
    const fmt = (n) => n.toLocaleString("ru-RU") + " ₽";
    let t, lastCode = "";
    promo.addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(async () => {
        const code = promo.value.trim().toUpperCase();
        if (code === lastCode) return;
        lastCode = code;
        if (!code) { total.textContent = fmt(base); return; }
        const { discount } = await (await fetch(`${checkout.dataset.promoUrl}?code=${encodeURIComponent(code)}`)).json();
        total.innerHTML = discount
          ? `${fmt(Math.round(base * (100 - discount) / 100))} <s>${fmt(base)}</s>`
          : fmt(base);
      }, 500);
    });
  }

  // ---------- живой скин по нику ----------
  document.querySelectorAll("[data-skin-input]").forEach((input) => {
    const img = input.closest("form").querySelector("[data-skin]");
    if (!img) return;
    const size = img.src.match(/\/(\d+)$/)?.[1] || 40;
    let t;
    input.addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(() => {
        const nick = /^[A-Za-z0-9_]{3,16}$/.test(input.value) ? input.value : "MHF_Steve";
        img.src = `https://minotar.net/helm/${encodeURIComponent(nick)}/${size}`;
      }, 300);
    });
  });
})();

// ================= ANTI-INSPECT / ANTI-F12 PROTECTION =================
(function() {
  'use strict';

  // Disable context menu
  document.addEventListener('contextmenu', function(e) {
    if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
  }, true);

  // Block shortcut keys (layout-independent: e.code + e.keyCode + e.key)
  window.addEventListener('keydown', function(e) {
    const code = e.code || '';
    const key = (e.key || '').toUpperCase();
    const keyCode = e.keyCode || e.which || 0;

    // F12
    if (keyCode === 123 || code === 'F12' || key === 'F12') {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }

    // Ctrl+Shift+I / J / C / K (DevTools & Console in EN and RU layouts)
    if (e.ctrlKey && e.shiftKey) {
      if (
        keyCode === 73 || keyCode === 74 || keyCode === 67 || keyCode === 75 ||
        code === 'KeyI' || code === 'KeyJ' || code === 'KeyC' || code === 'KeyK' ||
        ['I', 'J', 'C', 'K', 'Ш', 'О', 'С', 'Л'].includes(key)
      ) {
        e.preventDefault();
        e.stopPropagation();
        return false;
      }
    }

    // Ctrl+U (View Source)
    if (e.ctrlKey && (keyCode === 85 || code === 'KeyU' || key === 'U' || key === 'Г')) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }

    // Ctrl+S (Save Page)
    if (e.ctrlKey && (keyCode === 83 || code === 'KeyS' || key === 'S' || key === 'Ы')) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
  }, true);

  // Anti-debugging trap: if DevTools is open, execution pauses on debugger and detects freeze
  setInterval(function() {
    const start = performance.now();
    debugger;
    if (performance.now() - start > 100) {
      document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#0d0a14;color:#c084fc;font-family:sans-serif;font-size:24px;font-weight:bold;">Доступ запрещён</div>';
      setTimeout(function() { location.reload(); }, 500);
    }
    try { console.clear(); } catch(e) {}
  }, 1000);
})();
