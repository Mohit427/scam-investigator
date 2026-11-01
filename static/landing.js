// Landing page effects, adapted to plain JS from React Bits (DecryptedText, ScrollReveal, Magnet).
// All page text is in the HTML and readable without this script or with reduced motion.
(() => {
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const SCRAMBLE = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz0123456789₹#%&@$*+";
  const pick = () => SCRAMBLE[Math.floor(Math.random() * SCRAMBLE.length)];
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  // Illustrative messages in patterns people receive, written for this page (the hero says so).
  // *Words* are the warning signs. These are not results; no check has been run on them.
  const MESSAGES = [
    "Dear Customer, your bank account will be *BLOCKED today* due to incomplete KYC. *Update your PAN immediately* to avoid suspension.",
    "Priya upbhokta, aapka bijli connection *aaj raat 9:30 baje* kaat diya jayega. *Turant* bijli officer se sampark karein.",
    "Your parcel is on hold at the depot. *Pay a ₹25 redelivery fee* within *2 hours* or it will be returned to the sender.",
    "Congratulations! You are selected for a part-time job. *Earn ₹8,000 daily* from home. *Message our HR on WhatsApp* to start.",
    "Your income tax refund of ₹15,490 is approved. *Share your card number and OTP* to receive it in your account today.",
    "This is the customs office. A parcel in your name contains illegal items. *Do not tell anyone.* Stay on this call to *avoid arrest*.",
    "Paise wapas chahiye? *Refund ke liye yeh UPI request approve karein* aur apna *PIN daalein*. Offer sirf aaj ke liye.",
    "Your reward points worth ₹4,999 *expire tonight*. *Install this app* from the link to redeem them before midnight.",
  ];
  const parsed = (() => {
    const chars = [], tells = [];
    for (const message of MESSAGES) {
      let on = false;
      for (const ch of message + "   ·   ") {
        if (ch === "*") { on = !on; continue; }
        chars.push(ch);
        tells.push(on);
      }
    }
    return { chars, tells };
  })();

  // ---------- microprint hero ----------
  function microprint() {
    const hero = document.querySelector(".light");
    const canvas = hero.querySelector(".microprint");
    const ctx = canvas.getContext("2d");
    if (!ctx) return { open: () => {} };
    const CELL_W = 8.6, CELL_H = 20, FONT = '500 14px "Anek Latin", sans-serif';
    const tile = document.createElement("canvas");
    const tctx = tile.getContext("2d");
    let w = 0, h = 0, dpr = 1, cols = 0, rows = [], quiet = [];
    let colors = {}, radius = 170, opening = false, raf = 0, visible = true;
    const lamp = { x: 0, y: 0, tx: 0, ty: 0, hover: false };

    function layout() {
      const r = hero.getBoundingClientRect();
      w = Math.max(1, Math.round(r.width));
      h = Math.max(1, Math.round(r.height));
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      cols = Math.ceil(w / CELL_W) + 2;
      const count = Math.ceil(h / CELL_H);
      colors = { ground: css("--cover"), micro: css("--micro"), paper: css("--on-cover"), foil: css("--foil"), tell: css("--tell") };
      tile.width = cols * CELL_W * dpr;
      tile.height = count * CELL_H * dpr;
      tctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      tctx.font = FONT;
      tctx.textAlign = "center";
      tctx.textBaseline = "middle";
      tctx.fillStyle = colors.micro;
      for (let row = 0; row < count; row++) {
        for (let col = 0; col < cols; col++) tctx.fillText(pick(), (col + 0.5) * CELL_W, (row + 0.5) * CELL_H);
      }
      rows = Array.from({ length: count }, (_, i) => ({
        y: i * CELL_H,
        start: (i * 211) % parsed.chars.length,
        speed: (i % 2 ? -1 : 1) * (5 + (i * 37) % 9),
        off: 0,
      }));
      radius = Math.min(190, Math.max(120, w * 0.14));
      // Text near page copy stays dim so the headline and buttons are always readable.
      const base = hero.getBoundingClientRect();
      quiet = [...hero.querySelectorAll("h1, .light-lead, .light-actions, .light-hint")]
        .concat(document.querySelector(".cover-bar"))
        .map((el) => {
          const b = el.getBoundingClientRect();
          return { x: b.left - base.left - 14, y: b.top - base.top - 8, w: b.width + 28, h: b.height + 16 };
        });
      if (!lamp.x) { lamp.x = w * 0.62; lamp.y = h * 0.26; }
    }

    const inQuiet = (x, y) => quiet.some((q) => x >= q.x && x <= q.x + q.w && y >= q.y && y <= q.y + q.h);
    const mod = (a, n) => ((a % n) + n) % n;

    function draw(time) {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = colors.ground;
      ctx.fillRect(0, 0, w, h);
      const tileW = cols * CELL_W;
      for (const row of rows) {
        const shift = mod(row.off, tileW);
        const sy = row.y * dpr, sh = CELL_H * dpr;
        ctx.drawImage(tile, 0, sy, tileW * dpr, sh, shift, row.y, tileW, CELL_H);
        ctx.drawImage(tile, 0, sy, tileW * dpr, sh, shift - tileW, row.y, tileW, CELL_H);
      }
      ctx.globalAlpha = 0.82;
      ctx.fillStyle = colors.ground;
      for (const q of quiet) ctx.fillRect(q.x, q.y, q.w, q.h);
      ctx.globalAlpha = 1;

      ctx.font = FONT;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      const bucket = Math.floor(time / 90);
      for (const row of rows) {
        const cy = row.y + CELL_H / 2, dy = cy - lamp.y;
        if (Math.abs(dy) > radius) continue;
        const span = Math.sqrt(radius * radius - dy * dy);
        const first = Math.floor((lamp.x - span - row.off) / CELL_W);
        const last = Math.ceil((lamp.x + span - row.off) / CELL_W);
        for (let col = first; col <= last; col++) {
          const x = col * CELL_W + row.off + CELL_W / 2;
          const d = Math.hypot(x - lamp.x, dy);
          if (d > radius || inQuiet(x, cy)) continue;
          const i = mod(row.start + col, parsed.chars.length);
          ctx.fillStyle = colors.ground;
          ctx.fillRect(x - CELL_W / 2, row.y, CELL_W, CELL_H);
          if (d < radius * 0.9) {
            ctx.fillStyle = parsed.tells[i] ? colors.tell : colors.paper;
            ctx.fillText(parsed.chars[i], x, cy);
          } else {
            ctx.fillStyle = colors.foil;
            ctx.fillText(SCRAMBLE[mod((col * 31 + row.y) * 17 + bucket * 13 + (col ^ bucket), SCRAMBLE.length)], x, cy);
          }
        }
      }
    }

    function shimmer() {
      tctx.fillStyle = colors.micro;
      for (let n = 0; n < 14; n++) {
        const col = Math.floor(Math.random() * cols), row = Math.floor(Math.random() * rows.length);
        tctx.clearRect(col * CELL_W, row * CELL_H, CELL_W, CELL_H);
        tctx.fillText(pick(), (col + 0.5) * CELL_W, (row + 0.5) * CELL_H);
      }
    }

    let last = 0;
    function frame(now) {
      raf = 0;
      if (!visible || document.hidden) return;
      const dt = Math.min(64, now - (last || now));
      last = now;
      for (const row of rows) row.off += (row.speed * dt) / 1000;
      if (!lamp.hover) {
        const narrow = w < 900;
        lamp.tx = w * (narrow ? 0.5 + 0.34 * Math.sin(now * 0.00031) : 0.56 + 0.36 * Math.sin(now * 0.00027));
        lamp.ty = h * (narrow ? 0.2 + 0.05 * Math.sin(now * 0.00041 + 1) : 0.3 + 0.16 * Math.sin(now * 0.00041 + 1));
      }
      lamp.x += (lamp.tx - lamp.x) * 0.09;
      lamp.y += (lamp.ty - lamp.y) * 0.09;
      shimmer();
      draw(now);
      raf = requestAnimationFrame(frame);
    }
    function start() {
      if (reduce) { draw(0); return; }
      if (!raf && visible && !document.hidden) { last = 0; raf = requestAnimationFrame(frame); }
    }
    function stop() { if (raf) cancelAnimationFrame(raf); raf = 0; }

    hero.addEventListener("pointermove", (e) => {
      if (e.pointerType !== "mouse" || opening) return;
      const r = hero.getBoundingClientRect();
      lamp.tx = e.clientX - r.left;
      lamp.ty = e.clientY - r.top;
      lamp.hover = true;
    }, { passive: true });
    hero.addEventListener("pointerleave", () => { lamp.hover = false; }, { passive: true });

    document.fonts.load(FONT).catch(() => {}).finally(() => {
      layout();
      draw(0);
      new ResizeObserver(() => { layout(); if (reduce) draw(0); }).observe(hero);
      new IntersectionObserver(([entry]) => {
        visible = entry.isIntersecting;
        visible ? start() : stop();
      }).observe(hero);
      document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
      start();
    });

    return {
      // The lamp grows until the whole sheet is decrypted, then the passbook opens.
      open(done) {
        if (reduce) { done(); return; }
        opening = true;
        const from = radius, to = Math.hypot(w, h), began = performance.now();
        lamp.hover = true;
        const grow = (now) => {
          const t = Math.min(1, (now - began) / 620);
          radius = from + (to - from) * t * t * t;
          if (t < 1) requestAnimationFrame(grow);
          else done();
        };
        requestAnimationFrame(grow);
      },
    };
  }

  // ---------- headline decrypts once on load (DecryptedText, sequential) ----------
  function decrypt(el) {
    const text = el.textContent;
    el.setAttribute("aria-label", el.innerText.replace(/\s+/g, " ").trim() || text);
    const cells = [];
    for (const node of [...el.childNodes]) {
      if (node.nodeType !== Node.TEXT_NODE) continue;
      const frag = document.createDocumentFragment();
      node.textContent.split(/(\s+)/).forEach((part) => {
        if (!part.trim()) { frag.append(part); return; }
        const word = document.createElement("span");
        word.className = "w";
        word.setAttribute("aria-hidden", "true");
        for (const ch of part) {
          const c = document.createElement("span");
          c.className = "c";
          c.textContent = ch;
          word.append(c);
          cells.push(c);
        }
        frag.append(word);
      });
      node.replaceWith(frag);
    }
    // Fix each letter's width so scrambling never reflows the headline.
    cells.forEach((c) => { c.style.width = c.getBoundingClientRect().width + "px"; });
    const finals = cells.map((c) => c.textContent);
    let settled = 0;
    const tick = () => {
      cells.forEach((c, i) => {
        if (i < settled) { c.textContent = finals[i]; c.classList.remove("scrambling"); return; }
        c.textContent = pick();
        c.classList.add("scrambling");
      });
      settled += 1;
      if (settled <= cells.length) setTimeout(tick, 42);
      else cells.forEach((c) => { c.style.width = ""; });
    };
    tick();
  }

  // ---------- statement lights up word by word with scroll (ScrollReveal) ----------
  function scrollReveal(el) {
    const words = el.textContent.split(/(\s+)/);
    el.setAttribute("aria-label", el.textContent);
    el.textContent = "";
    const spans = [];
    for (const part of words) {
      if (!part.trim()) { el.append(part); continue; }
      const s = document.createElement("span");
      s.className = "word";
      s.setAttribute("aria-hidden", "true");
      s.textContent = part;
      s.style.opacity = "0.16";
      el.append(s);
      spans.push(s);
    }
    let ticking = false;
    const update = () => {
      ticking = false;
      const r = el.getBoundingClientRect(), vh = window.innerHeight;
      const p = Math.max(0, Math.min(1, (vh * 0.88 - r.top) / (r.height + vh * 0.36)));
      const lit = p * spans.length;
      spans.forEach((s, i) => { s.style.opacity = i < lit ? "1" : "0.16"; });
    };
    const request = () => { if (!ticking) { ticking = true; requestAnimationFrame(update); } };
    window.addEventListener("scroll", request, { passive: true });
    window.addEventListener("resize", request, { passive: true });
    update();
  }

  // ---------- button leans toward the pointer (Magnet) ----------
  function magnet(el) {
    const PADDING = 70, STRENGTH = 5;
    window.addEventListener("pointermove", (e) => {
      if (e.pointerType !== "mouse") return;
      const r = el.getBoundingClientRect();
      const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      const near = Math.abs(e.clientX - cx) < r.width / 2 + PADDING && Math.abs(e.clientY - cy) < r.height / 2 + PADDING;
      el.style.transition = near ? "transform .2s ease-out, background-color .2s" : "transform .55s ease-in-out, background-color .2s";
      el.style.transform = near ? `translate3d(${(e.clientX - cx) / STRENGTH}px, ${(e.clientY - cy) / STRENGTH}px, 0)` : "";
    }, { passive: true });
  }

  const print = microprint();

  document.querySelectorAll("[data-open]").forEach((link) => {
    link.addEventListener("click", (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
      e.preventDefault();
      print.open(() => { window.location.href = link.href; });
    });
  });

  // Stamps strike one after another when their list enters the screen; visible without script.
  const strikeList = document.querySelector("[data-strike]");
  const strikeNow = () => strikeList.querySelectorAll(".stamp").forEach((s, i) => {
    setTimeout(() => s.classList.add("struck"), reduce ? 0 : i * 340);
  });

  if (reduce || !("IntersectionObserver" in window)) {
    strikeNow();
    return;
  }

  document.fonts.ready.then(() => document.querySelectorAll("[data-decrypt]").forEach(decrypt));
  document.querySelectorAll("[data-scroll-reveal]").forEach(scrollReveal);
  document.querySelectorAll("[data-magnet]").forEach(magnet);

  const strikeIO = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) { strikeNow(); strikeIO.disconnect(); }
  }, { rootMargin: "0px 0px -18% 0px" });
  strikeIO.observe(strikeList);

  // Sections below settle in once as they enter; targets already on screen are left alone.
  const targets = document.querySelectorAll(".how h2, .stair li, .sources-head, .statement, .help h2, .helpline, .help-list li, .close h2");
  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("in");
      io.unobserve(entry.target);
    }
  }, { rootMargin: "0px 0px -8% 0px" });
  targets.forEach((t, i) => {
    if (t.getBoundingClientRect().top > window.innerHeight) {
      t.classList.add("reveal");
      t.style.transitionDelay = (i % 4) * 70 + "ms";
      io.observe(t);
    }
  });
})();
