// Security-paper guilloche behind the passbook spread.
// A Canvas 2D port of ReactBits "Waves" (lines bent by Perlin noise, pushed aside by the pointer and
// sprung back), trimmed for low-end phones: no WebGL, paused when off screen or the tab is hidden,
// drawn once and left still under prefers-reduced-motion.
(() => {
  const canvas = document.querySelector(".guilloche");
  if (!canvas) return;
  const host = canvas.parentElement;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const SPACING = 15;      // px between lines
  const STEP = 10;         // px between samples along a line
  const AMPLITUDE = 22;    // px of noise displacement
  const SCALE = 0.0021;    // noise frequency
  const SPEED = 0.00005;   // noise drift per ms
  const RADIUS = 150;      // pointer influence
  const PUSH = 34;         // max pointer displacement
  const SPRING = 0.08, DAMP = 0.82;

  // Perlin noise (2D), as in the ReactBits shader.
  const perm = new Uint8Array(512);
  {
    const p = Array.from({ length: 256 }, (_, i) => i);
    let seed = 1337;
    for (let i = 255; i > 0; i--) {
      seed = (seed * 16807) % 2147483647;
      const j = seed % (i + 1);
      [p[i], p[j]] = [p[j], p[i]];
    }
    for (let i = 0; i < 512; i++) perm[i] = p[i & 255];
  }
  const G = [[1, 1], [-1, 1], [1, -1], [-1, -1], [1, 0], [-1, 0], [0, 1], [0, -1]];
  const fade = (t) => t * t * t * (t * (t * 6 - 15) + 10);
  const grad = (h, x, y) => { const g = G[h & 7]; return g[0] * x + g[1] * y; };
  function perlin(x, y) {
    const xi = Math.floor(x), yi = Math.floor(y);
    const xf = x - xi, yf = y - yi;
    const X = xi & 255, Y = yi & 255;
    const aa = perm[X + perm[Y]], ab = perm[X + perm[Y + 1]];
    const ba = perm[X + 1 + perm[Y]], bb = perm[X + 1 + perm[Y + 1]];
    const u = fade(xf), v = fade(yf);
    const x1 = grad(aa, xf, yf) + u * (grad(ba, xf - 1, yf) - grad(aa, xf, yf));
    const x2 = grad(ab, xf, yf - 1) + u * (grad(bb, xf - 1, yf - 1) - grad(ab, xf, yf - 1));
    return x1 + v * (x2 - x1);
  }

  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  const pointer = { x: -9999, y: -9999, active: false };
  let width = 0, height = 0, dpr = 1, lines = [], color = "#bcd2c4";
  let raf = 0, last = 0, visible = true, time = 0;

  function readColor() {
    color = getComputedStyle(document.documentElement).getPropertyValue("--guilloche").trim() || color;
  }

  function layout() {
    const rect = host.getBoundingClientRect();
    width = Math.max(1, Math.round(rect.width));
    height = Math.max(1, Math.round(rect.height));
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    lines = [];
    const count = Math.ceil((height + AMPLITUDE * 4) / SPACING);
    const points = Math.ceil(width / STEP) + 2;
    for (let i = 0; i < count; i++) {
      // per-point spring offset (y only) and velocity
      lines.push({ y: i * SPACING - AMPLITUDE * 2, off: new Float32Array(points), vel: new Float32Array(points) });
    }
    draw();
  }

  function draw() {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = color;
    ctx.lineWidth = 1;
    const t = time * SPEED;
    for (let li = 0; li < lines.length; li++) {
      const line = lines[li];
      ctx.beginPath();
      for (let i = 0; i < line.off.length; i++) {
        const x = i * STEP;
        const n = perlin(x * SCALE + t, line.y * SCALE * 1.6 - t * 0.6);
        const y = line.y + n * AMPLITUDE * 2 + Math.sin(x * 0.012 + line.y * 0.05) * 3 + line.off[i];
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.stroke();
    }
  }

  function physics() {
    let moving = false;
    for (const line of lines) {
      for (let i = 0; i < line.off.length; i++) {
        let target = 0;
        if (pointer.active) {
          const dx = i * STEP - pointer.x, dy = line.y + line.off[i] - pointer.y;
          const d = Math.hypot(dx, dy);
          if (d < RADIUS) {
            const f = 1 - d / RADIUS;
            target = Math.max(-1, Math.min(1, dy / 40)) * PUSH * f * f;
          }
        }
        line.vel[i] = (line.vel[i] + (target - line.off[i]) * SPRING) * DAMP;
        line.off[i] += line.vel[i];
        if (Math.abs(line.vel[i]) > 0.01 || Math.abs(line.off[i]) > 0.05) moving = true;
      }
    }
    return moving;
  }

  function frame(now) {
    raf = 0;
    if (!visible || document.hidden) return;
    const dt = Math.min(64, now - (last || now));
    last = now;
    time += dt;
    physics();
    draw();
    raf = requestAnimationFrame(frame);
  }

  function start() {
    if (reduce.matches) { draw(); return; }
    if (!raf && visible && !document.hidden) { last = 0; raf = requestAnimationFrame(frame); }
  }
  function stop() { if (raf) cancelAnimationFrame(raf); raf = 0; }

  host.addEventListener("pointermove", (e) => {
    const r = host.getBoundingClientRect();
    pointer.x = e.clientX - r.left;
    pointer.y = e.clientY - r.top;
    pointer.active = e.pointerType === "mouse";
  }, { passive: true });
  host.addEventListener("pointerleave", () => { pointer.active = false; }, { passive: true });

  new ResizeObserver(() => layout()).observe(host);
  new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
    visible ? start() : stop();
  }).observe(host);
  document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
  reduce.addEventListener?.("change", () => { stop(); start(); });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", () => { readColor(); draw(); });

  readColor();
  layout();
  start();
})();
