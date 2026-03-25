// hacker.js — Kwang Security
(function () {
  'use strict';

  // ── Custom cursor ──────────────────────────────────────────────────────────
  function initCursor() {
    var dot  = document.createElement('div');
    var ring = document.createElement('div');
    dot.id  = 'hk-cursor-dot';
    ring.id = 'hk-cursor-ring';
    document.body.appendChild(dot);
    document.body.appendChild(ring);

    var mx = 0, my = 0, rx = 0, ry = 0;

    document.addEventListener('mousemove', function (e) {
      mx = e.clientX; my = e.clientY;
      dot.style.transform = 'translate(' + (mx - 3.5) + 'px,' + (my - 3.5) + 'px)';
    });

    (function animRing() {
      rx += (mx - rx) * 0.11;
      ry += (my - ry) * 0.11;
      ring.style.transform = 'translate(' + (rx - 15) + 'px,' + (ry - 15) + 'px)';
      requestAnimationFrame(animRing);
    })();

    document.querySelectorAll('a, button, .hk-btn, .hk-service-card, .hk-post-card').forEach(function (el) {
      el.addEventListener('mouseenter', function () { ring.classList.add('hk-cursor-hover'); });
      el.addEventListener('mouseleave', function () { ring.classList.remove('hk-cursor-hover'); });
    });
  }

  // ── Matrix rain ────────────────────────────────────────────────────────────
  function initMatrixRain() {
    var canvas = document.createElement('canvas');
    canvas.id = 'hk-matrix';
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d');
    var W, H, cols, drops;
    var CHARS =
      'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホ' +
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*<>/|[]{}';
    var FS = 13;

    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
      cols  = Math.floor(W / FS);
      drops = Array.from({ length: cols }, function () { return Math.random() * -80; });
    }

    function draw() {
      ctx.fillStyle = 'rgba(8,8,8,0.055)';
      ctx.fillRect(0, 0, W, H);

      for (var i = 0; i < drops.length; i++) {
        var y = drops[i] * FS;
        if (y < 0) { drops[i] += 0.4; continue; }
        // head
        ctx.fillStyle = 'rgba(220,255,220,0.9)';
        ctx.font = 'bold ' + FS + 'px monospace';
        ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], i * FS, y);
        // body
        ctx.fillStyle = 'rgba(0,255,65,0.45)';
        ctx.font = FS + 'px monospace';
        if (y > FS) ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], i * FS, y - FS);

        if (y > H && Math.random() > 0.975) drops[i] = 0;
        drops[i] += 0.42;
      }
    }

    resize();
    setInterval(draw, 40);
    window.addEventListener('resize', resize);
  }

  // ── Scanlines ─────────────────────────────────────────────────────────────
  function initScanlines() {
    var el = document.createElement('div');
    el.id  = 'hk-scanlines';
    document.body.appendChild(el);
  }

  // ── Glitch on site title ──────────────────────────────────────────────────
  function initGlitch() {
    var title = document.querySelector('.site-title');
    if (!title) return;
    var raw = '';
    title.childNodes.forEach(function (n) { if (n.nodeType === 3) raw += n.textContent; });
    raw = raw.trim() || title.textContent.trim();
    title.setAttribute('data-text', raw);

    function fire() {
      title.classList.add('glitching');
      setTimeout(function () { title.classList.remove('glitching'); }, 200);
      setTimeout(fire, 4000 + Math.random() * 12000);
    }
    setTimeout(fire, 2500);
  }

  // ── Scroll reveal ─────────────────────────────────────────────────────────
  function initReveal() {
    var targets = document.querySelectorAll(
      '.hk-service-card, .hk-post-card, .hk-hof-item, .hk-metric, .hk-hero__inner > *'
    );
    if (!targets.length || !window.IntersectionObserver) return;

    targets.forEach(function (el, i) {
      el.classList.add('hk-reveal');
      el.style.transitionDelay = (i * 0.055) + 's';
    });

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('hk-visible');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    targets.forEach(function (el) { io.observe(el); });
  }

  // ── Animated metric counters ──────────────────────────────────────────────
  function initCounters() {
    var statsEl = document.getElementById('hk-stats');
    if (!statsEl || !window.IntersectionObserver) return;

    var io = new IntersectionObserver(function (entries) {
      if (!entries[0].isIntersecting) return;
      io.disconnect();
      statsEl.querySelectorAll('.hk-metric__num').forEach(function (el) {
        var target = parseInt(el.getAttribute('data-target'), 10);
        var suffix = el.getAttribute('data-suffix') || '';
        var count  = 0;
        var step   = Math.max(1, Math.ceil(target / 45));
        var timer  = setInterval(function () {
          count = Math.min(count + step, target);
          el.textContent = count + suffix;
          if (count >= target) clearInterval(timer);
        }, 32);
      });
    }, { threshold: 0.5 });

    io.observe(statsEl);
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initMatrixRain();
    initScanlines();
    initGlitch();
    initReveal();
    initCounters();
    if (window.matchMedia('(pointer: fine)').matches) initCursor();
  });
})();
