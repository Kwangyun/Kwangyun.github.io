// Kwang Security — premium consulting interactions
(function () {
  'use strict';

  // ── Aurora canvas (Stripe-style floating mesh gradient) ───────────────────
  function initAurora() {
    var canvas = document.createElement('canvas');
    canvas.id = 'aurora';
    canvas.style.cssText =
      'position:fixed;top:0;left:0;width:100%;height:100%;' +
      'z-index:0;pointer-events:none;';
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d');
    var W = 0, H = 0;

    // Orbs: fixed orbital center + sine-wave offset
    var orbs = [
      { ox: 0.15, oy: 0.25, r: 0.65, color: [77, 124, 254],  a: 0,    sa: 0.00035, sb: 0.00028, pa: 0.14, pb: 0.10 },
      { ox: 0.85, oy: 0.15, r: 0.58, color: [139, 92, 246],  a: 2.1,  sa: 0.00025, sb: 0.00038, pa: 0.12, pb: 0.13 },
      { ox: 0.50, oy: 0.82, r: 0.60, color: [59, 130, 246],  a: 4.2,  sa: 0.00030, sb: 0.00022, pa: 0.16, pb: 0.11 },
      { ox: 0.72, oy: 0.55, r: 0.48, color: [167, 139, 250], a: 1.0,  sa: 0.00018, sb: 0.00032, pa: 0.10, pb: 0.14 },
      { ox: 0.30, oy: 0.70, r: 0.45, color: [99, 102, 241],  a: 3.3,  sa: 0.00022, sb: 0.00026, pa: 0.13, pb: 0.09 },
    ];

    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
    }

    var t = 0;
    function draw() {
      ctx.clearRect(0, 0, W, H);
      t += 1;

      orbs.forEach(function (orb) {
        orb.a += orb.sa;
        var x = (orb.ox + Math.sin(orb.a)           * orb.pa) * W;
        var y = (orb.oy + Math.cos(orb.a * 1.3 + 1) * orb.pb) * H;
        var r = orb.r * Math.max(W, H) * 0.75;

        var g = ctx.createRadialGradient(x, y, 0, x, y, r);
        g.addColorStop(0,   'rgba(' + orb.color + ',0.20)');
        g.addColorStop(0.35,'rgba(' + orb.color + ',0.07)');
        g.addColorStop(1,   'rgba(' + orb.color + ',0)');

        ctx.fillStyle = g;
        ctx.fillRect(0, 0, W, H);
      });

      requestAnimationFrame(draw);
    }

    resize();
    draw();
    window.addEventListener('resize', resize, { passive: true });
  }

  // ── Noise texture overlay ────────────────────────────────────────────────
  function initNoise() {
    var c  = document.createElement('canvas');
    var cx = c.getContext('2d');
    c.width = c.height = 200;
    var id = cx.createImageData(200, 200);
    for (var i = 0; i < id.data.length; i += 4) {
      var v = (Math.random() * 255) | 0;
      id.data[i] = id.data[i+1] = id.data[i+2] = v;
      id.data[i+3] = 255;
    }
    cx.putImageData(id, 0, 0);

    var el = document.createElement('div');
    el.style.cssText =
      'position:fixed;top:0;left:0;width:100%;height:100%;' +
      'background-image:url(' + c.toDataURL() + ');' +
      'background-repeat:repeat;' +
      'opacity:0.022;pointer-events:none;z-index:9996;';
    document.body.appendChild(el);
  }

  // ── Grid overlay ─────────────────────────────────────────────────────────
  function initGrid() {
    var el = document.createElement('div');
    el.id  = 'grid-overlay';
    document.body.insertBefore(el, document.body.children[1] || null);
  }

  // ── Masthead: darken + blur more on scroll ─────────────────────────────
  function initNav() {
    var nav = document.querySelector('.masthead');
    if (!nav) return;
    window.addEventListener('scroll', function () {
      nav.classList.toggle('scrolled', window.scrollY > 50);
    }, { passive: true });
  }

  // ── Scroll reveal with staggered children ────────────────────────────────
  function initReveal() {
    if (!window.IntersectionObserver) {
      document.querySelectorAll('.c-reveal').forEach(function (el) {
        el.classList.add('is-visible');
      });
      return;
    }

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('is-visible');
        io.unobserve(entry.target);
      });
    }, { threshold: 0.08, rootMargin: '0px 0px -20px 0px' });

    var groups = ['.c-services', '.c-sessions', '.c-posts', '.c-recog-list', '.c-hero__inner', '.c-metrics'];
    groups.forEach(function (sel) {
      document.querySelectorAll(sel).forEach(function (parent) {
        Array.from(parent.children).forEach(function (child, i) {
          if (!child.classList.contains('c-reveal')) return;
          child.style.transitionDelay = (i * 0.09) + 's';
        });
      });
    });

    document.querySelectorAll('.c-reveal').forEach(function (el) { io.observe(el); });
  }

  // ── Animated counters (easeOutExpo) ──────────────────────────────────────
  function initCounters() {
    var el = document.getElementById('c-metrics');
    if (!el || !window.IntersectionObserver) return;

    var fired = false;
    var io = new IntersectionObserver(function (entries) {
      if (!entries[0].isIntersecting || fired) return;
      fired = true; io.disconnect();

      el.querySelectorAll('.c-metric__num').forEach(function (num) {
        var target   = parseInt(num.getAttribute('data-target'), 10);
        var suffix   = num.getAttribute('data-suffix') || '';
        var start    = performance.now();
        var duration = 1800;
        (function tick(now) {
          var p = Math.min((now - start) / duration, 1);
          var e = p === 1 ? 1 : 1 - Math.pow(2, -10 * p);
          num.textContent = (Math.floor(e * target)) + suffix;
          if (p < 1) requestAnimationFrame(tick);
          else num.textContent = target + suffix;
        })(performance.now());
      });
    }, { threshold: 0.5 });
    io.observe(el);
  }

  // ── Magnetic buttons ─────────────────────────────────────────────────────
  function initMagnetic() {
    document.querySelectorAll('.c-btn').forEach(function (btn) {
      btn.addEventListener('mousemove', function (e) {
        var r = btn.getBoundingClientRect();
        var x = (e.clientX - r.left - r.width  / 2) * 0.25;
        var y = (e.clientY - r.top  - r.height / 2) * 0.25;
        btn.style.transform = 'translate(' + x + 'px,' + y + 'px) translateY(-2px)';
      });
      btn.addEventListener('mouseleave', function () {
        btn.style.transform = '';
      });
    });
  }

  // ── Smooth nav section highlight ─────────────────────────────────────────
  function initNavHighlight() {
    var links = document.querySelectorAll('.masthead__menu-item a');
    if (!links.length) return;
    var secs = [];
    links.forEach(function (link) {
      var href = link.getAttribute('href') || '';
      if (!href.includes('#')) return;
      var sec = document.getElementById(href.split('#')[1]);
      if (sec) secs.push({ link: link, sec: sec });
    });
    window.addEventListener('scroll', function () {
      var y = window.scrollY + 140;
      secs.forEach(function (item) {
        var active = y >= item.sec.offsetTop && y < item.sec.offsetTop + item.sec.offsetHeight;
        item.link.style.color = active ? 'var(--blue)' : '';
      });
    }, { passive: true });
  }

  // ── Process tabs (Ellis-style interactive timeline) ───────────────────────
  function initProcessTabs() {
    var tabs = document.querySelectorAll('.c-process__tab');
    var panels = document.querySelectorAll('.c-process__panel');
    if (!tabs.length) return;

    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        var step = tab.getAttribute('data-step');
        tabs.forEach(function (t) {
          t.classList.remove('is-active');
          t.setAttribute('aria-selected', 'false');
        });
        panels.forEach(function (p) { p.classList.remove('is-active'); });

        tab.classList.add('is-active');
        tab.setAttribute('aria-selected', 'true');
        var panel = document.querySelector('.c-process__panel[data-panel="' + step + '"]');
        if (panel) panel.classList.add('is-active');
      });
    });

    // Keyboard navigation (arrow keys)
    tabs.forEach(function (tab, idx) {
      tab.addEventListener('keydown', function (e) {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        e.preventDefault();
        var next = e.key === 'ArrowRight'
          ? (idx + 1) % tabs.length
          : (idx - 1 + tabs.length) % tabs.length;
        tabs[next].focus();
        tabs[next].click();
      });
    });
  }

  // ── Boot ─────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initAurora();
    initNoise();
    initGrid();
    initNav();
    initReveal();
    initCounters();
    initMagnetic();
    initNavHighlight();
    initProcessTabs();
  });
})();
