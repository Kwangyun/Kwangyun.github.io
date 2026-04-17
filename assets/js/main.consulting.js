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

  // ── Process: connected timeline + tab detail (Ellis O-1 replica) ─────────
  function initProcessTabs() {
    var steps = document.querySelectorAll('.c-timeline__step');
    var tabs = document.querySelectorAll('.c-process-detail__tab');
    var panels = document.querySelectorAll('.c-process-detail__panel');
    var trackFill = document.querySelector('[data-track-fill]');
    var pmPhase = document.querySelector('[data-pm="phase"]');
    var pmProgress = document.querySelector('[data-pm="progress"]');
    var pmChecks = document.querySelector('[data-pm="checks"]');
    if (!steps.length && !tabs.length) return;

    var phaseNames = ['Scoping', 'Discovery', 'Exploitation', 'Reporting'];
    var phaseChecks = [14, 287, 62, 9];
    var autoTimer = null;
    var checksTimer = null;

    function activate(stepId, fromAuto) {
      var stepNum = parseInt(stepId, 10);

      steps.forEach(function (s) {
        var id = parseInt(s.getAttribute('data-step'), 10);
        s.classList.remove('is-active', 'is-complete');
        if (id < stepNum) s.classList.add('is-complete');
        if (id === stepNum) s.classList.add('is-active');
      });

      if (trackFill && steps.length > 1) {
        var pct = ((stepNum - 1) / (steps.length - 1)) * 100;
        trackFill.style.width = (pct * 0.75) + '%';
      }

      tabs.forEach(function (t) { t.classList.remove('is-active'); });
      panels.forEach(function (p) { p.classList.remove('is-active'); });
      var tab = document.querySelector('.c-process-detail__tab[data-step="' + stepId + '"]');
      var panel = document.querySelector('.c-process-detail__panel[data-panel="' + stepId + '"]');
      if (tab) tab.classList.add('is-active');
      if (panel) panel.classList.add('is-active');

      // Update live metrics bar
      if (pmPhase)    pmPhase.textContent = phaseNames[stepNum - 1];
      if (pmProgress) pmProgress.textContent = (stepNum * 25) + '%';
      if (pmChecks)   pmChecks.setAttribute('data-target', phaseChecks[stepNum - 1]);
      startChecksTick(phaseChecks[stepNum - 1]);

      // Reset auto-advance timer when user interacts
      if (!fromAuto) restartAuto();
    }

    function nextStep() {
      var active = document.querySelector('.c-timeline__step.is-active');
      var current = active ? parseInt(active.getAttribute('data-step'), 10) : 1;
      var next = (current % steps.length) + 1;
      activate(String(next), true);
    }

    function startAuto() {
      stopAuto();
      autoTimer = setInterval(nextStep, 5000);
    }
    function stopAuto() {
      if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
    }
    function restartAuto() { stopAuto(); startAuto(); }

    // Animated count up/drift on checks number
    function startChecksTick(target) {
      if (!pmChecks) return;
      if (checksTimer) clearInterval(checksTimer);
      var current = parseInt(pmChecks.textContent.replace(/,/g, ''), 10) || 0;
      var step = target > current ? Math.max(1, Math.round((target - current) / 20)) : -Math.max(1, Math.round((current - target) / 20));
      var countedTo = current;
      checksTimer = setInterval(function () {
        countedTo += step;
        if ((step > 0 && countedTo >= target) || (step < 0 && countedTo <= target)) {
          countedTo = target;
          clearInterval(checksTimer);
          // Then start a small jitter to simulate "live" scanning
          checksTimer = setInterval(function () {
            var jitter = Math.floor(Math.random() * 5) - 2;
            var val = Math.max(1, target + jitter);
            pmChecks.textContent = val.toLocaleString();
          }, 900);
        }
        pmChecks.textContent = countedTo.toLocaleString();
      }, 50);
    }

    steps.forEach(function (s) {
      s.addEventListener('click', function () { activate(s.getAttribute('data-step')); });
    });
    tabs.forEach(function (t) {
      t.addEventListener('click', function () { activate(t.getAttribute('data-step')); });
    });

    // Keyboard navigation on tabs
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

    // Pause auto-advance when user hovers the section
    var section = document.getElementById('process');
    if (section) {
      section.addEventListener('mouseenter', stopAuto);
      section.addEventListener('mouseleave', startAuto);
    }

    // Start on step 1 + begin auto-cycling
    activate('1', true);
    startAuto();
  }

  // ── Boot ─────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    // Aurora / noise / grid disabled for light theme
    // initAurora();
    // initNoise();
    // initGrid();
    initNav();
    initReveal();
    initCounters();
    initMagnetic();
    initNavHighlight();
    initProcessTabs();
  });
})();
