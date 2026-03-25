// Kwang Security — premium consulting interactions
(function () {
  'use strict';

  // ── Masthead: darken on scroll ────────────────────────────────────────────
  function initNav() {
    var nav = document.querySelector('.masthead');
    if (!nav) return;
    window.addEventListener('scroll', function () {
      nav.classList.toggle('scrolled', window.scrollY > 40);
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
    }, { threshold: 0.1, rootMargin: '0px 0px -30px 0px' });

    // Stagger siblings inside grids
    var groups = ['.c-services', '.c-sessions', '.c-posts', '.c-recog-list', '.c-hero__inner'];
    groups.forEach(function (sel) {
      document.querySelectorAll(sel).forEach(function (parent) {
        Array.from(parent.children).forEach(function (child, i) {
          if (!child.classList.contains('c-reveal')) return;
          child.style.transitionDelay = (i * 0.08) + 's';
        });
      });
    });

    document.querySelectorAll('.c-reveal').forEach(function (el) {
      io.observe(el);
    });
  }

  // ── Animated counters (easeOutExpo) ──────────────────────────────────────
  function initCounters() {
    var el = document.getElementById('c-metrics');
    if (!el || !window.IntersectionObserver) return;

    var fired = false;
    var io = new IntersectionObserver(function (entries) {
      if (!entries[0].isIntersecting || fired) return;
      fired = true;
      io.disconnect();

      el.querySelectorAll('.c-metric__num').forEach(function (num) {
        var target  = parseInt(num.getAttribute('data-target'), 10);
        var suffix  = num.getAttribute('data-suffix') || '';
        var start   = performance.now();
        var duration = 1600;

        function tick(now) {
          var elapsed = now - start;
          var progress = Math.min(elapsed / duration, 1);
          // easeOutExpo
          var eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
          var value = Math.floor(eased * target);
          num.textContent = value + suffix;
          if (progress < 1) requestAnimationFrame(tick);
          else num.textContent = target + suffix;
        }
        requestAnimationFrame(tick);
      });
    }, { threshold: 0.6 });
    io.observe(el);
  }

  // ── Magnetic buttons ─────────────────────────────────────────────────────
  function initMagnetic() {
    document.querySelectorAll('.c-btn--primary, .c-btn--ghost').forEach(function (btn) {
      btn.addEventListener('mousemove', function (e) {
        var r  = btn.getBoundingClientRect();
        var x  = (e.clientX - r.left - r.width  / 2) * 0.22;
        var y  = (e.clientY - r.top  - r.height / 2) * 0.22;
        btn.style.transform = 'translate(' + x + 'px,' + y + 'px) translateY(-2px)';
      });
      btn.addEventListener('mouseleave', function () {
        btn.style.transform = '';
      });
    });
  }

  // ── Smooth active nav on scroll ───────────────────────────────────────────
  function initNavHighlight() {
    var links = document.querySelectorAll('.masthead__menu-item a');
    if (!links.length) return;
    var sections = [];
    links.forEach(function (link) {
      var href = link.getAttribute('href') || '';
      if (!href.includes('#')) return;
      var id  = href.split('#')[1];
      var sec = document.getElementById(id);
      if (sec) sections.push({ link: link, sec: sec });
    });
    window.addEventListener('scroll', function () {
      var y = window.scrollY + 140;
      sections.forEach(function (item) {
        var top = item.sec.offsetTop;
        var bot = top + item.sec.offsetHeight;
        var active = y >= top && y < bot;
        item.link.style.color = active ? 'var(--blue)' : '';
      });
    }, { passive: true });
  }

  // ── Hero parallax (subtle) ────────────────────────────────────────────────
  function initParallax() {
    var blobs = document.querySelectorAll('.c-hero__blob');
    if (!blobs.length) return;
    window.addEventListener('scroll', function () {
      var y = window.scrollY;
      blobs.forEach(function (blob, i) {
        var speed = (i + 1) * 0.08;
        blob.style.transform = 'translateY(' + (y * speed) + 'px)';
      });
    }, { passive: true });
  }

  // ── Boot ─────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initNav();
    initReveal();
    initCounters();
    initMagnetic();
    initNavHighlight();
    initParallax();
  });
})();
