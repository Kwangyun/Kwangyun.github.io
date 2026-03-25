// Kwang Security — consulting site interactions
(function () {
  'use strict';

  // ── Scroll reveal ─────────────────────────────────────────────────────────
  function initReveal() {
    if (!window.IntersectionObserver) {
      document.querySelectorAll('.c-reveal').forEach(function (el) {
        el.classList.add('is-visible');
      });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

    document.querySelectorAll('.c-reveal').forEach(function (el, i) {
      el.style.transitionDelay = Math.min(i * 0.04, 0.4) + 's';
      io.observe(el);
    });
  }

  // ── Animated counters ─────────────────────────────────────────────────────
  function initCounters() {
    var el = document.getElementById('c-metrics');
    if (!el || !window.IntersectionObserver) return;

    var fired = false;
    var io = new IntersectionObserver(function (entries) {
      if (!entries[0].isIntersecting || fired) return;
      fired = true;
      io.disconnect();

      el.querySelectorAll('.c-metric__num').forEach(function (num) {
        var target = parseInt(num.getAttribute('data-target'), 10);
        var suffix = num.getAttribute('data-suffix') || '';
        var current = 0;
        var step = Math.max(1, Math.ceil(target / 40));
        var timer = setInterval(function () {
          current = Math.min(current + step, target);
          num.textContent = current + suffix;
          if (current >= target) clearInterval(timer);
        }, 30);
      });
    }, { threshold: 0.5 });

    io.observe(el);
  }

  // ── Smooth nav highlight on scroll ───────────────────────────────────────
  function initNavHighlight() {
    var links = document.querySelectorAll('.masthead__menu-item a');
    if (!links.length) return;

    var sections = [];
    links.forEach(function (link) {
      var hash = link.getAttribute('href');
      if (hash && hash.includes('#')) {
        var id = hash.split('#')[1];
        var section = document.getElementById(id);
        if (section) sections.push({ link: link, section: section });
      }
    });

    window.addEventListener('scroll', function () {
      var scrollY = window.scrollY + 120;
      sections.forEach(function (item) {
        var top    = item.section.offsetTop;
        var bottom = top + item.section.offsetHeight;
        if (scrollY >= top && scrollY < bottom) {
          links.forEach(function (l) { l.style.color = ''; });
          item.link.style.color = 'var(--accent)';
        }
      });
    }, { passive: true });
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initReveal();
    initCounters();
    initNavHighlight();
  });
})();
