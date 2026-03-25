// hacker.js — award-winning terminal/hacker aesthetic
// kwangyun.github.io
(function () {
  'use strict';

  // ── Custom cursor ──────────────────────────────────────────────────────────
  function initCursor() {
    var dot   = document.createElement('div');
    var ring  = document.createElement('div');
    dot.id    = 'hk-cursor-dot';
    ring.id   = 'hk-cursor-ring';
    document.body.appendChild(dot);
    document.body.appendChild(ring);

    var mx = 0, my = 0, rx = 0, ry = 0;

    document.addEventListener('mousemove', function (e) {
      mx = e.clientX;
      my = e.clientY;
      dot.style.transform = 'translate(' + (mx - 4) + 'px,' + (my - 4) + 'px)';
    });

    // Ring follows with lag
    (function animRing() {
      rx += (mx - rx) * 0.12;
      ry += (my - ry) * 0.12;
      ring.style.transform = 'translate(' + (rx - 16) + 'px,' + (ry - 16) + 'px)';
      requestAnimationFrame(animRing);
    })();

    // Expand on hover
    document.querySelectorAll('a, button, .archive__item').forEach(function (el) {
      el.addEventListener('mouseenter', function () { ring.classList.add('hk-cursor-hover'); });
      el.addEventListener('mouseleave', function () { ring.classList.remove('hk-cursor-hover'); });
    });
  }

  // ── Matrix rain ────────────────────────────────────────────────────────────
  function initMatrixRain() {
    var canvas = document.createElement('canvas');
    canvas.id = 'hk-matrix';
    canvas.style.cssText =
      'position:fixed;top:0;left:0;width:100%;height:100%;' +
      'z-index:0;pointer-events:none;opacity:1;';
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d');
    var W, H, cols, drops;
    var CHARS =
      'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン' +
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*<>/|[]{}';
    var FS = 13;

    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
      cols = Math.floor(W / FS);
      drops = Array.from({ length: cols }, function () { return Math.random() * -80; });
    }

    var frame = 0;
    function draw() {
      frame++;
      // Fade trail
      ctx.fillStyle = 'rgba(10,10,10,0.055)';
      ctx.fillRect(0, 0, W, H);

      for (var i = 0; i < drops.length; i++) {
        var y = drops[i] * FS;
        if (y < 0 || y > H) { drops[i] += 0.5; continue; }

        // Head — bright white-green
        ctx.fillStyle = '#ccffcc';
        ctx.font = 'bold ' + FS + 'px monospace';
        ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], i * FS, y);

        // Body — neon green
        ctx.fillStyle = 'rgba(0,255,65,0.55)';
        ctx.font = FS + 'px monospace';
        ctx.fillText(CHARS[Math.floor(Math.random() * CHARS.length)], i * FS, y - FS);

        if (y > H && Math.random() > 0.975) drops[i] = 0;
        drops[i] += 0.45;
      }
    }

    resize();
    setInterval(draw, 38);
    window.addEventListener('resize', resize);
  }

  // ── Noise texture overlay ─────────────────────────────────────────────────
  function initNoise() {
    var noise = document.createElement('canvas');
    noise.style.cssText =
      'position:fixed;top:0;left:0;width:100%;height:100%;' +
      'z-index:9997;pointer-events:none;opacity:0.028;';
    var nc  = noise.getContext('2d');
    noise.width  = 256;
    noise.height = 256;
    var id = nc.createImageData(256, 256);
    for (var i = 0; i < id.data.length; i += 4) {
      var v = Math.random() * 255;
      id.data[i] = v; id.data[i+1] = v; id.data[i+2] = v; id.data[i+3] = 255;
    }
    nc.putImageData(id, 0, 0);
    document.body.appendChild(noise);
  }

  // ── CRT flicker ───────────────────────────────────────────────────────────
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
    title.childNodes.forEach(function(n){ if(n.nodeType===3) raw += n.textContent; });
    raw = raw.trim() || title.textContent.trim();
    title.setAttribute('data-text', raw);

    function fire() {
      title.classList.add('glitching');
      setTimeout(function () { title.classList.remove('glitching'); }, 200);
      setTimeout(fire, 3500 + Math.random() * 10000);
    }
    setTimeout(fire, 2000);
  }

  // ── Scroll-reveal ─────────────────────────────────────────────────────────
  function initReveal() {
    var items = document.querySelectorAll('.list__item, .archive__item, h3.archive__subtitle');
    if (!items.length) return;

    items.forEach(function (el, i) {
      el.style.opacity    = '0';
      el.style.transform  = 'translateY(28px)';
      el.style.transition = 'opacity 0.55s ease ' + (i * 0.06) + 's, transform 0.55s ease ' + (i * 0.06) + 's';
    });

    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.style.opacity   = '1';
          entry.target.style.transform = 'translateY(0)';
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    items.forEach(function (el) { io.observe(el); });
  }

  // ── Card 3D tilt on hover ─────────────────────────────────────────────────
  function initTilt() {
    document.querySelectorAll('.list__item .archive__item').forEach(function (card) {
      card.addEventListener('mousemove', function (e) {
        var r   = card.getBoundingClientRect();
        var x   = (e.clientX - r.left) / r.width  - 0.5;
        var y   = (e.clientY - r.top)  / r.height - 0.5;
        card.style.transform = 'perspective(600px) rotateY(' + (x * 6) + 'deg) rotateX(' + (-y * 6) + 'deg) translateZ(4px)';
      });
      card.addEventListener('mouseleave', function () {
        card.style.transform = 'perspective(600px) rotateY(0) rotateX(0) translateZ(0)';
      });
    });
  }

  // ── Animated stat counters ────────────────────────────────────────────────
  function initStats() {
    var statsEl = document.getElementById('hk-stats');
    if (!statsEl) return;

    var counters = statsEl.querySelectorAll('.hk-stat-num');
    var io = new IntersectionObserver(function (entries) {
      if (!entries[0].isIntersecting) return;
      io.disconnect();
      counters.forEach(function (el) {
        var target = parseInt(el.getAttribute('data-target'), 10);
        var start  = 0;
        var step   = Math.ceil(target / 40);
        var timer  = setInterval(function () {
          start = Math.min(start + step, target);
          el.textContent = start + (el.getAttribute('data-suffix') || '');
          if (start >= target) clearInterval(timer);
        }, 35);
      });
    }, { threshold: 0.5 });
    io.observe(statsEl);
  }

  // ── Terminal typing (home page) ───────────────────────────────────────────
  function initTerminal() {
    var outputEl = document.getElementById('terminal-output');
    var cmdEl    = document.getElementById('typed-cmd');
    if (!outputEl || !cmdEl) return;

    var sequence = [
      { cmd: 'whoami',
        out: 'kwang &mdash; offensive security researcher @ bytedance red team' },
      { cmd: 'cat skills.txt',
        out: 'red team &nbsp;|&nbsp; edr bypass &nbsp;|&nbsp; byovd &nbsp;|&nbsp; malware dev &nbsp;|&nbsp; web vulns' },
      { cmd: 'ls ./findings/',
        out: 'nasa_xss.md &nbsp; harvard_authz_bypass.md &nbsp; un_broken_auth.md &nbsp; ed_naep_api.md' },
    ];

    var seq = 0;

    function typeCmd(cmd, done) {
      var i = 0; cmdEl.textContent = '';
      (function tick() {
        if (i < cmd.length) {
          cmdEl.textContent += cmd[i++];
          setTimeout(tick, 52 + Math.random() * 38);
        } else { setTimeout(done, 300); }
      })();
    }

    function appendLine(html, cls) {
      var div = document.createElement('div');
      div.className = cls || '';
      div.innerHTML = html;
      outputEl.appendChild(div);
    }

    function runNext() {
      if (seq >= sequence.length) { cmdEl.textContent = ''; return; }
      var item = sequence[seq++];
      typeCmd(item.cmd, function () {
        appendLine('<span class="prompt">kwang@redhunter:~$</span> ' + item.cmd, 'terminal-cmd-line');
        cmdEl.textContent = '';
        setTimeout(function () {
          appendLine(item.out, 'terminal-out-line');
          setTimeout(runNext, 400);
        }, 130);
      });
    }
    setTimeout(runNext, 800);
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initMatrixRain();
    initNoise();
    initScanlines();
    initGlitch();
    initTerminal();
    initReveal();
    initTilt();
    initStats();
    // Cursor only on non-touch
    if (window.matchMedia('(pointer: fine)').matches) initCursor();
  });
})();
