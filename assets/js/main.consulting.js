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

    // Full kill-chain sequence. Each item:
    //   { cmd: '<html command>', out: ['<html line1>', ...], postWait: ms }
    var frames = [
      {
        cmd: '<span class="tl-cmd">nmap</span> <span class="tl-flag">-sS -sV -Pn -p</span> <span class="tl-num">88,135,389,445,636,3268</span> <span class="tl-num">10.10.10.0/24</span>',
        out: [
          '<span class="tl-dim">Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-16 09:14 UTC</span>',
          'Nmap scan report for <span class="tl-hi">dc01.acme.local</span> (<span class="tl-num">10.10.10.10</span>)',
          '<span class="tl-dim">Host is up (0.0021s latency).</span>',
          'PORT     STATE SERVICE      VERSION',
          '<span class="tl-num">88/tcp</span>   <span class="tl-ok">open</span>  kerberos-sec Microsoft Windows Kerberos',
          '<span class="tl-num">389/tcp</span>  <span class="tl-ok">open</span>  ldap         Microsoft Windows Active Directory LDAP',
          '<span class="tl-num">445/tcp</span>  <span class="tl-ok">open</span>  microsoft-ds Windows Server 2019 Standard 17763',
          '<span class="tl-num">636/tcp</span>  <span class="tl-ok">open</span>  tcpwrapped',
          '<span class="tl-num">3268/tcp</span> <span class="tl-ok">open</span>  ldap         Microsoft Windows AD LDAP (Global Catalog)',
          '<span class="tl-dim">Service detection performed. 1 IP (1 host up) scanned in 12.47s</span>',
        ],
        postWait: 900,
      },
      {
        cmd: '<span class="tl-cmd">netexec</span> smb <span class="tl-num">10.10.10.0/24</span> <span class="tl-flag">--shares -u</span> <span class="tl-str">\'\'</span> <span class="tl-flag">-p</span> <span class="tl-str">\'\'</span>',
        out: [
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     [*] Windows Server 2019 (name:DC01)</span>',
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     [+] acme.local\\: (Guest)</span>',
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     [*] Enumerated shares</span>',
          'SMB     10.10.10.10    445  DC01     Share          Permissions  Remark',
          'SMB     10.10.10.10    445  DC01     <span class="tl-hi">SYSVOL</span>         <span class="tl-ok">READ</span>         Logon server share',
          'SMB     10.10.10.10    445  DC01     <span class="tl-hi">NETLOGON</span>       <span class="tl-ok">READ</span>         Logon server share',
          '<span class="tl-warn">SMB     10.10.10.10    445  DC01     [!] SMB signing: False — vulnerable to relay</span>',
        ],
        postWait: 800,
      },
      {
        cmd: '<span class="tl-cmd">sudo responder</span> <span class="tl-flag">-I</span> <span class="tl-num">eth0</span> <span class="tl-flag">-wFd</span>',
        out: [
          '<span class="tl-dim">[+] Listening for events...</span>',
          '<span class="tl-dim">[*] [LLMNR] Poisoned answer sent to 10.10.10.42 for name WORKSTATION05</span>',
          '<span class="tl-dim">[*] [LLMNR] Poisoned answer sent to 10.10.10.42 for name WORKSTATION05</span>',
          '<span class="tl-ok">[SMB] NTLMv2-SSP Client   : 10.10.10.42</span>',
          '<span class="tl-ok">[SMB] NTLMv2-SSP Username : ACME\\<span class="tl-user">svc_backup</span></span>',
          '<span class="tl-ok">[SMB] NTLMv2-SSP Hash     : svc_backup::ACME:1a2b3c...[<span class="tl-dim">truncated</span>]...c93f</span>',
          '<span class="tl-dim">[*] Hash written to /root/.responder/Responder-Session.log</span>',
        ],
        postWait: 800,
      },
      {
        cmd: '<span class="tl-cmd">hashcat</span> <span class="tl-flag">-m</span> <span class="tl-num">5600</span> <span class="tl-flag">-a</span> <span class="tl-num">0</span> hash.txt <span class="tl-str">/usr/share/wordlists/rockyou.txt</span>',
        out: [
          '<span class="tl-dim">hashcat (v6.2.6) starting</span>',
          '<span class="tl-dim">* Device #1: NVIDIA GeForce RTX 4090, 23960/24260 MB, 128MCU</span>',
          '<span class="tl-dim">Dictionary cache built: /usr/share/wordlists/rockyou.txt</span>',
          '<span class="tl-dim">Speed.#1.........: 8943.2 MH/s (42.15ms)</span>',
          '<span class="tl-ok">SVC_BACKUP::ACME:1a2b3c:...:c93f:<span class="tl-pass">Winter2025!</span></span>',
          '<span class="tl-ok">Status: Cracked   Time: 00:00:14</span>',
        ],
        postWait: 900,
      },
      {
        cmd: '<span class="tl-cmd">netexec</span> smb <span class="tl-num">10.10.10.10</span> <span class="tl-flag">-u</span> <span class="tl-str">svc_backup</span> <span class="tl-flag">-p</span> <span class="tl-str">\'Winter2025!\'</span> <span class="tl-flag">--rid-brute</span>',
        out: [
          '<span class="tl-ok">SMB     10.10.10.10    445  DC01     [+] acme.local\\svc_backup:Winter2025!</span>',
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     500: ACME\\Administrator (SidTypeUser)</span>',
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     501: ACME\\Guest (SidTypeUser)</span>',
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     512: ACME\\Domain Admins (SidTypeGroup)</span>',
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     1103: ACME\\svc_backup (SidTypeUser)</span>',
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     1105: ACME\\svc_sql (SidTypeUser)</span>',
          '<span class="tl-dim">SMB     10.10.10.10    445  DC01     1109: ACME\\jdoe (SidTypeUser)</span>',
          '<span class="tl-hi">SMB     10.10.10.10    445  DC01     [+] 2,847 principals enumerated</span>',
        ],
        postWait: 800,
      },
      {
        cmd: '<span class="tl-cmd">impacket-GetUserSPNs</span> <span class="tl-domain">acme.local</span>/<span class="tl-user">svc_backup</span>:<span class="tl-str">\'Winter2025!\'</span> <span class="tl-flag">-request</span>',
        out: [
          '<span class="tl-dim">Impacket v0.11.0 - Copyright 2023 Fortra</span>',
          'ServicePrincipalName       Name        MemberOf',
          '-------------------------  ----------  ----------',
          'MSSQLSvc/sql01.acme.local  <span class="tl-user">svc_sql</span>     CN=Domain Admins,CN=Users,DC=acme,DC=local',
          'HTTP/intra.acme.local      <span class="tl-user">svc_web</span>     CN=Domain Users,CN=Users,DC=acme,DC=local',
          '',
          '<span class="tl-ok">$krb5tgs$23$*svc_sql$ACME$MSSQLSvc/sql01.acme.local*$...[<span class="tl-dim">redacted</span>]</span>',
        ],
        postWait: 800,
      },
      {
        cmd: '<span class="tl-cmd">hashcat</span> <span class="tl-flag">-m</span> <span class="tl-num">13100</span> tgs.hash <span class="tl-str">/usr/share/wordlists/rockyou.txt</span>',
        out: [
          '<span class="tl-dim">hashcat (v6.2.6) starting</span>',
          '<span class="tl-dim">Kerberos 5, etype 23, TGS-REP detected</span>',
          '<span class="tl-ok">$krb5tgs$23$*svc_sql*...[redacted]:<span class="tl-pass">Summer2025!</span></span>',
          '<span class="tl-ok">Status: Cracked   Time: 00:00:08   Recovered: 1/1</span>',
          '<span class="tl-hi">[*] svc_sql is a member of Domain Admins — pivoting to DC</span>',
        ],
        postWait: 900,
      },
      {
        cmd: '<span class="tl-cmd">bloodhound-python</span> <span class="tl-flag">-u</span> <span class="tl-str">svc_sql</span> <span class="tl-flag">-p</span> <span class="tl-str">\'Summer2025!\'</span> <span class="tl-flag">-d</span> <span class="tl-domain">acme.local</span> <span class="tl-flag">-c</span> <span class="tl-num">all</span>',
        out: [
          '<span class="tl-dim">INFO: Found AD domain: acme.local</span>',
          '<span class="tl-dim">INFO: Connecting to LDAP server: dc01.acme.local</span>',
          '<span class="tl-dim">INFO: Collected 2,847 users, 412 computers, 183 groups</span>',
          '<span class="tl-dim">INFO: Collected 19 domain trusts, 1,204 ACLs</span>',
          '<span class="tl-ok">[*] Domain collection finished in 9.3s · 4 JSON files written</span>',
          '<span class="tl-hi">[*] Shortest path to Domain Admin: 2 edges via svc_sql → HasSession → DC01</span>',
        ],
        postWait: 800,
      },
      {
        cmd: '<span class="tl-cmd">impacket-secretsdump</span> <span class="tl-domain">acme.local</span>/<span class="tl-user">svc_sql</span>:<span class="tl-str">\'Summer2025!\'</span>@<span class="tl-num">10.10.10.10</span> <span class="tl-flag">-just-dc</span>',
        out: [
          '<span class="tl-dim">Impacket v0.11.0 - Copyright 2023 Fortra</span>',
          '<span class="tl-dim">[*] Target system bootKey: 0x4a7f...</span>',
          '<span class="tl-dim">[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)</span>',
          '<span class="tl-dim">[*] Using the DRSUAPI method to get NTDS.DIT secrets</span>',
          '<span class="tl-ok">acme.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:<span class="tl-pass">d7e6[...redacted...]91a</span>:::</span>',
          '<span class="tl-ok">acme.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<span class="tl-pass">8c31[...redacted...]fd4</span>:::</span>',
          '<span class="tl-dim">[*] Cleaning up...</span>',
          '<span class="tl-hi">[+] 2,847 credentials dumped · krbtgt compromised · Golden Ticket possible</span>',
        ],
        postWait: 1100,
      },
    ];

    var lineDelay = 180;          // ms between output lines (default)
    var interFrameWait = 1100;    // pause after output before next prompt
    var clearBetweenLoops = true;
    var maxLinesBeforeScroll = 18;

    // Per-frame pace hints (assigned below) — scan = scanner stream, burst = fast dump,
    // crack = slow during setup then dwell on final result line.
    var paceByFrame = ['scan','scan','scan','crack','burst','scan','crack','scan','burst'];
    function delayForPace(pace, lineIdx, total) {
      if (pace === 'scan')  return 80 + Math.random() * 40;
      if (pace === 'burst') return 28 + Math.random() * 18;
      if (pace === 'crack') {
        if (lineIdx >= total - 2) return 380 + Math.random() * 120;
        return 90 + Math.random() * 40;
      }
      return lineDelay;
    }

    // Frame index → process-timeline step + human phase label for the objective strip.
    // Frames 0–1 recon = discovery; 2–7 credential/lateral = exploitation; 8 dcsync = reporting.
    function phaseFor(frameIdx) {
      if (frameIdx <= 1) return { step: 2, label: 'discovery' };
      if (frameIdx <= 7) return { step: 3, label: 'exploitation' };
      return { step: 4, label: 'reporting' };
    }

    var termClockEl = document.querySelector('[data-term-clock]');
    var termPhaseEl = document.querySelector('[data-term-phase]');
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

    // Frame → operator-notes mapping. Each entry = array of {text, cls}.
    // These surface as timestamped one-liners in the right-hand pane as the engagement progresses.
    var notesByFrame = [
      [{ text: 'recon started · LDAP+Kerberos live on DC01', cls: '' }],
      [{ text: 'SMB signing disabled on DC01', cls: 'flag' },
       { text: 'SYSVOL + NETLOGON readable (guest)', cls: '' }],
      [{ text: 'LLMNR poisoning live on eth0', cls: '' },
       { text: 'NTLMv2 captured · svc_backup', cls: 'ok' }],
      [{ text: 'cracked: Winter2025! (14s, RTX 4090)', cls: 'ok' }],
      [{ text: '2,847 principals enumerated via RID brute', cls: '' }],
      [{ text: 'kerberoast TGS · svc_sql (Domain Admins)', cls: 'flag' }],
      [{ text: 'cracked: Summer2025! · svc_sql → DA', cls: 'ok' }],
      [{ text: 'BloodHound: 2-edge path to Domain Admin', cls: 'ok' }],
      [{ text: 'krbtgt hash captured — Golden Ticket viable', cls: 'hot' },
       { text: '2,847 NTDS credentials exfiltrated (evidence)', cls: 'hot' }]
    ];

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
      var p = phaseFor(frameIdx);
      if (termPhaseEl) termPhaseEl.textContent = p.label;
      if (window.__process && window.__process.activate) {
        if (!termProcessDriven && window.__process.disableAuto) {
          window.__process.disableAuto();
          termProcessDriven = true;
        }
        window.__process.activate(p.step);
      }
    }

    // Human typing cadence — normal-ish distribution around 42ms, clamped 15–110
    function humanCharDelay() {
      var u1 = Math.random() || 0.0001;
      var u2 = Math.random();
      var z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      var ms = 42 + z * 22;
      if (ms < 15) ms = 15;
      if (ms > 110) ms = 110;
      return ms;
    }
    // Token-boundary "thinking" pause — only fires on space boundaries
    function maybeTokenPause() {
      if (Math.random() < 0.55) return 150 + Math.random() * 260;
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
      // Output pacing differs by frame intent — scanners stream, dumps burst, crackers dwell
      var pace = paceByFrame[frameIdx] || 'default';
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

    // Establishing-shot banner — orients the viewer at the start of every loop
    function writeBanner() {
      appendLine('<span class="tl-dim">─── ENGAGEMENT · ACME CORP · RED TEAM REPLAY ───</span>');
      appendLine('<span class="tl-dim">  host  </span><span class="tl-hi">kali-op1</span><span class="tl-dim">  ·  vpn  </span><span class="tl-hi">acme-ops</span><span class="tl-dim">  ·  session  </span><span class="tl-hi">tmux 0:0*</span>');
      appendLine('<span class="tl-dim">  objective  </span><span class="tl-hi">domain admin</span><span class="tl-dim">  ·  operator  </span><span class="tl-hi">kwangyun</span>');
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
        startClock();
        writeBanner();
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
