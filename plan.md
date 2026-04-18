# Terminal Redesign — Design Plan

> Goal: make the hero live terminal feel **native to the site**, **credible to operators**, and **classy to buyers** — without losing the real AD kill-chain content that makes it distinctive.

## Context

The site is a boutique offensive-consulting brand ("Keum Offensive") built on a white Ellis-style editorial theme with a disciplined teal accent (`--blue: #0d9488`). The hero terminal currently plays a full Active Directory kill-chain on loop (`nmap → responder → hashcat → kerberoast → BloodHound → secretsdump`) inside a dark `#0a0e14` macOS-chrome window.

The content is excellent and stays. Everything surrounding it changes.

## Problems

1. **Pasted-on feel.** Dark rectangle floats on pure white; no environmental blending.
2. **Color soup.** Terminal ships pink / lavender / cyan / yellow — none exist elsewhere on the site.
3. **Robotic typing.** Flat 38ms/char intervals; no pauses, no pastes, no thinking.
4. **Generic macOS chrome.** Red/yellow/green traffic dots on a Kali window is a tiny visual lie.
5. **Two "live" fictions that don't talk.** Process section shows "Active Phase / Progress / Live" and the terminal plays a kill-chain — they never sync.
6. **No honesty frame.** Nothing marks the terminal as a replay. Offensive firms never imply live access to client networks.
7. **Hard loop reset.** `innerHTML = ''` flashes the viewer out of the moment.

## Design targets

- **Blend** — read the terminal as the same document as the rest of the page.
- **Color discipline** — brand teal for informational tokens; red/yellow/green reserved for operational semantics (ok/warn/err/creds).
- **Operator authenticity** — human typing cadence, tmux-style surface elements.
- **Narrative sync** — the terminal's phase should drive the Process timeline's active state.
- **Honesty** — a quiet `REPLAY · RECORDED` label stops the "is this real?" moment before it lands.

---

## Tier 1 — Blend (highest ROI)

Fixes the pasted-on feel and color soup. No content changes.

- [ ] **Teal radial glow bed** behind the terminal container — soft wash matching `--blue-glow`, placed on the hero so the dark rectangle sits *on* light instead of *against* it.
- [ ] **Brand-teal token palette** — drift informational tokens (`.tl-prompt-host`, `.tl-hi`, `.tl-user`, `.tl-domain`, `.tl-banner`) toward the site's teal / slate family. Keep `.tl-ok` / `.tl-warn` / `.tl-err` / `.tl-pass` untouched — those carry operational meaning.
- [ ] **Top fade mask** — replace hidden scrollbar with `mask-image: linear-gradient(180deg, transparent 0, black 40px, black 100%)`. Old lines fade off the top instead of hard-cutting.
- [ ] **Operational chrome** — replace macOS traffic dots with two subtle badges: `● REC` (red pulse) + `⎇ VPN UP` (teal). Center title stays. Session tag right-aligned.
- [ ] **Human typing cadence** — normal distribution around 42ms, stdev 25ms, clamp 15–110ms. Token-boundary pauses 150–400ms between flags/args. One "paste" per loop reveals instantly.
- [ ] **Fade loop reset** — 300ms fade on the body before clearing and re-showing, instead of a hard flash.

**Estimated effort:** ~2 hours.

---

## Tier 2 — Craft (signature polish)

Adds the narrative structure and honesty frame that separate this from every other pentest-firm site.

- [ ] **Objective strip** below the chrome: `TARGET acme.local  ·  OBJECTIVE domain admin  ·  T+00:14:22  ·  PHASE exploitation`. The `T+` clock and `PHASE` value update as frames advance.
- [ ] **REPLAY label** — quiet corner label in the chrome: `REPLAY · RECORDED 2026-04-12`. Honest, classy, protects the brand.
- [ ] **Establishing-shot banner** on each loop: a dim three-line intro (`─── ACME RED TEAM · REPLAY ───` + host/vpn/session) before the first prompt.
- [ ] **Process timeline sync** — terminal frame index drives the Process section's `.c-timeline__step.is-active` class and `data-pm="phase"` readout. Frames 1–2 → Discovery, 3–6 → Exploitation, 7–9 → Reporting setup.
- [ ] **Differential output pacing** — scanner output (nmap, hashcat) streams at 60–90ms/line, dumps (secretsdump) burst at 25ms, banners dwell 300–450ms for suspense.

**Estimated effort:** ~3 hours.

---

## Tier 3 — Signature (showcase craft)

Elective. Only if the terminal is a deliberate centerpiece worth the extra surface area.

- [ ] **Split pane** — 60% main terminal, 40% right-hand "operator notes" panel. Timestamped one-liners update as frames fire (`09:14 recon started`, `09:23 svc_backup creds captured`, ...).
- [ ] **tmux-style status line** — 22px bar pinned to the bottom of the terminal body: `[kali ▸ acme] 2:ssh*  1:tunnel-  ·  load 0.42  ·  T+14:23  ·  sync ↑8MB ↓241KB`. Values drift slightly over time.
- [ ] **Pause/play toggle** — small glyph in the chrome corner. Accessibility win + confidence signal.

**Estimated effort:** ~4 hours.

---

## Files expected to change

- `_layouts/home.html` — hero terminal markup (chrome, objective strip, optional split pane)
- `_includes/head/custom.html` — CSS for all of the above (glow bed, palette drift, fade mask, chrome badges, objective strip, status line, responsive)
- `assets/js/main.consulting.js` — `initLiveTerminal()` — human cadence, differential pacing, Process sync, pause/play, REPLAY banner, loop fade

No change to the kill-chain content (`frames` array). No change to site palette. No new dependencies.

## Out of scope

- Audio / typing sounds (too risky on default-on sites; can revisit if someone specifically asks)
- Rotated "pinned snapshot" framing (dates the site to 2019)
- Rewriting kill-chain frames — content is already strong

## Rollout

Ship tiers as independent commits so each can stand on its own. Review after Tier 1 before committing to Tier 2+.
