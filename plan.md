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

---

# Phase 2 — Workstation Composition

> Goal: re-frame the terminal as part of a **three-monitor operator workstation**, so the live kill-chain reads as "a hacker is running this right now on their desk" — without resorting to stock hoodie-hacker imagery.

## Reference tone

Apple Pro Display XDR product shots · Linear's perspective-tilted UI cards · Mr. Robot's workstation crops · Panic's Playdate hero — floating device compositions on soft gradient washes. **Not** TV-show hacker silhouettes, **not** Matrix green, **not** 3D renders.

## Composition

Three monitors in a front-center product shot:

- **Left monitor** (tilted +22° Y-axis, ~0.6 opacity): operator-notes panel, moved out of the terminal's split pane into a standalone side monitor. Timestamped one-liners still driven by the terminal.
- **Center monitor** (flat, dominant, z-index: 3): the full live kill-chain terminal. Enlarged to ~460px body height now that the split pane is gone — reads bigger, breathes better.
- **Right monitor** (tilted -22° Y-axis, ~0.6 opacity): BloodHound-style AD attack-path SVG — DC at center, ~8 nodes around it, one pulsing red highlight path to Domain Admin. Small "nodes / edges / DAs" metric legend.

All three sit over the existing teal light-bed (extended wider). Dark bezels, thin teal edge accent ring, soft drop shadows. No keyboard, no silhouette, no desk — the composition implies the workstation.

## Markup changes

- Wrap `.c-hero__term` in a new `.c-workstation` scene container.
- Split-pane `<aside class="c-term-notes">` moves OUT of the terminal body and INTO a new `.c-workstation__side--left` monitor shell. Same `data-term-notes` attr, so JS keeps working unchanged.
- Add `.c-workstation__side--right` with inline SVG BloodHound graph.
- Remove the `.c-term-window__split` wrapper — terminal body becomes a direct child of `.c-term-window` again.

## CSS spec

- `.c-workstation` — `perspective: 1800px`, `perspective-origin: 50% 55%`, no `overflow: hidden` on any ancestor in the composition.
- Side monitors use `transform: rotateY(±22deg) translateX(...)`, `transform-style: preserve-3d`, `backface-visibility: hidden`, `translateZ(0)` + antialiased font smoothing.
- Center monitor: `z-index: 3`, `max-width: 780px`, flat. Terminal body grows from 320 → 460px tall.
- Sides: `opacity: 0.6`, absolutely positioned on desktop, `display: none` below 1180px.
- Reduced-motion: disable pulse animations on side monitors and AD-map path.

## What NOT to do

- No hacker silhouette / figure
- No keyboard illustration
- No stock imagery / PNGs
- No >3 monitors (density collapses legibility)
- No retro green palette — keep brand teal/slate
- No parallax/scroll-linked animation on side monitors (jank risk)

## Out of scope for Phase 2

- Real product-shot reflections (too heavy)
- A literal desk surface (light-bed handles environment)
- Motion-synced tilt on scroll

---

# Phase 3 — Operator at the Screen

> Revised direction: **one monitor, one human.** The three-monitor shot was too "product showcase" and missed the visceral "hacker operating" feeling the user asked for. Phase 3 replaces it with a single large monitor + a silhouetted operator in the foreground.

## Reference tone

Mr. Robot opening shots of Elliot at keyboard · Cyberpunk cinematics (operator silhouettes at screens) · Corridor Digital over-the-shoulder hacking shots · Defcon poster illustration style. Single focused figure, single focused screen. Camera POV: slightly above and behind the operator, looking at the screen over their shoulder.

## Composition

- **Center**: the live terminal at full size (460px body), split pane restored so operator notes sit alongside command output
- **Foreground (bottom)**: a hand-drawn SVG silhouette of an operator — back of head + shoulders only, no face, no hoodie, no accessories
- **Lighting**: screen-glow teal gradient fill on the silhouette (top is rim-lit teal, bottom fades to pure dark), plus CSS `drop-shadow` above the silhouette for soft ambient halo
- **No side monitors** — they fight the focused-operator story
- **No literal desk / keyboard** — the silhouette implies the workstation

## SVG silhouette spec

ViewBox `0 0 600 200`. Single path:
- Shoulders span full width, peaks ~y:120 at x:70 and x:530
- Neck saddle dips into head base at x:240 and x:360
- Head dome from y:100 (base) to y:6 (apex), width ~120px
- All curves cubic/quadratic bezier for smoothness
- No hair, no ear, no detail — anonymous operator

Fill: `<linearGradient>` id `hacker-rim` — teal @ 0% → mid-teal @ 12% → dark @ 35% → pure dark @ 100%. Replicates the effect of screen light hitting the top of the head and dying out as it travels down the silhouette.

## Markup changes

- Remove `.c-workstation__side--left` and `.c-workstation__side--right` entirely
- Restore `.c-term-window__split` wrapper inside the terminal with the notes `<aside>` back inside it
- Add `<svg class="c-hacker">` as a sibling of `.c-workstation__center`, rendered after the monitor

## CSS spec

- `.c-workstation` → `flex-direction: column`, center-aligned
- `.c-hacker` → `width: min(100%, 680px)`, `margin-top: -40px` (overlaps monitor shadow, sells foreground depth), `filter: drop-shadow(0 -8px 24px rgba(45,212,191,0.35))`
- Prior side-monitor styles removed (dead selectors)
- Mobile: silhouette scales naturally with SVG viewBox

## What NOT to do

- No hoodie / face / detail on the silhouette — anonymity is the design
- No keyboard / desk render — implied
- No animation on the silhouette itself — it's a static foreground element
- No second figure / scene characters
- No background wall / room — just the light-bed behind the monitor


