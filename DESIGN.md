---
name: Evidence Passbook
colors:
  cover: "#14264a"
  cover-deep: "#0e1c38"
  on-cover: "#e6efe8"
  on-cover-2: "#b4c4d8"
  foil: "#cfae5a"
  paper: "#e6efe8"
  paper-2: "#d9e6dd"
  paper-field: "#fbfdfb"
  fold: "#c6d8cc"
  guilloche: "#bcd2c4"
  rule: "#a9c1b3"
  ink: "#10213d"
  ink-2: "#3d4f66"
  ink-3: "#5b6c80"
  scam: "#b42318"
  genuine: "#1d6a44"
  unsure: "#8a5d00"
  neutral: "#4d5d70"
typography:
  face: "Anek Latin (Ek Type, OFL), self-hosted variable: wght 100-800, wdth 75-125"
  display: "700, wdth 78%, clamp(2.6rem, 1.2rem + 4.4vw, 5.25rem), leading 0.94, tracking -0.03em"
  h2: "700, wdth 78%, clamp(1.9rem, 1.2rem + 2.2vw, 3.25rem), leading 1"
  h3: "700, wdth 78%, clamp(1.5rem, 1.1rem + 1vw, 2rem)"
  lead: "clamp(1.125rem, 1rem + 0.4vw, 1.3rem)"
  body: "1.0625rem / 1.5, tabular numerals everywhere"
  small: "0.9rem"
rounded:
  default: 0
  genuine-stamp: 999px
spacing:
  gutter: "clamp(16px, 2.2vw, 32px)"
  section: "clamp(80px, 12vw, 180px) vertical on cover sections"
---

# Evidence Passbook

The interface is an Indian bank passbook. A navy cloth cover frames pale sea-green security paper;
each live check prints as a ledger entry; the verdict is a rubber stamp struck on the page.

## Colour

- **Cover** (navy) is the page ground, the top bar and the cover sections (How it checks, Help).
  **Foil** gold appears only on the cover: wordmark, station names, the 1930 helpline, focus ring.
- **Paper** carries everything the user reads and works with: the spread and the sources statement.
  A live **guilloche** (`static/guilloche.js`, a Canvas 2D port of ReactBits Waves) is the paper's
  security print; it is low contrast, never sits over text at full strength, pauses off screen and
  is static under reduced motion.
- **Ink** is blue-black, never grey; `ink-2` for secondary text (7:1 on paper).
- **Stamps / signals** each pair a colour with a word *and* a frame, never colour alone:
  scam = vermilion, solid double frame; can't say = turmeric, dashed frame; genuine = bank green,
  oval frame. Findings use the same language: Malicious (solid), Suspicious (dashed), Clean (oval),
  No signal / Unavailable (word only).
- Dark mode: the cover deepens to near-black navy and the paper becomes deep sea-green night paper,
  so the two materials stay distinct.

## Type

One family, Anek Latin, from an Indian foundry (Devanagari sibling available for a Hindi UI).
Condensed width (78%) for display, headings, stamps; normal width for reading. Five working sizes:
display, h2, h3, lead, body, plus small. No monospace except raw JSON evidence.

## Components

- **Spread**: two pages, a flat fold band between them. Before a case: 1fr / 1.08fr. With a case
  open the result page takes the width (0.62fr / 1.38fr) — the answer comes first.
- **Stamps row**: all three verdicts are always printed faintly; on verdict the real one is struck
  (scale-in thunk, -3.5deg, SVG ink-speckle filter `#stamp-ink`), the rest fade further.
- **Verdict panel**: paper-field ground, 6px top band in the verdict colour, title, "N% sure" with a
  CountUp, a 20-cell meter, then What to do and Why (citation buttons jump to and flash ledger rows).
- **Stations**: Reading the message → Checking reputation → Visiting the link → Weighing the evidence;
  square markers: outline (pending), blinking (active), filled (done).
- **Ledger**: a real table (Time, Source + entry id, Particulars, Signal) with raw evidence in a
  disclosure. New rows print left-to-right (`clip-path` steps). Blank ruled rows before a case.
  On phones rows become stacked blocks.
- **Buttons**: square, flat navy fill, arrow nudges on hover. Text actions are underlined links.

## Motion

One authored moment per state: rows print, the stamp strikes, confidence counts up. Below-the-fold
sections settle in once (24px rise, staggered). Everything is visible without script and under
`prefers-reduced-motion`.

## Rules

No gradients, glass, glows, eyebrows, icon-card rows, or invented results. Example *inputs* only.
