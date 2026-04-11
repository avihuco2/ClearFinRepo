---
inclusion: manual
---

# Frontend Design Steering

This steering guides creation of distinctive, production-grade frontend interfaces that avoid generic "AI slop" aesthetics. Implement real working code with exceptional attention to aesthetic details and creative choices.

## Design Thinking

Before coding, understand the context and commit to a BOLD aesthetic direction:
- **Purpose**: What problem does this interface solve? Who uses it?
- **Tone**: Pick a clear direction: brutally minimal, luxury/refined, editorial/magazine, art deco/geometric, soft/pastel, industrial/utilitarian, etc. Commit fully.
- **Constraints**: Technical requirements (framework, performance, accessibility).
- **Differentiation**: What makes this UNFORGETTABLE? What's the one thing someone will remember?

Choose a clear conceptual direction and execute it with precision. Bold maximalism and refined minimalism both work — the key is intentionality, not intensity.

Then implement working code that is:
- Production-grade and functional
- Visually striking and memorable
- Cohesive with a clear aesthetic point-of-view
- Meticulously refined in every detail

## Frontend Aesthetics Guidelines

Focus on:
- **Typography**: Choose fonts that are beautiful, unique, and interesting. Avoid generic fonts like Arial, Inter, Roboto, system fonts. Opt for distinctive choices that elevate the frontend's aesthetics. Pair a distinctive display font with a refined body font. Use Google Fonts or similar CDN.
- **Color & Theme**: Commit to a cohesive aesthetic. Use CSS variables for consistency. Dominant colors with sharp accents outperform timid, evenly-distributed palettes.
- **Motion**: Use animations for effects and micro-interactions. Focus on high-impact moments: one well-orchestrated page load with staggered reveals creates more delight than scattered micro-interactions. Use scroll-triggering and hover states that surprise.
- **Spatial Composition**: Unexpected layouts. Asymmetry. Overlap. Diagonal flow. Grid-breaking elements. Generous negative space OR controlled density.
- **Backgrounds & Visual Details**: Create atmosphere and depth rather than defaulting to solid colors. Add contextual effects and textures that match the overall aesthetic. Apply creative forms like gradient meshes, noise textures, geometric patterns, layered transparencies, dramatic shadows, decorative borders, and grain overlays.

## Anti-Patterns (NEVER do these)

- Generic system font stacks (`-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`)
- Overused font families (Inter, Roboto, Arial, Space Grotesk)
- Cliched color schemes (purple gradients on white, generic blue `#1a73e8` buttons)
- Predictable centered-card-on-gray-background layouts
- Cookie-cutter design that lacks context-specific character
- Plain white cards with subtle box-shadows on `#f5f5f5` backgrounds

## ClearFin Brand Context

ClearFin is a multi-tenant fintech platform. The design should convey:
- **Trust and security** — this handles financial data and credentials
- **Sophistication** — fintech, not a toy app
- **Clarity** — clean information hierarchy, no clutter
- **Premium feel** — this is enterprise-grade software

Consider a dark, refined aesthetic with gold/amber accents, or a clean editorial style with strong typography. The login page is the first impression — make it count.
