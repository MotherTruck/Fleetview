# Vendored: xterm.js

Files here are vendored from the `@xterm/xterm` (5.5.0) and `@xterm/addon-fit`
(0.10.0) npm packages, unmodified apart from stripping `sourceMappingURL`
comments (the `.map` files aren't vendored). MIT licensed; see `LICENSE`.

Vendored rather than loaded from a CDN so this dashboard's static assets
stay fully self-contained, consistent with the rest of `server/app/static/`.

To update: download the new package versions and replace `xterm.js`,
`xterm-addon-fit.js` (from each package's `lib/` directory) and `xterm.css`
(from `@xterm/xterm`'s `css/` directory).
