# Android moonlit-island UI · 0.1.1-test

Created 2026-11-06 with the built-in imagegen tool. The finished raster asset is `port/platform/android/app/assets/ui/moonlit-island.png`. It decorates the title/settings and side rails only. It is never substituted for an original game scene or used to infer progression. Buttons, outline icons and all translated text are drawn by Android Canvas, so they remain interactive and localizable.

The original scene keeps its full 4:3 frame, centered at full safe height where the available side rails fit. Dialogue has no opaque box. Touch targets have thin slate borders and muted brass selection marks. There is no directional pad, controller button legend or physical game-key mapping. Gesture adapters only enqueue original actions. The only optional picture filter is scanlines, with normal smooth display scaling.

## Generation prompt

Use case: stylized-concept. Asset type: production background art for a landscape Android interactive mystery novel UI. Create one high-resolution very wide landscape artwork (about 20:9) of a midnight Japanese island, a faint old isolated lodge silhouette low on the RIGHT shoreline, a fine waxing crescent moon in the upper RIGHT, cold sea fog and delicate silver reflections on still water along the lower third. Suspenseful and restrained, sophisticated Japanese mystery title design, softly painted cinematic realism mixed with very fine indigo paper grain. Midnight navy, deep petrol blue, muted silver and very subtle antique brass. Composition: the upper and middle LEFT half and central region must be very dark open negative space suitable for live software typography and touch menu buttons. Fine low-contrast mist along both outer vertical edges that remains attractive when the centre is covered by a 4:3 game viewport. Gentle vignette; no bright flare; no harsh gradients. This will be actually used as menu and side-rail art, not as an in-game scene. NO typography, NO letters, NO logos, NO buttons, NO controls, NO frame, NO people, NO blood, NO watermark. Edge-to-edge finished artwork, no device mockup.

## Provenance and limits

- New UI illustration generated for this project, not extracted from the retail disc.
- Original output: `exec-e1234554-c2e7-4529-804c-dbb175f11004.png`; copied unchanged into the app assets.
- Real integration captures and build-bound receipts: `analysis/android/24-touch-title*`, `25-touch-story*`, and subsequent touch validation evidence.
- Primary trial device remains iQOO Z9 Turbo. Emulator screenshots verify the implemented layout, not physical-device audio, thermal behavior or GPU compatibility.
