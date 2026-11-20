# Manager reference prototype

`index.html` preserves the maintainer-approved HTML prototype with fake data.
Only its two Portuguese prototype controls were translated into English.
Open it locally; it makes no agent requests and saves nothing. Its simulated
approvals, clipboard, settings, restore and KeePassXC handoff are not real
implementations or security guarantees. In particular, locking alone cannot
ensure exclusive access for KeePassXC, and the restore it simulates will not
be built: a backup is restored by hand (ADR 0007, amended 2026-11-10).
Its page of remembered approvals and its "Edit in KeePassXC" will not be
built either (ADR 0007, amended 2026-11-19).

[ADR 0007](../../adr/0007-visual-manager.md) defines the implementation and
milestones, including deliberate differences from this reference. The chosen
Abrigo icon is in `data/icons/hicolor/scalable/apps/` at the repository root.
