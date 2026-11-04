# Launch kit

Copy ready to adapt, not to paste twice. One honest post per community beats
the same text everywhere; privacy and Rust communities both have a low
tolerance for marketing voice and a high tolerance for technical detail.

## Positioning

- One line: **Network anonymity for Linux that undoes itself.**
- Supporting line: every layer (MAC, hostname, `sysctl`, IPv6, DNS, Tor/VPN,
  kill switch, sandbox) is one state, applied in order, rolled back on failure,
  and checked for drift.
- Differentiator that must stay in every post: **it never touches logs, audit
  trails, timestamps or histories.** That is the line between this project and
  "anti-forensics" tools, and saying it up front prevents the worst comments.

Audience → angle:

| Channel | Angle |
| --- | --- |
| Hacker News (Show HN) | "The rollback is the feature" — half-applied shell scripts are the real problem |
| r/rust | Design: typed module state, `flock` + atomic state, no `unwrap` in prod, namespace tests, `bwrap` integration |
| r/privacy | Threat model table: what it mitigates, what it explicitly does not |
| r/linux, r/archlinux | Distro compatibility, packaging, NetworkManager behavior |
| awesome-privacy / Privacy Guides | Catalog entry under network hardening |
| Mastodon infosec | Short post + the screenshot, no thread |

## Show HN

**Title:** Show HN: Anonify – reversible network anonymity for Linux (Rust)

> Most "anonymity scripts" are shell one-liners that spray `ip`, `nft` and
> `sysctl` calls. When one step fails, you are left with a half-applied firewall
> and no idea what changed.
>
> Anonify treats the whole set as one state: MAC, hostname, kernel network
> hardening, IPv6 off, DNS pinned, Tor or WireGuard with a fail-closed kill
> switch, all applied in order. If a layer fails, the ones already applied are
> rolled back. `anonify restore` returns the machine to its exact previous
> configuration, and `anonify watch` warns when a daemon quietly reverts
> something.
>
> It is Rust, GPLv3, root only where needed, and deliberately narrow: no log
> deletion, no timestamp edits, no history wiping, no hiding processes. Those
> are refused in review, not just undocumented. It does not claim to defeat a
> global adversary — Tails and Whonix exist for that.
>
> Feedback I am after: NetworkManager and VPN combinations that break it, and
> the per-app bubblewrap sandbox (`launch --isolate`), which is the piece I
> trust least.

Post Tue–Thu morning US Eastern; answer every technical comment the same day.
If it does not get traction, do not repost — write the follow-up post about
the rollback design instead.

## r/rust

**Title:** Anonify: reversible network hardening in Rust — critique my rollback design

> Side project I have been hardening for a while: a CLI that applies network
> anonymity changes (MAC, hostname, `sysctl`, IPv6, DNS, Tor/VPN, kill switch)
> and must be able to undo all of them, in order, after any failure.
>
> Things I would like reviewed: the state machine in `src/state.rs` (atomic
> write + `flock`, original values preserved when a restore fails), the
> fail-closed ordering in `src/modules/tor.rs` (firewall before bootstrap), and
> `src/modules/bwrap.rs` (argv building and path validation for the sandbox).
>
> No `unwrap`/`expect` in production paths, `clippy::pedantic` in CI, and the
> low-level tests run inside user/mount/network namespaces so nothing touches
> the host. Happy to hear where the error handling is still sloppy.

## r/privacy

**Title:** Anonify: ephemeral network hardening for Linux, with an explicit "what it does not do"

> Short version: `sudo anonify enable --all` randomizes MAC and hostname,
> disables IPv6, pins DNS, and routes through Tor or WireGuard behind a
> fail-closed kill switch. `anonify restore` undoes it. State is in `/run`,
> nothing is written to disk.
>
> What it does not do, stated plainly: no protection against a compromised
> endpoint, no defense against global traffic correlation, no identity
> protection for logged-in accounts, and it never deletes logs, histories,
> timestamps or evidence. It is not an anti-forensics tool and will not become
> one.
>
> If your threat model is "the café Wi-Fi and my ISP", this is aimed at you. If
> it is a state-level adversary, use Tails or Whonix instead — this README says
> so too.

Expect the "just use Tor Browser" comment; agree with it, and point at the
comparison table.

## Catalog entries

For awesome-privacy style lists:

> **[anonify](https://github.com/grubberdubber/anonify)** — Reversible,
> memory-only network hardening for Linux: MAC/hostname randomization, IPv6 and
> DNS leak prevention, Tor/WireGuard with a fail-closed kill switch, and a
> per-app bubblewrap sandbox. GPLv3.

Submit a single PR adding one line in the right section; do not open issues
asking to be added.

## Short posts

> New release of anonify: one command to randomize MAC/hostname, kill IPv6 and
> DNS leaks, and route through Tor or WireGuard behind a fail-closed kill
> switch — with verified rollback and drift detection. No logs touched, ever.
> GPLv3, Rust. Feedback welcome.

> The feature nobody demos: undo. anonify applies a stack of network anonymity
> changes and can reverse every one of them, in order, after a failure. Rust,
> GPLv3, Linux.

Attach `docs/screenshot.png`; do not attach the banner alone (no information).

## Launch checklist

- [ ] GitHub social preview uploaded (`.github/assets/social-preview.jpg`,
      1280×640 — Settings → General → Social preview).
- [ ] Repository description and topics set; they drive GitHub search.
- [ ] Sponsor button live (enroll at github.com/sponsors, then `FUNDING.yml`).
- [ ] A pinned issue or Discussion titled "Compatibility reports" with a short
      template: distro, NetworkManager version, VPN/Tor setup, what broke.
- [ ] Release tagged with the commit CI verified, so the badge and the code match.
- [ ] Someone available to answer comments for the first 6 hours.

Rules: no vote manipulation, no alt accounts, no "please star" DMs, no claims
the README does not support. One good technical post in the right community
outperforms ten generic ones, and a project that overclaims gets destroyed in
the comments — which is also why the limits section stays in the README.

## After launch

- Answer issues with a fix or a documented limitation; link the commit.
- Keep a `CHANGELOG.md` entry per release: people fund projects that look alive.
- Post a short monthly devlog (roadmap item done, bug fixed, what is next) in
  the same communities only if there is something real to report.
- Track stars → sponsors in the README's Support section and adjust the pitch
  to what people actually cite as the reason they sponsored.
