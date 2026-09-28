# Lab captures: STARTTLS / plaintext-auth test cases

Not committed to git (`data/pcaps/*.pcap` is gitignored — these are
reproducible lab artifacts, not source). This file documents how to
regenerate them and what each one demonstrates. Lab server only,
`127.0.0.1`, dummy credentials (`labuser`/`labpass`) throughout — see
CLAUDE.md.

## S17 — `S17_smtp_587_plaintext_auth.pcap`

SMTP submission (port 587) where the client authenticates with `AUTH
LOGIN` **without** ever issuing STARTTLS, even though the server
advertises `STARTTLS` in its EHLO capability response.

Generated with the lab mail server running (`docker compose up -d` in
`lab/docker/`) via:

```
swaks --to labuser@lab.test --from labuser@lab.test \
      --server 127.0.0.1:2587 -au labuser -ap labpass
```

(no `--tls` flag) while `tcpdump -i lo0 -w ... 'tcp port 2587'` captured
in parallel.

**Verified with tshark:**
- `tls.handshake.type` never appears anywhere in the capture — no TLS
  handshake ever occurs.
- Frame 15 payload decodes (base64) to `labuser`, frame 19 to `labpass`
  — the dummy credentials appear in cleartext on the wire. This is the
  expected/intended demonstration of plaintext auth before TLS (rule
  T-01), using dummy credentials only, per CLAUDE.md.

## S01b — `S01b_smtp_587_starttls_auth.pcap`

Same SMTP submission port (587), but the client issues STARTTLS before
authenticating.

Generated identically but with `--tls` added:

```
swaks --to labuser@lab.test --from labuser@lab.test \
      --server 127.0.0.1:2587 --tls -au labuser -ap labpass
```

**Verified with tshark:**
- Plaintext phase: `EHLO` → `STARTTLS` command (frame 11) → `220`
  success (frame 13).
- TLS ClientHello/ServerHello immediately follow (frames 15/17).
- `strings` over the whole pcap finds no occurrence of `labuser`,
  `labpass`, or their base64 forms — AUTH happened entirely inside TLS,
  so the credentials never appear in the clear.
