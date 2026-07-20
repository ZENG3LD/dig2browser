# dig2browser-probe

`dig2browser-probe` validates a small JSON observation returned by a controlled
origin and binds it to a compiled browser persona and the runtime record that
actually served the page. A successful `ProbeTranscriptV1` is an allowlisted,
deterministically hashed statement about that observation.

The input has exactly two objects, `browser` and `server`. Browser dimensions
and `dprMilli` are integers; `dprMilli` is device pixel ratio multiplied by
1000. The server preserves the raw `Sec-CH-UA-Mobile` value (`?0` or `?1`) and
the quoted raw `Sec-CH-UA-Platform` value (for example, `"Windows"`).

The decoder accepts at most 64 KiB and rejects unknown JSON properties. The
schema intentionally has no URL, query, cookies, authorization data, raw header
map, browser storage, or page content. The server section contains only the four
headers needed for consistency checks.

`canonical_bytes` writes every fixed field tag and every value with an unsigned
32-bit little-endian length prefix, then writes integer values in little-endian
form and booleans as `0` or `1`. `sha256` hashes those bytes, not JSON text, so
JSON whitespace and property ordering do not affect the transcript digest.

User-Agent validation is preset- and runtime-specific. Windows Chromium requires
bounded `Chrome/<version>` plus Windows, Win64, and x64 tokens; the Chrome branch
rejects Edge products, while the Edge branch also requires `Edg/<version>`.
The Pixel 7 mobile-web preset requires Linux, Android 13.0.0, Pixel 7,
`Chrome/<version>`, and Mobile tokens and rejects Edge Android products.

This contract proves only that the listed browser-visible and server-visible
values were coherent on a controlled page with a viewport meta tag. It does not
prove GPU identity, TLS fingerprint, public IP or routing egress, Android or
device nativeness, carrier state, hardware attestation, or equivalence to a
physical device. Mobile presets describe Chromium mobile-web emulation unless a
separate runtime contract explicitly establishes something stronger.
