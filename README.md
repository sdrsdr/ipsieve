# ipsieve

Is this peer address inside these ranges? No dependencies, ~50 ns per check.

```ts
import { compileRanges, inRanges, LOOPBACK } from 'ipsieve';

// Once, at module load. Throws on a typo instead of silently widening.
const INTERNAL = compileRanges([
	...LOOPBACK,          // 127.0.0.0/8, ::1
	'10.0.0.0/8',
	'172.16.0.0/12',      // NOT all of 172.* -- see below
	'37.157.143.250',     // bare address = /32
]);

// Per request. Pass the socket address as node reports it.
if (inRanges(INTERNAL, req.socket.remoteAddress)) { /* allowed */ }
```

## Why not a regex

The usual hand-written allowlist gets one of these wrong:

| check | admits |
|---|---|
| `/(127\|10\|172)\./` | `110.0.0.1`, `8.8.10.9`, `35.172.129.137`: it matches anywhere in the string |
| `/^(127\|10\|172)\./` | `172.104.0.1` (Linode), `172.32.0.1` (T-Mobile US). Only `172.16.0.0/12` is private |
| `ip === '::ffff:127.0.0.1'` | not `::1`, and not the rest of `127/8` |
| `/^10\./` on a header value | `10.0.0.256`, `10.0.0.1\n` |

`ipsieve` parses the address into a 32-bit number once and tests each range with a mask, so a
range means exactly its CIDR.

## API

```ts
interface ip_ranges_t { /* opaque */ }

const LOOPBACK: readonly string[];    // ['127.0.0.0/8', '::1']
const PRIVATE_V4: readonly string[];  // ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

function compileRanges(list: readonly string[]): ip_ranges_t;
function inRanges(ranges: ip_ranges_t, ip: string | null | undefined): boolean;
function v4ToNum(s: string): number;  // strict dotted quad -> 0..2^32-1, or -1
function unmapIp(ip: string): string; // '::ffff:1.2.3.4' -> '1.2.3.4', else unchanged
```

`compileRanges` accepts `a.b.c.d/bits`, bare `a.b.c.d` (/32), `::ffff:a.b.c.d[/bits]`, and
exact IPv6 addresses (`::1`, optionally `/128`). It **throws** on:

- host bits set: `172.16.0.0/8` is almost certainly a typo for `/12`, so it fails and suggests
  `172.0.0.0/8` rather than admitting all of 172
- a prefix over 32, malformed or leading-zero prefix lengths
- anything that is not an address
- an IPv6 prefix other than /128 (not supported, and not silently matched as text)

`inRanges` **fails closed**: `undefined`, empty, malformed, leading-zero octets (`010.0.0.1` is
octal to `inet_aton`), whitespace, and anything unparseable all answer `false`.

## Scope

- IPv4 CIDR ranges, matched by mask.
- IPv4-mapped IPv6 (`::ffff:1.2.3.4`, what node reports on a dual-stack socket) is matched as
  the IPv4 address it carries.
- IPv6 by exact address only, compared lower-case in the compressed form node reports.

It checks an address. It does not decide which address to trust: behind a reverse proxy the
socket address is the proxy's, and an `X-Forwarded-For` value is whatever the client sent.

## License

LGPL-3.0, Shelly Group SE.
