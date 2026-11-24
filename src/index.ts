/**
 * ipsieve -- is this peer address inside these ranges? No dependencies.
 *
 * Replaces the hand-written regexes and `startsWith()` tests that IP allowlists tend to grow, and
 * the mistakes they tend to carry:
 *
 *   /(127|10|172)\./     unanchored: admits 110.0.0.1, 8.8.10.9, 35.172.129.137
 *   /^(127|10|172)\./    anchored, but `172.` is not private: 172.104/15 is Linode,
 *                        172.32/11 is T-Mobile US -- only 172.16.0.0/12 is RFC 1918
 *   ip === '::ffff:127.0.0.1'   misses ::1 and the rest of 127/8
 *
 * The address is parsed into a number once and tested against each range with a mask, so a
 * range means exactly its CIDR and nothing that merely looks similar as text.
 *
 * Scope, deliberately small:
 *   - IPv4 ranges in CIDR form, matched by mask.
 *   - IPv4-mapped IPv6 (`::ffff:1.2.3.4`, what node reports on a dual-stack socket) is matched
 *     as the IPv4 address it carries.
 *   - IPv6 by EXACT address only (`::1`), compared in the lower-case compressed form node
 *     reports. An IPv6 prefix other than /128 is refused at compile time rather than silently
 *     matched as text.
 *
 * Everything that does not parse fails CLOSED: `inRanges()` returns false, `compileRanges()`
 * throws.
 */

/** A compiled range list. Build with `compileRanges()`; treat as opaque. */
export interface ip_ranges_t {
	/** [network, mask] pairs, both unsigned 32-bit. */
	readonly v4:ReadonlyArray<readonly [number,number]>;
	/** Exact IPv6 addresses, lower-case. */
	readonly v6:ReadonlySet<string>;
}

/** All of loopback: 127.0.0.0/8 and ::1. */
export const LOOPBACK:readonly string[]=Object.freeze(['127.0.0.0/8','::1']);

/** RFC 1918 private IPv4. Note 172.16.0.0/12 is 172.16 - 172.31, NOT all of 172. */
export const PRIVATE_V4:readonly string[]=Object.freeze(['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']);

/**
 * Strict dotted-quad IPv4 to an unsigned 32-bit number, or -1.
 *
 * Strict on purpose: exactly four decimal octets, 0-255, no leading zeros (`010` is octal to
 * inet_aton and decimal to everyone else -- ambiguous, so refused), no whitespace, no sign.
 */
export function v4ToNum(s:string):number {
	let n=0, octet=0, digits=0, dots=0;
	for (let i=0; i<s.length; i++) {
		const c=s.charCodeAt(i);
		if (c===46) { // '.'
			if (digits===0 || ++dots>3) return -1;
			n=n*256+octet; octet=0; digits=0;
		} else if (c>=48 && c<=57) { // '0'..'9'
			if (digits>0 && octet===0) return -1; // leading zero
			octet=octet*10+(c-48);
			if (++digits>3 || octet>255) return -1;
		} else return -1;
	}
	if (dots!==3 || digits===0) return -1;
	return n*256+octet;
}

/** `::ffff:1.2.3.4` -> `1.2.3.4`; anything else unchanged. Case-insensitive on the prefix. */
export function unmapIp(ip:string):string {
	if (ip.length>7 && ip.charCodeAt(0)===58 && ip.charCodeAt(1)===58 && ip.slice(2,7).toLowerCase()==='ffff:') {
		return ip.slice(7);
	}
	return ip;
}

function maskOf(bits:number):number {
	return bits===0 ? 0 : (0xffffffff<<(32-bits))>>>0;
}

/**
 * Compile a list of ranges once, at module load, and reuse it.
 *
 * Accepts `a.b.c.d/bits`, bare `a.b.c.d` (= /32), `::ffff:a.b.c.d[/bits]` (bits counted on the
 * IPv4 part), and exact IPv6 `x::y` or `x::y/128`.
 *
 * THROWS on anything else, including a network with host bits set: `172.16.0.0/8` is almost
 * certainly a typo for /12, and accepting it as written would silently admit all of 172/8.
 */
export function compileRanges(list:readonly string[]):ip_ranges_t {
	const v4:Array<readonly [number,number]>=[];
	const v6=new Set<string>();

	for (const entry of list) {
		if (typeof entry!=='string') throw new Error(`ipsieve: range is not a string: ${String(entry)}`);
		const slash=entry.indexOf('/');
		const addr=slash<0 ? entry : entry.slice(0,slash);
		const bitsTxt=slash<0 ? undefined : entry.slice(slash+1);

		if (bitsTxt!==undefined && !/^(0|[1-9][0-9]{0,2})$/.test(bitsTxt)) {
			throw new Error(`ipsieve: bad prefix length in [${entry}]`);
		}

		const n=v4ToNum(unmapIp(addr));
		if (n>=0) {
			const bits=bitsTxt===undefined ? 32 : Number(bitsTxt);
			if (bits>32) throw new Error(`ipsieve: IPv4 prefix longer than 32 in [${entry}]`);
			const mask=maskOf(bits);
			if (((n&mask)>>>0)!==n) {
				throw new Error(`ipsieve: host bits set in [${entry}] -- did you mean ${numToV4((n&mask)>>>0)}/${bits}?`);
			}
			v4.push([n,mask]);
			continue;
		}

		if (addr.includes(':') && /^[0-9a-fA-F:]+$/.test(addr) && addr.length<=39) {
			if (bitsTxt!==undefined && bitsTxt!=='128') {
				throw new Error(`ipsieve: IPv6 ranges are not supported, only exact addresses: [${entry}]`);
			}
			v6.add(addr.toLowerCase());
			continue;
		}

		throw new Error(`ipsieve: not an IP address or range: [${entry}]`);
	}

	return { v4, v6 };
}

/**
 * Is `ip` inside any of `ranges`? Pass `req.socket.remoteAddress` as is.
 *
 * `undefined`, empty and unparseable all answer false.
 */
export function inRanges(ranges:ip_ranges_t, ip:string|null|undefined):boolean {
	if (typeof ip!=='string' || ip.length===0) return false;
	const s=unmapIp(ip);
	const n=v4ToNum(s);
	if (n>=0) {
		for (const [net,mask] of ranges.v4) {
			if (((n&mask)>>>0)===net) return true;
		}
		return false;
	}
	return ranges.v6.size>0 && ranges.v6.has(s.toLowerCase());
}

function numToV4(n:number):string {
	return `${n>>>24}.${(n>>>16)&255}.${(n>>>8)&255}.${n&255}`;
}
