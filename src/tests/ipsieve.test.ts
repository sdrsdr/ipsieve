import { test } from 'node:test';
import * as assert from 'node:assert/strict';

import { compileRanges, inRanges, v4ToNum, unmapIp, LOOPBACK, PRIVATE_V4 } from '../index';

/** A realistic allowlist: loopback, GCP VPC, RFC1918 172 block, one office address. */
const INTERNAL=compileRanges([...LOOPBACK,'10.0.0.0/8','172.16.0.0/12','37.157.143.250']);

test('admits what the list says', () => {
	for (const ip of [
		'127.0.0.1','127.255.1.2','::1','::ffff:127.0.0.1',
		'10.0.0.0','10.132.0.5','10.255.255.255','::ffff:10.1.2.3',
		'172.16.0.0','172.17.0.2','172.31.100.142','172.31.255.255',
		'37.157.143.250','::ffff:37.157.143.250','::FFFF:37.157.143.250',
	]) assert.equal(inRanges(INTERNAL,ip),true,ip);
});

test('172: only 172.16.0.0/12, never the public blocks around it', () => {
	for (const ip of [
		'172.15.255.255', // one below the private block
		'172.32.0.0',     // one above -- and T-Mobile US (172.32/11)
		'172.0.0.1','172.64.0.1' /*Cloudflare*/,'172.104.0.1' /*Linode*/,
		'172.217.0.1' /*Google front-end*/,'172.232.0.1' /*Akamai*/,'::ffff:172.32.0.1',
	]) assert.equal(inRanges(INTERNAL,ip),false,ip);
});

test('refuses what an unanchored regex used to admit', () => {
	for (const ip of ['110.0.0.1','8.8.10.9','1.172.0.1','35.172.129.137','192.168.10.5','210.0.0.1','1.127.0.0'])
		assert.equal(inRanges(INTERNAL,ip),false,ip);
});

test('exact /32: neighbours are out', () => {
	for (const ip of ['37.157.143.25','37.157.143.249','37.157.143.251'])
		assert.equal(inRanges(INTERNAL,ip),false,ip);
});

test('fails closed on anything malformed', () => {
	for (const ip of [
		'',' 10.0.0.1','10.0.0.1 ','10.0.0.1\n','10.0.0','10.0.0.1.','10..0.1','10.0.0.256',
		'010.0.0.1','10.0.0.01','+10.0.0.1','10.0.0.1/8','0x0a.0.0.1',
		'::ffff:a00:1' /* hex-mapped form: node never reports it, so refusing is safe */,
		'2001:db8::1','::','fe80::1%eth0','localhost',
	]) assert.equal(inRanges(INTERNAL,ip),false,JSON.stringify(ip));
	assert.equal(inRanges(INTERNAL,undefined),false);
	assert.equal(inRanges(INTERNAL,null),false);
});

test('compileRanges throws on typos instead of widening', () => {
	assert.throws(() => compileRanges(['172.16.0.0/8']),/host bits set.*172\.0\.0\.0\/8/);
	assert.throws(() => compileRanges(['10.0.0.1/8']),/host bits set/);
	assert.throws(() => compileRanges(['10.0.0.0/33']),/longer than 32/);
	assert.throws(() => compileRanges(['10.0.0.0/']),/bad prefix/);
	assert.throws(() => compileRanges(['10.0.0.0/08']),/bad prefix/);
	assert.throws(() => compileRanges(['10.0.0.0/-1']),/bad prefix/);
	assert.throws(() => compileRanges(['10.0.0']),/not an IP/);
	assert.throws(() => compileRanges(['localhost']),/not an IP/);
	assert.throws(() => compileRanges(['2001:db8::/32']),/IPv6 ranges are not supported/);
	assert.throws(() => compileRanges([undefined as any]),/not a string/);
});

test('/0 admits every IPv4 and nothing else', () => {
	const all=compileRanges(['0.0.0.0/0']);
	for (const ip of ['0.0.0.0','255.255.255.255','::ffff:8.8.8.8']) assert.equal(inRanges(all,ip),true,ip);
	assert.equal(inRanges(all,'::1'),false);
});

test('mapped notation in the list is the IPv4 range it carries', () => {
	const r=compileRanges(['::ffff:10.0.0.0/8']);
	assert.equal(inRanges(r,'10.1.2.3'),true);
	assert.equal(inRanges(r,'::ffff:10.1.2.3'),true);
	assert.equal(inRanges(r,'11.0.0.0'),false);
});

test('IPv6 exact, case-insensitive, /128 accepted', () => {
	const r=compileRanges(['2001:DB8::1/128']);
	assert.equal(inRanges(r,'2001:db8::1'),true);
	assert.equal(inRanges(r,'2001:db8::2'),false);
});

test('empty list admits nothing', () => {
	const none=compileRanges([]);
	for (const ip of ['127.0.0.1','::1','10.0.0.1']) assert.equal(inRanges(none,ip),false,ip);
});

test('PRIVATE_V4 is RFC 1918 exactly', () => {
	const p=compileRanges(PRIVATE_V4);
	for (const ip of ['10.0.0.1','172.16.0.1','172.31.255.255','192.168.0.1','192.168.255.255'])
		assert.equal(inRanges(p,ip),true,ip);
	for (const ip of ['172.15.255.255','172.32.0.0','192.167.255.255','192.169.0.0','11.0.0.0','127.0.0.1'])
		assert.equal(inRanges(p,ip),false,ip);
});

test('the exported constants cannot be mutated', () => {
	assert.throws(() => { (LOOPBACK as string[]).push('0.0.0.0/0'); });
	assert.throws(() => { (PRIVATE_V4 as string[]).push('0.0.0.0/0'); });
});

test('v4ToNum and unmapIp', () => {
	assert.equal(v4ToNum('0.0.0.0'),0);
	assert.equal(v4ToNum('255.255.255.255'),4294967295);
	assert.equal(v4ToNum('10.132.0.5'),(10*2**24)+(132*2**16)+5);
	assert.equal(v4ToNum('1.2.3'),-1);
	assert.equal(unmapIp('::ffff:1.2.3.4'),'1.2.3.4');
	assert.equal(unmapIp('::1'),'::1');
	assert.equal(unmapIp('1.2.3.4'),'1.2.3.4');
});
