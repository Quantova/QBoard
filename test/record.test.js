// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function checkinJourney(key, subject) {
  return Q.checkin({ key, flightNo: 'QV123', pnr: 'ABC123', subject: Q.keyId(subject), carrierLabel: 'Quantova Air' });
}

test('a check in is a well formed signed record of the carrier', () => {
  const carrier = freshKey();
  const pax = freshKey();
  const j = checkinJourney(carrier, pax);
  assert.strictEqual(j.format, 'qboard/1');
  assert.strictEqual(j.type, 'checkin');
  assert.strictEqual(j.algorithm, 'ML-DSA-65');
  assert.strictEqual(j.signer.id, Q.keyId(carrier));
  assert.strictEqual(j.statement.carrierKeyId, Q.keyId(carrier));
  assert.strictEqual(j.statement.subjectKeyId, Q.keyId(pax));
  assert.match(j.statement.boardId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(j.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(j.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the bagdrop, screen and board records chain to the same journey', () => {
  const carrier = freshKey();
  const pax = freshKey();
  const handler = freshKey();
  const screener = freshKey();
  const agent = freshKey();
  const j = checkinJourney(carrier, pax);
  const bag = Q.bagdrop({ key: handler, checkin: j, bagTag: 'BAG0001' });
  const scr = Q.screen({ key: screener, record: j, result: 'cleared' });
  const brd = Q.board({ key: agent, record: scr, gate: 'A12' });
  assert.strictEqual(bag.statement.boardId, j.statement.boardId);
  assert.strictEqual(bag.statement.checkinRef, Q.recordRef(j));
  assert.strictEqual(scr.statement.priorRef, Q.recordRef(j));
  assert.strictEqual(brd.statement.priorRef, Q.recordRef(scr));
  assert.strictEqual(scr.statement.result, 'cleared');
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const pax = freshKey();
  const base = { key, flightNo: 'QV123', pnr: 'ABC123', subject: Q.keyId(pax) };
  assert.throws(() => Q.checkin(Object.assign({}, base, { flightNo: '' })), /flightNo is 1 to/);
  assert.throws(() => Q.checkin(Object.assign({}, base, { subject: 'nothex' })), /subject is a/);
  assert.throws(() => Q.checkin(Object.assign({}, base, { unknownField: 1 })), /is not an option of checkin/);
  const j = checkinJourney(key, pax);
  assert.throws(() => Q.screen({ key, record: j, result: 'maybe' }), /result must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  const pax = freshKey();
  assert.throws(() => checkinJourney(new Uint8Array(16), pax), /32 byte Uint8Array seed/);
  assert.throws(() => checkinJourney(new Uint8Array(32), pax), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const carrier = freshKey();
  const pax = freshKey();
  const j = checkinJourney(carrier, pax);
  const ok = await Q.verify(j, { type: 'checkin', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'checkin');
  assert.strictEqual(ok.boardId, j.statement.boardId);
  const wrongType = await Q.verify(j, { type: 'board', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(j, { type: 'checkin', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const carrier = freshKey();
  const pax = freshKey();
  const j = checkinJourney(carrier, pax);
  const forged = JSON.parse(JSON.stringify(j));
  forged.statement.flightNo = 'QV999';
  const r = await Q.verify(forged, { type: 'checkin', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a screening to the journey it refers to', async () => {
  const carrier = freshKey();
  const pax = freshKey();
  const screener = freshKey();
  const j = checkinJourney(carrier, pax);
  const scr = Q.screen({ key: screener, record: j, result: 'cleared' });
  const good = await Q.verify(scr, { type: 'screen', network: 'testnet', requireAnchor: false, strict: false, prior: j });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherJ = checkinJourney(carrier, pax);
  const bad = await Q.verify(scr, { type: 'screen', network: 'testnet', requireAnchor: false, strict: false, prior: otherJ });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'ABC123');
  const b = Q.subjectRef(secret, 'ABC123');
  const c = Q.subjectRef(secret, 'ABC124');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the passenger journey line', () => {
  assert.strictEqual(Q.KIND, 1504);
  assert.strictEqual(Q.FORMAT, 'qboard/1');
  assert.deepStrictEqual([...Q.TYPES], ['checkin', 'bagdrop', 'screen', 'board', 'offload']);
  assert.deepStrictEqual([...Q.RESULTS], ['cleared', 'secondary', 'denied']);
});
