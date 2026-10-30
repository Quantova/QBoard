// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type ScreenResult = 'cleared' | 'secondary' | 'denied';
export type RecordType = 'checkin' | 'bagdrop' | 'screen' | 'board' | 'offload';

export interface KeyDescription {
  format: 'qboard-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qboard/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface CheckinOptions {
  key: Uint8Array;
  flightNo: string;
  pnr: string;
  subject: Party;
  carrierLabel?: string;
  checkedInAt?: string;
  note?: string;
}

export interface BagdropOptions {
  key: Uint8Array;
  checkin: Envelope;
  bagTag: string;
  handlerLabel?: string;
  droppedAt?: string;
  note?: string;
}

export interface ScreenOptions {
  key: Uint8Array;
  record: Envelope;
  result: ScreenResult;
  screenerLabel?: string;
  screenedAt?: string;
  note?: string;
}

export interface BoardOptions {
  key: Uint8Array;
  record: Envelope;
  gate: string;
  agentLabel?: string;
  boardedAt?: string;
  note?: string;
}

export interface OffloadOptions {
  key: Uint8Array;
  record: Envelope;
  reason: string;
  agentLabel?: string;
  offloadedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  boardId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  boardId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function checkin(options: CheckinOptions): Envelope;
export function bagdrop(options: BagdropOptions): Envelope;
export function screen(options: ScreenOptions): Envelope;
export function board(options: BoardOptions): Envelope;
export function offload(options: OffloadOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qboard/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1504;
export const TYPES: readonly RecordType[];
export const RESULTS: readonly ScreenResult[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
