# QBoard

QBoard is a live production post quantum passenger journey record tool for airports and airlines on the Quantova network. It proves the check in, bag drop, security screening, boarding and offload of a passenger, and it lets any third party confirm that history without trusting the party that created it.

QBoard proves records without disclosing them. Passenger identities, booking references and bag tags stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no personal detail is ever published. A passenger is named only by a chain address.

## What it records

Each record is a signed envelope of one of five types.

1. checkin, a carrier states the flight, booking reference and passenger at check in.
2. bagdrop, a baggage handler records an accepted bag by its tag.
3. screen, a security screener records the result of a screening.
4. board, a gate agent records boarding at a named gate.
5. offload, a gate agent records an offload of the passenger or a bag and states why.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole journey forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qboard
```

## Use

```js
const qboard = require('@quantovainc/qboard');

const carrier = qboard.generateKey();
const passenger = qboard.generateKey();
const journey = qboard.checkin({
  key: carrier,
  flightNo: 'QV123',
  pnr: 'ABC123',
  subject: qboard.keyId(passenger),
  carrierLabel: 'Quantova Air',
});

const anchored = await qboard.anchor(journey, { seed, index: 0, network: 'testnet' });
const result = await qboard.verify(anchored[0], { type: 'checkin', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person. The passenger and the carrier are chain addresses, and linking an address to a person is a separate attestation held off the chain.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
