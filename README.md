# nutpatch

nutpatch is a [Nitro Modules](https://nitro.margelo.com) implementation of performance-critical [cashu-ts](https://github.com/cashubtc/cashu-ts) operations, offloaded to native C++ via JSI.

## Installation

```sh
npm install nutpatch
```

## Usage

Pass `NativeOutputCreator` to `CashuWallet` as `outputDataCreator` — that's it.

```ts
import { CashuWallet, CashuMint } from '@cashu/cashu-ts'
import { NativeOutputCreator } from 'nutpatch'

const wallet = new CashuWallet(new CashuMint('https://mint.example.com'), {
  outputDataCreator: new NativeOutputCreator(),
})
```

All output creation (random, deterministic, P2PK) is now handled natively.

peace