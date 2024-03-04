# Splits contracts monorepo

This is a mono-repository for the Splits contracts. Current packages in this repository include:

- [Splits - v2](./packages/splits-v2/README.md)

### Installation

The mono repo uses turborepo and pnpm. To install turbo repo, run the following command:

`pnpm install turbo --global`

To install pnpm run the following command:

`npm install pnpm --global` or checkout the [pnpm installation guide](https://pnpm.io/installation)

To install dependencies for all packages, run the following command:

`pnpm install`

### Build

To build all packages, run the following command:

`pnpm build`

### Test

To test all packages, run the following command:

`pnpm test`

### Lint

To lint all packages, run the following command:

`pnpm lint`

### Deployment

To deploy contracts, please refer to the README in the respective package.

### Acknowledgements

Shout out to the following projects for inspiration and guidance:

- [jtriley](https://github.com/jtriley-eth/ERC-6909)
- [frangio](https://github.com/frangio/erc6909-extensions)
- [Solady](https://github.com/vectorized/solady)
- [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)
- [Zora Protocol](https://github.com/ourzora/zora-protocol)
- [Solmate](https://github.com/transmissions11/solmate)
- [PaulRBerg's Foundry Template](https://github.com/PaulRBerg/foundry-template)
- [Uniswap's Permit2](https://github.com/Uniswap/permit2)
- [Coinbase Smart Wallet](https://github.com/coinbase/smart-wallet/tree/main)
