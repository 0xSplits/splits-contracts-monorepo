# Splits - v2

![Architecture](docs/architecture.png)

## Build

`pnpm build`

## Test

`pnpm test`

### Coverage

`pnpm test:coverage`

### Coverage Report

`pnpm test:coverage:report`

## Lint

`pnpm lint`

### Format

`pnpm format`

## Deployment

To deploy contracts, please ensure you have the environment variables set in `.env` file. Please refer to `.env.sample`
for the required environment variables.

For a chain not present in .env.sample, add the rpc url and etherscan API key to the .env.sample file and
[foundry.toml](./foundry.toml) file.

To understand how the configuration works, please refer to [foundry docs](https://book.getfoundry.sh/cheatcodes/rpc).

Each contract has its own deployment script. A config file is present in the `config` folder for each chain. The config
files contains the input needed for the constructors of the contracts.

The scripts use foundry's wallet to import the private key. To create the wallet refer to
[this](https://book.getfoundry.sh/reference/cast/cast-wallet-import).

e.g. `cast wallet import SPLITS_DEPLOYER --interactive`

To deploy contracts and verify contracts, run the following command:

### Splits Warehouse

`pnpm deploy:SplitsWarehouse`

For a test run, use the following command:

`pnpm deploy:SplitsWarehouse:test`

### Split Factory V2

`pnpm deploy:SplitFactoryV2`

For a test run, use the following command:

`pnpm deploy:SplitFactoryV2:test`

## Deployment requirements

To deploy split v2 contracts on a given chain, please make sure the following requirements are met:

1. Send the minimum amount of native gas token for deployment to the deployer address: `0x60C65c9a8674DA22e89C7d09e839908B9f0ecC3a`. Mainnet deployment transactions for gas cost:

    * [Warehouse](https://etherscan.io/tx/0x9a24df13332fafff979c35d5475be6a0594b9e8a632b1ff603150c413b7c134c)
    * [Pull Splits](https://etherscan.io/tx/0xe81eb2677e597ae98c65558487693d94494e28387f2a9d76782992e4f399f44a)
    * [Push Splits](https://etherscan.io/tx/0x20e8da208491560c658a25dcaa2bf37f94f26ccb4d5caaac4a346b2152818513)

2. Support for [CreateX](https://createx.rocks/). We use createX as our deployer factory. This will ensure that the addresses match existing deployments.

3. Complete OP Code compatibility with evm version: `Shanghai`.

Once these requirements are met please open an issue on github.

## Developers/Integrators

### Foundry

`forge install 0xSplits/splits-contracts-monorepo`

Update forge remapping to:

`splits-v2/=lib/splits-contracts-monorepo/packages/splits-v2/src`

If you are running into issues due to our use of named parameters with external dependencies such as Solady and
OpenZeppelin please use this [branch](https://github.com/0xSplits/splits-contracts-monorepo/tree/unnamed).

You can install it with foundry using:

`forge install 0xSplits/splits-contracts-monorepo@unnamed`
