import { rpc } from '@stellar/stellar-sdk';
async function run() {
  const server = new rpc.Server('https://soroban-testnet.stellar.org');
  const res = await server.getTransaction('f1358f074362b9e560d915c59e38c91de94ee8cdc0ba87fdbc646da6348191f2');
  console.log(JSON.stringify(res, null, 2));
}
run();
