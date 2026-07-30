import { rpc } from '@stellar/stellar-sdk';
const SOROBAN_RPC = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
async function run() {
  const server = new rpc.Server(SOROBAN_RPC);
  const res = await server.getTransaction('f1358f074362b9e560d915c59e38c91de94ee8cdc0ba87fdbc646da6348191f2');
  console.log(JSON.stringify(res, null, 2));
}
run();
