import { rpc } from '@stellar/stellar-sdk';
const SOROBAN_RPC = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
const CONTRACT_ID = process.env.CONTRACT_ID || 'CBGILJ5PSIDMDNET4M7Z55DX6SUPLG7AJIH6CGDFNJZU5QKQIBXVWN26';
async function run() {
  const server = new rpc.Server(SOROBAN_RPC);
  const res = await server.getEvents({
    startLedger: 3412550,
    filters: [{ type: 'contract', contractIds: [CONTRACT_ID] }],
    pagination: { limit: 100 }
  });
  console.log(JSON.stringify(res, null, 2));
}
run();
