import { rpc } from '@stellar/stellar-sdk';
async function run() {
  const server = new rpc.Server('https://soroban-testnet.stellar.org');
  const res = await server.getEvents({
    startLedger: 3412550,
    filters: [{ type: 'contract', contractIds: ['CBGILJ5PSIDMDNET4M7Z55DX6SUPLG7AJIH6CGDFNJZU5QKQIBXVWN26'] }],
    pagination: { limit: 100 }
  });
  console.log(JSON.stringify(res, null, 2));
}
run();
