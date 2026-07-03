import { rpc } from '@stellar/stellar-sdk';
async function run() {
  const res = await fetch('https://soroban-testnet.stellar.org', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getNetwork', params: {} })
  });
  console.log(await res.text());
}
run();
