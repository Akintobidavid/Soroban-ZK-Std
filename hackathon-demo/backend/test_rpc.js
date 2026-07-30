import { rpc, Contract, Address, TransactionBuilder, Networks, scValToNative, Account } from '@stellar/stellar-sdk';
const SOROBAN_RPC = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
const NETWORK_PASSPHRASE = process.env.NETWORK_PASSPHRASE || Networks.TESTNET;
const CONTRACT_ID = process.env.CONTRACT_ID || 'CBKCXGCXTY3TIEEVYSUPM4YY2XGBNDNGAXCO5BBEVZYZSWG7V2NNVYQH';
const SIM_PUBKEY = process.env.SIM_ACCOUNT_PUBKEY || 'GBA2SJQYYNSPMLPZBJBYWUC6KROU6LUFPYPHYIU2WNMVMOIY7WOQ5HYW';
async function run() {
  const sorobanServer = new rpc.Server(SOROBAN_RPC);
  const contract = new Contract(CONTRACT_ID);
  const op = contract.call("get_balance", Address.fromString(SIM_PUBKEY).toScVal());
  const sourceAccount = new Account(SIM_PUBKEY, "0");
  const tx = new TransactionBuilder(sourceAccount, { fee: "100", networkPassphrase: NETWORK_PASSPHRASE }).addOperation(op).setTimeout(30).build();
  const sim = await sorobanServer.simulateTransaction(tx);
  if (rpc.Api.isSimulationSuccess(sim)) {
     console.log("Balance:", Number(scValToNative(sim.result.retval)) / 10000000);
  } else {
     console.log("Sim failed:", sim);
  }
}
run();
