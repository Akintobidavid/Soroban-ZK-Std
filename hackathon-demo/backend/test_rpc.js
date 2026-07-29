import { rpc, Contract, Address, TransactionBuilder, Networks, scValToNative, Account } from '@stellar/stellar-sdk';
async function run() {
  const sorobanServer = new rpc.Server("https://soroban-testnet.stellar.org");
  const contract = new Contract("CBKCXGCXTY3TIEEVYSUPM4YY2XGBNDNGAXCO5BBEVZYZSWG7V2NNVYQH");
  const op = contract.call("get_balance", Address.fromString("GBA2SJQYYNSPMLPZBJBYWUC6KROU6LUFPYPHYIU2WNMVMOIY7WOQ5HYW").toScVal());
  const sourceAccount = new Account("GBA2SJQYYNSPMLPZBJBYWUC6KROU6LUFPYPHYIU2WNMVMOIY7WOQ5HYW", "0");
  const tx = new TransactionBuilder(sourceAccount, { fee: "100", networkPassphrase: Networks.TESTNET }).addOperation(op).setTimeout(30).build();
  const sim = await sorobanServer.simulateTransaction(tx);
  if (rpc.Api.isSimulationSuccess(sim)) {
     console.log("Balance:", Number(scValToNative(sim.result.retval)) / 10000000);
  } else {
     console.log("Sim failed:", sim);
  }
}
run();
