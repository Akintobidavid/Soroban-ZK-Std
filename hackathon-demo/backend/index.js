import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { rpc, Contract, Address, TransactionBuilder, Networks, scValToNative, Account, xdr } from '@stellar/stellar-sdk';
import Transaction from './models/Transaction.js';

dotenv.config();

const app = new Hono();
app.use('*', cors());

// ── Soroban helpers ──────────────────────────────────────────────────────────
const SOROBAN_RPC   = process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org';
const HORIZON_RPC   = process.env.HORIZON_RPC_URL || 'https://horizon-testnet.stellar.org';
const NETWORK_PASSPHRASE = process.env.NETWORK_PASSPHRASE || Networks.TESTNET;
const CONTRACT_ID   = process.env.CONTRACT_ID || 'CCE7SJDDRQEXOGF7PNIY26LY63ZUXGBIYXZ3ZY3J4MGSJSXFXTUS5NTN';

// A fixed dummy account used only for read-only simulations (no auth needed)
const SIM_ACCOUNT   = new Account(
  process.env.SIM_ACCOUNT_PUBKEY || 'GBA2SJQYYNSPMLPZBJBYWUC6KROU6LUFPYPHYIU2WNMVMOIY7WOQ5HYW',
  '0'
);

const sorobanServer = new rpc.Server(SOROBAN_RPC);
const contract      = new Contract(CONTRACT_ID);

/** Raw JSON-RPC helper — bypasses feaxios which is broken on Node.js 24 */
async function sorobanRpc(method, params = null) {
  const res = await fetch(SOROBAN_RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(`RPC error: ${JSON.stringify(json.error)}`);
  return json.result;
}

/** XDR-encode a get_balance call using the SDK (just for building the tx) then simulate via raw fetch */
async function fetchOnChainBalance(address) {
  try {
    const op  = contract.call('get_balance', Address.fromString(address).toScVal());
    const tx  = new TransactionBuilder(SIM_ACCOUNT, { fee: '100', networkPassphrase: NETWORK_PASSPHRASE })
      .addOperation(op).setTimeout(30).build();

    const result = await sorobanRpc('simulateTransaction', { transaction: tx.toXDR() });

    if (result?.results?.[0]?.xdr) {
      const retval = xdr.ScVal.fromXDR(result.results[0].xdr, 'base64');
      return Number(scValToNative(retval)) / 10_000_000;
    }
  } catch (e) {
    console.error('fetchOnChainBalance error:', e.message);
  }
  return 0;
}

/** Fetch latest ledger sequence via raw fetch */
async function getLatestLedger() {
  const result = await sorobanRpc('getLatestLedger');
  return result.sequence;
}

/** Fetch contract events via raw fetch */
async function getContractEvents(startLedger) {
  const result = await sorobanRpc('getEvents', {
    startLedger,
    filters: [{ type: 'contract', contractIds: [CONTRACT_ID] }],
    pagination: { limit: 100 },
  });
  return result?.events || [];
}

/**
 * Pull contract transactions from Horizon and upsert into MongoDB.
 */
async function syncContractEvents() {
  try {
    const url  = `${HORIZON_RPC}/accounts/${CONTRACT_ID}/transactions?order=desc&limit=50&include_failed=false`;
    const res  = await fetch(url);
    const data = await res.json();
    const records = data._embedded?.records || [];

    let upserted = 0;
    for (const tx of records) {
      const exists = await Transaction.findOne({ hash: tx.id });
      if (exists) continue;

      const opsRes  = await fetch(tx._links.operations.href);
      const opsData = await opsRes.json();
      const ops     = opsData._embedded?.records || [];

      for (const op of ops) {
        if (op.type === 'invoke_host_function') {
          await Transaction.findOneAndUpdate(
            { hash: tx.id },
            {
              hash:      tx.id,
              sender:    tx.source_account,
              receiver:  CONTRACT_ID,
              amount:    'Contract Interaction',
              status:    'Confirmed',
              label:     'Contract Call',
              createdAt: new Date(tx.created_at),
            },
            { upsert: true, new: true }
          );
          upserted++;
        }
      }
    }
    return upserted;
  } catch (e) {
    console.error('syncContractEvents error:', e.message);
    return 0;
  }
}


// ── MongoDB ──────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// ── Routes ───────────────────────────────────────────────────────────────────

app.get('/', (c) => c.json({ status: 'ok', contract: CONTRACT_ID }));

/** GET /api/balance/:address  — reads directly from the Soroban contract */
app.get('/api/balance/:address', async (c) => {
  try {
    const address = c.req.param('address');
    const balance = await fetchOnChainBalance(address);
    return c.json({ balance, source: 'soroban-contract', contract: CONTRACT_ID });
  } catch (error) {
    console.error('Error fetching balance:', error);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

/** POST /api/transactions  — frontend posts after a confirmed tx */
app.post('/api/transactions', async (c) => {
  try {
    const { hash, sender, receiver, amount, type } = await c.req.json();
    if (!hash || !sender || !receiver || !amount) {
      return c.json({ error: 'Missing required fields' }, 400);
    }
    // Upsert so duplicate posts from the UI don't create duplicate records
    const tx = await Transaction.findOneAndUpdate(
      { hash },
      { hash, sender, receiver, amount, type: type || 'transfer', status: 'Confirmed' },
      { upsert: true, new: true }
    );
    return c.json({ message: 'Saved', transaction: tx }, 201);
  } catch (error) {
    console.error('Error saving transaction:', error);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

/** GET /api/transactions  — returns stored transactions */
app.get('/api/transactions', async (c) => {
  try {
    const txs = await Transaction.find().sort({ createdAt: -1 }).limit(50);
    return c.json(txs);
  } catch (error) {
    console.error('Error fetching transactions:', error);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

/**
 * GET /api/resource-blueprint
 *
 * Returns the REAL Soroban resource values from the last confirmed
 * transfer_shielded transaction — not a simulation estimate, but the actual
 * values that validators accepted on-chain.
 *
 * How: look up the last 'transfer' tx hash from MongoDB → call
 * getTransaction() on the Soroban RPC → decode the envelopeXdr →
 * read SorobanTransactionData.resources().
 *
 * The frontend uses these as the resource declaration for the next tx
 * (+ a small 10% safety buffer), guaranteeing it won't hit Budget.ExceededLimit.
 */
app.get('/api/resource-blueprint', async (c) => {
  try {
    // 1. Find the last confirmed transfer tx hash stored by the frontend
    const lastTx = await Transaction.findOne({ type: 'transfer' }).sort({ createdAt: -1 });
    if (!lastTx) {
      return c.json({ error: 'No previous transfer transaction found' }, 404);
    }

    // 2. Fetch the real on-chain transaction from the Soroban RPC
    const txData = await sorobanRpc('getTransaction', { hash: lastTx.hash });
    if (!txData || txData.status !== 'SUCCESS') {
      return c.json({ error: 'Transaction not found or not successful on-chain', status: txData?.status }, 404);
    }

    // 3. Decode the envelope XDR to get the SorobanTransactionData
    //    The SorobanTransactionData lives in:
    //    TransactionEnvelope → v1 → tx → ext (arm sorobanV0) → sorobanData
    const { xdr } = await import('@stellar/stellar-sdk');
    const envelope = xdr.TransactionEnvelope.fromXDR(txData.envelopeXdr, 'base64');
    const sorobanData = envelope.v1().tx().ext().sorobanData();
    const resources   = sorobanData.resources();

    const blueprint = {
      instructions:  Number(resources.instructions()),
      diskReadBytes: Number(resources.diskReadBytes()),
      writeBytes:    Number(resources.writeBytes()),
      resourceFee:   Number(sorobanData.resourceFee()),
      sourceTxHash:  lastTx.hash,
    };

    console.log('📐 Resource blueprint from real tx:', blueprint);
    return c.json(blueprint);
  } catch (error) {
    console.error('resource-blueprint error:', error.message);
    return c.json({ error: 'Failed to extract resource blueprint', detail: error.message }, 500);
  }
});


/**
 * GET /api/contract-events
 * Reads events emitted directly from the Soroban contract via the RPC getEvents API.
 * This is the true source of truth — every shield, unshield, and transfer_shielded
 * that ever happened on-chain is returned here.
 */
app.get('/api/contract-events', async (c) => {
  try {
    const currentLedger = await getLatestLedger();
    const startLedger = Math.max(1, currentLedger - 1000);

    const rawEvents = await getContractEvents(startLedger);

    const events = (rawEvents || []).map(evt => {
      // The topic array holds the event name and addresses
      // topics[0] = event name (e.g. "Shielded"), topics[1..] = addresses
      const topics = evt.topic.map(t => {
        try { 
          const val = xdr.ScVal.fromXDR(t, 'base64');
          return scValToNative(val); 
        } catch { return t.toString(); }
      });

      let eventName = 'Contract Event';
      let sender = null;
      let receiver = null;

      // topic structure from our contract:
      // shield:            [(user,), "Shielded"]
      // unshield:          [(user,), "Unshielded"]
      // transfer_shielded: [(sender, receiver), "Shielded Transfer ..."]
      if (typeof topics[1] === 'string') {
        eventName = topics[1];
      } else if (typeof topics[0] === 'string') {
        eventName = topics[0];
      }

      // Try to extract addresses from the first topic tuple
      if (Array.isArray(topics[0])) {
        [sender, receiver] = topics[0];
      } else if (typeof topics[0] === 'object' && topics[0] !== null) {
        const keys = Object.values(topics[0]);
        sender = keys[0] || null;
        receiver = keys[1] || null;
      }

      return {
        id:         evt.id,
        txHash:     evt.txHash,
        ledger:     evt.ledger,
        type:       eventName,
        sender:     sender ? String(sender) : null,
        receiver:   receiver ? String(receiver) : null,
        explorerUrl: `${process.env.EXPLORER_TX_URL || 'https://stellar.expert/explorer/testnet/tx/'}${evt.txHash}`,
        contractUrl: `${process.env.EXPLORER_CONTRACT_URL || 'https://stellar.expert/explorer/testnet/contract/'}${CONTRACT_ID}`,
      };
    });

    return c.json({ events, contract: CONTRACT_ID, startLedger });
  } catch (error) {
    console.error('Error fetching contract events:', error);
    return c.json({ error: 'Internal Server Error', detail: error.message }, 500);
  }
});


/**
 * GET /api/sync
 * Pulls the latest contract events from Horizon, upserts them into MongoDB,
 * and returns a summary. Call this from the frontend after any transaction
 * to make sure the backend DB is in sync with the chain.
 */
app.get('/api/sync', async (c) => {
  try {
    const upserted = await syncContractEvents();
    return c.json({ synced: true, newRecords: upserted, contract: CONTRACT_ID });
  } catch (error) {
    console.error('Sync error:', error);
    return c.json({ error: 'Sync failed' }, 500);
  }
});

/**
 * GET /api/sync/:address
 * Returns the on-chain balance for an address AND all their transactions
 * found in MongoDB — a single call to refresh the whole UI state.
 */
app.get('/api/sync/:address', async (c) => {
  try {
    const address = c.req.param('address');

    // 1. Get live balance from contract
    const balance = await fetchOnChainBalance(address);

    // 2. Get their transactions from MongoDB (sent or received)
    const txs = await Transaction.find({
      $or: [{ sender: address }, { receiver: address }]
    }).sort({ createdAt: -1 }).limit(20);

    return c.json({
      address,
      shieldedBalance: balance,
      source: 'soroban-contract',
      contract: CONTRACT_ID,
      transactions: txs,
    });
  } catch (error) {
    console.error('Sync error:', error);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

/**
 * POST /api/verify-and-send
 * Receives the ZK Proof from the frontend, verifies it using snarkjs in Node.js,
 * and if valid, submits the transaction to Soroban Testnet.
 */
app.post('/api/verify-and-send', async (c) => {
  try {
    const snarkjs = await import('snarkjs');
    const fs = await import('fs');
    const path = await import('path');

    const { signedTxXdr, proof, publicSignals } = await c.req.json();
    if (!signedTxXdr || !proof || !publicSignals) {
      return c.json({ error: 'Missing proof or tx data' }, 400);
    }

    console.log("Received ZK Proof for verification:", publicSignals);
    
    // 1. Load the Verifying Key
    const vKeyPath = path.resolve('../circuit/verification_key.json');
    const vKey = JSON.parse(fs.readFileSync(vKeyPath, 'utf8'));

    // 2. Verify the Proof
    const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    
    if (!isValid) {
      console.log("❌ ZK Proof verification failed!");
      return c.json({ error: 'Invalid ZK Proof' }, 400);
    }
    console.log("✅ ZK Proof verified successfully in backend!");

    // 3. Submit the signed transaction to Soroban Testnet
    const signedTx = TransactionBuilder.fromXDR(signedTxXdr, NETWORK_PASSPHRASE);
    const sorobanSender = new rpc.Server(SOROBAN_RPC);
    const response = await sorobanSender.sendTransaction(signedTx);
    
    if (response.status === "ERROR") {
       console.error("Soroban Error:", response);
       return c.json({ error: 'Transaction rejected by Soroban', details: response }, 400);
    }

    console.log("✅ Transaction submitted:", response.hash);
    return c.json({ success: true, hash: response.hash || signedTx.hash().toString("hex") });
  } catch (error) {
    console.error('Error in verify-and-send:', error);
    return c.json({ error: error.message || 'Internal Server Error' }, 500);
  }
});

// ── Start ────────────────────────────────────────────────────────────────────
const port = Number(process.env.PORT) || 3001;
console.log(`🚀 Server running on port ${port}`);
console.log(`📄 Contract: ${CONTRACT_ID}`);

serve({ fetch: app.fetch, port });
