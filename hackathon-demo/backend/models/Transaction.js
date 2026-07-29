import mongoose from 'mongoose';

const TransactionSchema = new mongoose.Schema({
  hash: { type: String, required: true },
  sender: { type: String, required: true },
  receiver: { type: String, required: true },
  amount: { type: String, required: true },
  status: { type: String, default: 'Confirmed' },
  createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', TransactionSchema);
export default Transaction;
