export async function decryptAmount(amount, viewingKey) {
  if (typeof amount !== 'number' || !Number.isFinite(amount)) {
    throw new Error('Expected a finite number for the amount to decrypt.');
  }

  if (typeof viewingKey !== 'string' || viewingKey.trim().length === 0) {
    throw new Error('Viewing key must be a non-empty string.');
  }

  const normalizedAmount = Number(amount);
  const sanitizedKey = viewingKey.trim();
  const bytes = Array.from(new TextEncoder().encode(sanitizedKey));

  let hash = 2166136261;
  for (const byte of bytes) {
    hash ^= byte;
    hash = Math.imul(hash, 16777619);
  }

  const mix = ((hash >>> 0) % 97) / 1000 + 1;
  const bias = (((hash >>> 0) % 11) / 100) * (normalizedAmount > 0 ? 1 : 0);
  const decryptedAmount = normalizedAmount * mix + bias;

  return Number(decryptedAmount.toFixed(2));
}
