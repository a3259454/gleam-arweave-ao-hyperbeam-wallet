import { clientForGateway } from "./client";
import {
  applyTransactionSignature,
  buildUnsignedTransaction,
  broadcastTransaction,
  signTransactionWithSigner,
  type ArweaveTransactionJson,
} from "./transaction";
import type { Signer } from "../vault/signer";
import type { Winston } from "../models/balance";
import type { Tag } from "../models/tag";
import { userErrorMessage } from "../models/user-errors";

/**
 * This module's public functions accept an unlocked wallet's `Signer`
 * rather than a password or wallet id — they never
 * decrypt anything themselves, and never use `core/vault`'s envelope, since key
 * material is never persisted anywhere (see `wallet-lifecycle.ts`). This
 * keeps `core/arweave` agnostic about how the caller obtained signing
 * material. A hardware wallet uses `prepareTransfer`/`finishTransfer`
 * with a signature from the device instead.
 *
 * No `fetchImpl` injection point here (unlike `balance.ts`/`graphql.ts`):
 * `arweave-js`'s internal `Api` class always calls the ambient `fetch`
 * directly with no override hook, so tests mock `globalThis.fetch`
 * instead.
 */
export interface FeeQuote {
  fee: Winston;
}

/**
 * Reads a fee quote via the gateway's `price` endpoint. Pure network read,
 * no signing.
 *
 * `recipient` is optional, but omitting it underquotes: the gateway adds
 * a new-wallet fee once a target is known and isn't yet in the wallet
 * list, so a recipient-less quote can be lower than the real one.
 *
 * `byteSize` defaults to 0 (a plain AR value transfer with no data). A
 * caller quoting a data transaction (e.g. a dApp's `sign`/`dispatch`
 * request with no `reward` of its own) must pass the actual payload size —
 * arweave-js prices a transaction by its real `data.byteLength` when it
 * signs, so a 0-byte quote for a non-empty payload underquotes the fee
 * that will actually be charged.
 */
export async function estimateFee(gatewayUrl: string, recipient?: string, byteSize = 0): Promise<FeeQuote> {
  const client = clientForGateway(gatewayUrl);
  const fee = await client.transactions.getPrice(byteSize, recipient);
  return { fee };
}

export interface SubmittedTransfer {
  txId: string;
}

/**
 * Builds the unsigned, data-less transaction to `recipient` that
 * `ownerB64Url` will sign: an AR value transfer, or with `tags` a message
 * to a process that reads L1 (a collectible send). `reward` is the fee the
 * user approved, never a fresh quote: the gateway only supplies the anchor,
 * so it can't raise the fee after they saw it.
 */
export async function prepareTransfer(
  gatewayUrl: string,
  ownerB64Url: string,
  recipient: string,
  amount: Winston,
  reward: Winston,
  tags: Tag[] = [],
): Promise<ArweaveTransactionJson> {
  // arweave-js decodes `target` with strict base64 and would otherwise
  // throw a bare "Invalid character" DOMException.
  if (!/^[A-Za-z0-9_-]{43}$/.test(recipient)) {
    throw new Error(userErrorMessage("transferRecipientInvalid", { recipient }));
  }
  // The quantity is what gets signed, and the network only accepts a whole
  // number of Winston. A decimal, exponent or sign would build a transaction
  // that can never be mined; the UI checks its field, and this is the last
  // point every caller, the hardware path included, passes through.
  if (!/^\d+$/.test(amount)) {
    throw new Error(`A transfer amount must be a whole number of Winston, got "${amount}".`);
  }
  return buildUnsignedTransaction(gatewayUrl, ownerB64Url, { target: recipient, quantity: amount, reward }, tags);
}

/** Applies `expectedOwner`'s signature to a `prepareTransfer` result and posts it. */
export async function finishTransfer(
  gatewayUrl: string,
  unsigned: ArweaveTransactionJson,
  signature: Uint8Array,
  expectedOwner: string,
): Promise<SubmittedTransfer> {
  const { id, transaction } = await applyTransactionSignature(unsigned, signature, expectedOwner);
  const response = await broadcastTransaction(gatewayUrl, transaction);
  if (response.status < 200 || response.status >= 300) {
    throw new Error(
      userErrorMessage("transferSubmitFailed", { gateway: gatewayUrl, status: response.status, statusText: response.statusText }),
    );
  }
  return { txId: id };
}

/** Builds, signs with the keyfile, and posts an AR value-transfer transaction. */
export async function submitTransfer(
  gatewayUrl: string,
  signer: Signer,
  recipient: string,
  amount: Winston,
  reward: Winston,
): Promise<SubmittedTransfer> {
  const unsigned = await prepareTransfer(gatewayUrl, signer.owner, recipient, amount, reward);
  return finishTransfer(gatewayUrl, unsigned, await signTransactionWithSigner(unsigned, signer), signer.owner);
}
