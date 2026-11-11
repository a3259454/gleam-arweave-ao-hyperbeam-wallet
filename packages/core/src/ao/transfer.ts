import type { Signer } from "../vault/signer";
import { applyDataItemSignature, buildUnsignedDataItem, signDataItemWithSigner } from "../arweave/data-item";
import { userErrorMessage } from "../models/user-errors";

export { createSignedDataItem } from "../arweave/data-item";

/**
 * An AO `Transfer` is a signed ANS-104 data item posted to the legacynet
 * Messenger Unit. The MU/CU routing here is independent of
 * `NetworkSettings.activePeerUrl`, which selects a HyperBEAM peer for
 * `ao/balance.ts`'s `~process@1.0` reads, an unrelated piece of
 * infrastructure.
 *
 * Tags follow the `ao.TN.1` message protocol
 * (`Data-Protocol`/`Variant`/`Type`/`Action`/`Recipient`/`Quantity`,
 * capitalized) that AO token processes' `Transfer` handler matches on.
 *
 * The data item is built and signed by `arweave/data-item.ts` with plain
 * `Uint8Array`s and WebCrypto rather than through `@permaweb/aoconnect`: aoconnect's
 * browser build re-verifies every signed item through its bundled
 * arbundles `ArweaveSigner.verify`, which hands the owner's raw bytes to
 * `crypto.subtle.importKey("jwk", { n: <Uint8Array> })` instead of a
 * base64url string, so Chrome rejects every signature. Owning the
 * ANS-104 encoding also keeps Node polyfills (`Buffer`, `crypto`) out of
 * this path.
 */
export const AO_LEGACY_MU_URL = "https://mu.ao-testnet.xyz";

export interface SubmittedAoTransfer {
  /** The data item id — base64url SHA-256 of its signature — once the Messenger Unit accepts it. */
  messageId: string;
}

/**
 * AO token transfers have no `arweave/transfer.ts`-style fee quote to
 * estimate: the token process (not the sender) bears its own compute
 * cost, and nothing in AO's message protocol quotes a sender-side fee
 * before posting. Callers should carry `TransferDraft.fee` as `null` for
 * every AO transfer, matching its `Winston | null` shape, rather than a
 * fabricated `0`.
 */
export const AO_TRANSFER_HAS_NO_FEE = true;

type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();

/**
 * Builds, signs, and posts an AO `Transfer` message to `processId` via the
 * legacynet Messenger Unit. `amount` is an atomic-integer string in the
 * token's own smallest unit (matching `TokenBalance.quantity`'s shape) —
 * never a floating-point number. `processId` must be a valid 43-character
 * base64url Arweave id (32 raw bytes) — it becomes the data item's
 * `target`.
 *
 * What "submitted" means here: the MU has accepted and scheduled the
 * signed data item — not that the token process has executed the
 * `Transfer` handler yet, nor that the recipient's balance has updated.
 * Callers writing an optimistic activity entry from this result should
 * treat status as "message accepted by the MU", not "transfer confirmed".
 */
export async function submitTransfer(
  signer: Signer,
  processId: string,
  recipient: string,
  amount: string,
): Promise<SubmittedAoTransfer> {
  const unsigned = prepareTransfer(signer.owner, processId, recipient, amount);
  return finishTransfer(unsigned, await signDataItemWithSigner(unsigned, signer), signer.owner);
}

/** The unsigned `Transfer` data item `ownerB64Url` will sign. */
export function prepareTransfer(ownerB64Url: string, processId: string, recipient: string, amount: string): Bytes {
  if (!/^[A-Za-z0-9_-]{43}$/.test(processId)) {
    throw new Error(`AO message target must be a 32-byte Arweave id (43 base64url characters), got "${processId}".`);
  }
  // Both of these go into the signed item as plain tags, and the token
  // process reads them from there: a recipient that isn't an address and a
  // quantity that isn't a whole number build a message that either bounces
  // or credits the wrong amount.
  if (!/^[A-Za-z0-9_-]{43}$/.test(recipient)) {
    throw new Error(`AO message recipient must be a 32-byte Arweave id (43 base64url characters), got "${recipient}".`);
  }
  if (!/^\d+$/.test(amount)) {
    throw new Error(`AO message quantity must be a whole number in the token's smallest unit, got "${amount}".`);
  }
  return buildUnsignedDataItem(ownerB64Url, {
    // A tag-only message still carries a non-empty body, as other AO
    // wallets send it, rather than relying on the MU accepting empty data.
    data: encoder.encode(" "),
    target: processId,
    tags: [
      { name: "Data-Protocol", value: "ao" },
      { name: "Variant", value: "ao.TN.1" },
      { name: "Type", value: "Message" },
      { name: "Action", value: "Transfer" },
      { name: "Recipient", value: recipient },
      { name: "Quantity", value: amount },
      { name: "Content-Type", value: "text/plain" },
    ],
  });
}

/** Applies `expectedOwner`'s signature to a `prepareTransfer` item and posts it to the MU. */
export async function finishTransfer(
  unsigned: Uint8Array,
  signature: Uint8Array,
  expectedOwner: string,
): Promise<SubmittedAoTransfer> {
  const { id, raw } = await applyDataItemSignature(unsigned, signature, expectedOwner);
  const response = await fetch(AO_LEGACY_MU_URL, {
    method: "POST",
    headers: { "content-type": "application/octet-stream", accept: "application/json" },
    body: raw,
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(
      detail
        ? userErrorMessage("aoSubmitFailedDetail", { url: AO_LEGACY_MU_URL, status: response.status, detail })
        : userErrorMessage("aoSubmitFailed", { url: AO_LEGACY_MU_URL, status: response.status }),
    );
  }

  return { messageId: id };
}
