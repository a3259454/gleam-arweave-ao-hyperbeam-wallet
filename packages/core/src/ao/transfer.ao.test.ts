import { describe, expect, it, vi, beforeAll, afterEach } from "vitest";
import { signerFromJwk, generateJWK } from "../signer/keys";
import { DataItem } from "@dha-team/arbundles/web";
import type { JWKInterface } from "../models/wallet";
import {
  AO_LEGACY_MU_URL,
  AO_TRANSFER_HAS_NO_FEE,
  createSignedDataItem,
  finishTransfer,
  prepareTransfer,
  submitTransfer,
} from "./transfer";
import { dataItemSignatureData } from "../arweave/data-item";
import { signRsaPss } from "../arweave/rsa-pss";

const PROCESS_ID = "0syT13r0s0tgPmIed95bJnuSqaD29HQNN8D3ElLSrsc";
const RECIPIENT = "vh-NTHVvlKZqRxc8LyyTNok65yQ55a_PJ1zWLb9G2JI";

let jwk: JWKInterface;

beforeAll(async () => {
  jwk = await generateJWK();
}, 20_000);

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function stubMu(response: Response = new Response("{}", { status: 200 })) {
  const fetchMock = vi.fn<typeof fetch>(async () => response);
  globalThis.fetch = fetchMock;
  return fetchMock;
}

/**
 * Independent check of the signature over arbundles' own parse and deep
 * hash of the item. Not `DataItem.verify`: arbundles' web build hands the
 * owner's raw bytes to WebCrypto as the JWK `n` (the bug `transfer.ts`
 * exists to avoid), and its Node build needs `axios`, which this package
 * doesn't depend on.
 */
async function verifies(item: DataItem): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "RSA", e: "AQAB", n: item.owner },
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    key,
    new Uint8Array(item.rawSignature),
    new Uint8Array(await item.getSignatureData()),
  );
}

function postedItem(fetchMock: ReturnType<typeof stubMu>): DataItem {
  const [, init] = fetchMock.mock.calls[0]!;
  return new DataItem(Buffer.from(init!.body as Uint8Array));
}

describe("createSignedDataItem", () => {
  it("produces an ANS-104 item whose signature verifies over arbundles' own parse, with the id derived from its signature", async () => {
    const { id, raw } = await createSignedDataItem(signerFromJwk(jwk, ""), {
      data: new TextEncoder().encode("hello"),
      target: PROCESS_ID,
      tags: [{ name: "Action", value: "Transfer" }],
    });

    const item = new DataItem(Buffer.from(raw));
    expect(await verifies(item)).toBe(true);
    expect(item.id).toBe(id);
    expect(item.owner).toBe(jwk.n);
    expect(item.target).toBe(PROCESS_ID);
    expect(item.tags).toEqual([{ name: "Action", value: "Transfer" }]);
    expect(Buffer.from(item.rawData).toString()).toBe("hello");
  });

  it("fails verification once a signed field is tampered with", async () => {
    const { raw } = await createSignedDataItem(signerFromJwk(jwk, ""), { data: new TextEncoder().encode("hello"), target: PROCESS_ID, tags: [] });
    raw[raw.byteLength - 1]! ^= 1;
    expect(await verifies(new DataItem(Buffer.from(raw)))).toBe(false);
  });

  it("rejects a target that isn't a 32-byte Arweave id", async () => {
    await expect(
      createSignedDataItem(signerFromJwk(jwk, ""), { data: new Uint8Array([1]), target: "not-an-id", tags: [] }),
    ).rejects.toThrow(/32-byte Arweave id/);
  });
});

describe("AO submitTransfer", () => {
  it("posts the signed item as octet-stream to the legacynet MU", async () => {
    const fetchMock = stubMu();
    await submitTransfer(signerFromJwk(jwk, ""), PROCESS_ID, RECIPIENT, "1000000000000");

    expect(fetchMock).toHaveBeenCalledWith(
      AO_LEGACY_MU_URL,
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ "content-type": "application/octet-stream" }),
      }),
    );
    expect(await verifies(postedItem(fetchMock))).toBe(true);
  }, 20_000);

  it("sends an ao.TN.1 Transfer message targeting the process, with capitalized tags", async () => {
    const fetchMock = stubMu();
    await submitTransfer(signerFromJwk(jwk, ""), PROCESS_ID, RECIPIENT, "42");

    const item = postedItem(fetchMock);
    expect(item.target).toBe(PROCESS_ID);
    expect(item.tags).toEqual([
      { name: "Data-Protocol", value: "ao" },
      { name: "Variant", value: "ao.TN.1" },
      { name: "Type", value: "Message" },
      { name: "Action", value: "Transfer" },
      { name: "Recipient", value: RECIPIENT },
      { name: "Quantity", value: "42" },
      { name: "Content-Type", value: "text/plain" },
    ]);
  });

  it("returns the posted data item's id as the messageId", async () => {
    const fetchMock = stubMu();
    const result = await submitTransfer(signerFromJwk(jwk, ""), PROCESS_ID, RECIPIENT, "42");
    expect(result).toEqual({ messageId: postedItem(fetchMock).id });
  });

  it("preserves large atomic-integer amounts exactly as strings, never floats", async () => {
    const fetchMock = stubMu();
    const huge = "90071992547409930000";
    await submitTransfer(signerFromJwk(jwk, ""), PROCESS_ID, RECIPIENT, huge);

    const quantityTag = postedItem(fetchMock).tags.find((tag) => tag.name === "Quantity");
    expect(quantityTag?.value).toBe(huge);
  });

  it("throws with the MU's status and body when it rejects the message", async () => {
    stubMu(new Response("bad item", { status: 400 }));
    await expect(submitTransfer(signerFromJwk(jwk, ""), PROCESS_ID, RECIPIENT, "1")).rejects.toThrow(/failed \(400\): bad item/);
  });

  it("propagates a network failure reaching the MU", async () => {
    globalThis.fetch = vi.fn<typeof fetch>().mockRejectedValue(new Error("network error"));
    await expect(submitTransfer(signerFromJwk(jwk, ""), PROCESS_ID, RECIPIENT, "1")).rejects.toThrow(/network error/);
  });
});

describe("AO_TRANSFER_HAS_NO_FEE", () => {
  it("is explicit that AO transfers have no sender-side fee quote, unlike AR", () => {
    expect(AO_TRANSFER_HAS_NO_FEE).toBe(true);
  });
});

describe("AO prepareTransfer / finishTransfer", () => {
  it("posts an item signed from the owner's public key alone, and refuses a signature for another item", async () => {
    const fetchMock = stubMu();
    const unsigned = prepareTransfer(jwk.n, PROCESS_ID, RECIPIENT, "42");
    const signature = await signRsaPss(signerFromJwk(jwk, ""), await dataItemSignatureData(unsigned));

    const { messageId } = await finishTransfer(unsigned, signature, jwk.n);

    const item = postedItem(fetchMock);
    expect(item.id).toBe(messageId);
    expect(await verifies(item)).toBe(true);
    expect(Buffer.from(item.getRaw().subarray(514)).equals(Buffer.from(unsigned.subarray(514)))).toBe(true);

    const other = prepareTransfer(jwk.n, PROCESS_ID, RECIPIENT, "43");
    await expect(finishTransfer(other, signature, jwk.n)).rejects.toThrow(/doesn't match/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("refuses an item built for and signed by another key", async () => {
    const fetchMock = stubMu();
    const other = await generateJWK();
    const foreign = prepareTransfer(other.n, PROCESS_ID, RECIPIENT, "42");
    const signature = await signRsaPss(signerFromJwk(other, ""), await dataItemSignatureData(foreign));

    await expect(finishTransfer(foreign, signature, jwk.n)).rejects.toThrow(/doesn't match/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a process id that isn't a 32-byte Arweave id", () => {
    expect(() => prepareTransfer(jwk.n, "not-an-id", RECIPIENT, "1")).toThrow(/32-byte Arweave id/);
  });

  it("refuses a recipient or quantity the token process would read wrong", () => {
    expect(() => prepareTransfer(jwk.n, PROCESS_ID, "not-an-id", "1")).toThrow(/recipient must be a 32-byte Arweave id/);
    expect(() => prepareTransfer(jwk.n, PROCESS_ID, RECIPIENT, "1.5")).toThrow(/whole number/);
    expect(() => prepareTransfer(jwk.n, PROCESS_ID, RECIPIENT, "-1")).toThrow(/whole number/);
  });
});
