import { afterEach, describe, expect, it, vi } from "vitest";
import { signerFromJwk } from "../signer/keys";
import Arweave from "arweave";
import { estimateFee, finishTransfer, prepareTransfer, submitTransfer } from "./transfer";

const jwk = await Arweave.init({}).wallets.generate();

const RECIPIENT = "rEcIpIeNt_AdDrEsS-0123456789abcdefghijklmno";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

/**
 * Real `Response` objects — `arweave-js`'s internal `Api.request` calls
 * `res.headers.get(...)` and `res.clone().json()`, which a plain object
 * satisfying only `{ ok, status, json }` doesn't support.
 */
function mockFetchSequence(responses: Array<{ status: number; body: unknown }>) {
  let call = 0;
  globalThis.fetch = vi.fn(async () => {
    const response = responses[Math.min(call, responses.length - 1)]!;
    call += 1;
    const body = typeof response.body === "string" ? response.body : JSON.stringify(response.body);
    return new Response(body, { status: response.status });
  }) as unknown as typeof fetch;
}

describe("estimateFee", () => {
  it("returns the fee as a Winston string from the gateway's price endpoint", async () => {
    mockFetchSequence([{ status: 200, body: "1234567" }]);
    const quote = await estimateFee("https://arweave.net", "recipientAddr");
    expect(quote.fee).toBe("1234567");
    expect(typeof quote.fee).toBe("string");
  });
});

describe("submitTransfer", () => {
  it("returns the signed transaction's txId on a successful post", async () => {
    mockFetchSequence([
      { status: 200, body: "anchor12345678901234567890123456789012345678" }, // getTransactionAnchor
      { status: 200, body: { ok: true } }, // post
    ]);

    const result = await submitTransfer("https://arweave.net", signerFromJwk(jwk, ""), RECIPIENT, "1000000000000", "1234567");
    expect(typeof result.txId).toBe("string");
    expect(result.txId.length).toBeGreaterThan(0);
  });

  it("throws a descriptive error when the post fails", async () => {
    mockFetchSequence([
      { status: 200, body: "anchor12345678901234567890123456789012345678" },
      { status: 500, body: "internal error" },
    ]);

    await expect(
      submitTransfer("https://arweave.net", signerFromJwk(jwk, ""), RECIPIENT, "1000000000000", "1234567"),
    ).rejects.toThrow(/Failed to submit transfer/);
  });

  it("rejects a recipient that isn't an Arweave address before touching the network", async () => {
    mockFetchSequence([{ status: 200, body: "" }]);

    await expect(
      submitTransfer("https://arweave.net", signerFromJwk(jwk, ""), "recipientAddr", "1000000000000", "1234567"),
    ).rejects.toThrow(/must be an Arweave address/);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});

describe("prepareTransfer / finishTransfer", () => {
  const TARGET = "vh-NTHVvlKZqRxc8LyyTNok65yQ55a_PJ1zWLb9G2JI";

  function recordFetch() {
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.includes("tx_anchor")) return new Response("b".repeat(64), { status: 200 });
      if (url.includes("price")) return new Response("1234567", { status: 200 });
      return new Response("OK", { status: 200 });
    });
    return () =>
      spy.mock.calls.map(([input, init]) => {
        const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
        if (body) {
          delete body.id;
          delete body.signature;
        }
        return { url: String(input instanceof Request ? input.url : input), method: init?.method ?? "GET", body };
      });
  }

  it("makes the same requests and posts the same transaction as arweave-js's JWK path", async () => {
    const referenceCalls = recordFetch();
    const client = Arweave.init({ host: "arweave.net", port: 443, protocol: "https" });
    const reference = await client.createTransaction({ target: TARGET, quantity: "1000", reward: "1234567" }, jwk);
    await client.transactions.sign(reference, jwk, { saltLength: 32 });
    await client.transactions.post(reference);
    const expected = referenceCalls();
    vi.restoreAllMocks();

    const calls = recordFetch();
    const { txId } = await submitTransfer("https://arweave.net", signerFromJwk(jwk, ""), TARGET, "1000", "1234567");

    expect(expected.map((call) => call.method)).toEqual(["GET", "POST"]);
    expect(expected[1]!.body).toMatchObject({ owner: jwk.n, target: TARGET, quantity: "1000", reward: "1234567" });
    expect(calls()).toEqual(expected);
    expect(txId).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("signs the approved reward and never asks the gateway for a price", async () => {
    const calls = recordFetch();
    const unsigned = await prepareTransfer("https://arweave.net", jwk.n, TARGET, "1000", "42");

    expect(unsigned.reward).toBe("42");
    expect(calls().some((call) => call.url.includes("price"))).toBe(false);
  });

  it("refuses an amount the network could never mine", async () => {
    await expect(prepareTransfer("https://arweave.net", jwk.n, TARGET, "1.5", "42")).rejects.toThrow(/whole number of Winston/);
  });

  it("posts a transfer whose signature came from elsewhere, and refuses a wrong one", async () => {
    const calls = recordFetch();
    const unsigned = await prepareTransfer("https://arweave.net", jwk.n, TARGET, "1000", "1234567");
    const reference = Arweave.init({}).transactions.fromRaw({ ...unsigned });
    await Arweave.init({}).transactions.sign(reference, jwk, { saltLength: 32 });
    const signature = reference.get("signature", { decode: true, string: false });

    await expect(finishTransfer("https://arweave.net", unsigned, signature, jwk.n)).resolves.toEqual({ txId: reference.id });
    await expect(finishTransfer("https://arweave.net", { ...unsigned, quantity: "1001" }, signature, jwk.n)).rejects.toThrow(
      /doesn't match/,
    );
    expect(calls().filter((call) => call.method === "POST")).toHaveLength(1);
  });
});
