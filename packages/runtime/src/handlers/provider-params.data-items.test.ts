import { describe, expect, it } from "vitest";
import { MAX_BATCH_DATA_ITEMS, readDataItems } from "./provider-params";

function item(index: number) {
  return { data: `item ${index}`, tags: [] };
}

describe("readDataItems", () => {
  it("reads a batch up to the limit", () => {
    const items = Array.from({ length: MAX_BATCH_DATA_ITEMS }, (_, index) => item(index));
    expect(readDataItems(items)).toHaveLength(MAX_BATCH_DATA_ITEMS);
  });

  it("refuses one item past the limit", () => {
    const items = Array.from({ length: MAX_BATCH_DATA_ITEMS + 1 }, (_, index) => item(index));
    expect(() => readDataItems(items)).toThrow(/at most 100 data items/);
  });

  it("keeps refusing an empty or non-array batch", () => {
    expect(() => readDataItems([])).toThrow(/non-empty array/);
    expect(() => readDataItems({ data: "x" })).toThrow(/non-empty array/);
  });
});
