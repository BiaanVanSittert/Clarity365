import { describe, expect, it } from "vitest";
import { hasIntuneCapability } from "./intune-capability";

const cap = (id: string, name: string, licensed: boolean) => ({ id, name, licensed, category: "Endpoint" as const, tier: "", description: "" });

describe("hasIntuneCapability", () => {
  it("recognises the live generic id and the demo tier-specific id", () => {
    expect(hasIntuneCapability({ capabilities: [cap("cap-intune", "Microsoft Intune", true)] })).toBe(true);
    expect(hasIntuneCapability({ capabilities: [cap("cap-intune-p1", "Microsoft Intune Suite", true)] })).toBe(true);
  });

  it("is false when unlicensed or absent", () => {
    expect(hasIntuneCapability({ capabilities: [cap("cap-intune", "Microsoft Intune", false)] })).toBe(false);
    expect(hasIntuneCapability({ capabilities: [] })).toBe(false);
  });
});
