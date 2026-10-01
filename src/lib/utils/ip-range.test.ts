import { describe, expect, it } from "vitest";
import { isIpInCidr } from "./ip-range";

describe("isIpInCidr", () => {
  it("matches IPv4 addresses inside a range and rejects those outside", () => {
    expect(isIpInCidr("203.0.113.57", "203.0.113.0/24")).toBe(true);
    expect(isIpInCidr("203.0.114.1", "203.0.113.0/24")).toBe(false);
    expect(isIpInCidr("10.1.2.3", "10.0.0.0/8")).toBe(true);
    expect(isIpInCidr("198.51.100.7", "198.51.100.7/32")).toBe(true);
    expect(isIpInCidr("198.51.100.8", "198.51.100.7/32")).toBe(false);
    expect(isIpInCidr("8.8.8.8", "0.0.0.0/0")).toBe(true);
  });

  it("matches IPv6 addresses, including the :: shorthand", () => {
    expect(isIpInCidr("2001:db8:abcd:12::1", "2001:db8:abcd::/48")).toBe(true);
    expect(isIpInCidr("2001:db8:abce::1", "2001:db8:abcd::/48")).toBe(false);
    expect(isIpInCidr("::1", "::1/128")).toBe(true);
    expect(isIpInCidr("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::/32")).toBe(true);
  });

  it("never matches across address families or on malformed input", () => {
    expect(isIpInCidr("203.0.113.57", "2001:db8::/32")).toBe(false);
    expect(isIpInCidr("2001:db8::1", "203.0.113.0/24")).toBe(false);
    expect(isIpInCidr("0.0.0.0", "")).toBe(false);
    expect(isIpInCidr("not-an-ip", "203.0.113.0/24")).toBe(false);
    expect(isIpInCidr("203.0.113.57", "203.0.113.0/33")).toBe(false);
    expect(isIpInCidr("203.0.113.999", "203.0.113.0/24")).toBe(false);
    expect(isIpInCidr("1:2:3", "::/0")).toBe(false);
  });
});
