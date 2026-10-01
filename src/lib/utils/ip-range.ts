// Is an IP address inside a CIDR range? Used to tell whether a sign-in came
// from one of the tenant's named locations (which Entra stores as CIDR
// ranges, IPv4 and IPv6). Malformed input never matches.

function ipv4ToBigInt(ip: string): bigint | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) + BigInt(n);
  }
  return value;
}

function ipv6ToBigInt(ip: string): bigint | null {
  let address = ip.split("%")[0];
  // An embedded IPv4 tail (::ffff:192.0.2.1) becomes two hex groups.
  const lastColon = address.lastIndexOf(":");
  if (address.includes(".")) {
    const v4 = ipv4ToBigInt(address.slice(lastColon + 1));
    if (v4 === null) return null;
    address = `${address.slice(0, lastColon + 1)}${(v4 >> 16n).toString(16)}:${(v4 & 0xffffn).toString(16)}`;
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    value = (value << 16n) + BigInt(parseInt(group, 16));
  }
  return value;
}

function parseIp(ip: string): { value: bigint; bits: number } | null {
  const trimmed = (ip || "").trim();
  if (trimmed.includes(":")) {
    const value = ipv6ToBigInt(trimmed);
    return value === null ? null : { value, bits: 128 };
  }
  const value = ipv4ToBigInt(trimmed);
  return value === null ? null : { value, bits: 32 };
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const [rangeIp, prefixText] = (cidr || "").trim().split("/");
  const address = parseIp(ip);
  const range = parseIp(rangeIp);
  if (!address || !range || address.bits !== range.bits) return false;
  const prefix = prefixText === undefined ? range.bits : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > range.bits) return false;
  const shift = BigInt(range.bits - prefix);
  return address.value >> shift === range.value >> shift;
}
