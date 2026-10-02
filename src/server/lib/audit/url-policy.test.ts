import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppError } from "@/server/lib/errors";
import {
  isCrawlableUrl,
  isFetchableUrl,
  normalizeAndValidateStartUrl,
  resolveStartUrlRedirects,
  setHostAddressResolverForTesting,
} from "@/server/lib/audit/url-policy";

/** A DoH JSON reply; `a` lists A-record addresses (empty = no answer). */
const dohReply = (a: string[], status = 0) =>
  new Response(
    JSON.stringify({
      Status: status,
      Answer: a.map((data) => ({ type: 1, data })),
    }),
    { status: 200, headers: { "content-type": "application/dns-json" } },
  );

describe("normalizeAndValidateStartUrl", () => {
  beforeEach(() => {
    setHostAddressResolverForTesting(null);
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    setHostAddressResolverForTesting(null);
  });

  it("adds https when protocol is missing and strips hash", async () => {
    vi.mocked(fetch).mockImplementation(() =>
      Promise.resolve(dohReply(["93.184.215.14"])),
    );

    await expect(
      normalizeAndValidateStartUrl("example.com/path#section"),
    ).resolves.toBe("https://example.com/path");
  });

  it.each([
    "http://localhost:3000",
    "http://192.168.0.10",
    "http://openseo:3001/",
    "http://core-api:8730/",
    "http://localhost/",
    "http://app.localhost/",
    "http://db/",
    "http://printer.lan/",
    "http://nas.home.arpa/",
    "http://192.0.0.8/",
    "http://[64:ff9b::10.0.0.1]/",
  ])("blocks %s without a DNS lookup", async (url) => {
    await expect(normalizeAndValidateStartUrl(url)).rejects.toMatchObject({
      code: "CRAWL_TARGET_BLOCKED",
    } satisfies Partial<AppError>);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("fails closed when public DNS has no answer", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(dohReply([])));
    await expect(
      normalizeAndValidateStartUrl("https://only-internal.example/"),
    ).rejects.toMatchObject({ code: "CRAWL_TARGET_BLOCKED" });
  });

  it("fails closed on NXDOMAIN", async () => {
    vi.mocked(fetch).mockImplementation(() => Promise.resolve(dohReply([], 3)));
    await expect(
      normalizeAndValidateStartUrl("https://nope.example/"),
    ).rejects.toMatchObject({ code: "CRAWL_TARGET_BLOCKED" });
  });

  it("fails closed when the resolver errors", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("DoH unreachable"));
    await expect(
      normalizeAndValidateStartUrl("https://example.com/"),
    ).rejects.toMatchObject({ code: "CRAWL_TARGET_BLOCKED" });
  });

  it("blocks public names that resolve to private addresses", async () => {
    vi.mocked(fetch).mockImplementation(() =>
      Promise.resolve(dohReply(["93.184.215.14", "10.0.0.5"])),
    );
    await expect(
      normalizeAndValidateStartUrl("https://rebind.example/"),
    ).rejects.toMatchObject({ code: "CRAWL_TARGET_BLOCKED" });
  });

  it("uses an injected resolver", async () => {
    setHostAddressResolverForTesting(async (host) =>
      host === "ok.example" ? ["93.184.215.14"] : ["172.18.0.3"],
    );
    await expect(
      normalizeAndValidateStartUrl("https://ok.example/"),
    ).resolves.toBe("https://ok.example/");
    await expect(
      normalizeAndValidateStartUrl("https://docker.example/"),
    ).rejects.toMatchObject({ code: "CRAWL_TARGET_BLOCKED" });
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("isCrawlableUrl", () => {
  it.each([
    ["https://example.com/a", true],
    ["http://openseo:3001/mcp", false],
    ["http://core-api:8730/api/health", false],
    ["http://localhost/", false],
    ["http://x.localhost/", false],
    ["http://10.1.2.3/", false],
    ["ftp://example.com/", false],
  ])("%s -> %s", (url, expected) => {
    expect(isCrawlableUrl(url)).toBe(expected);
  });
});

describe("isFetchableUrl", () => {
  afterEach(() => setHostAddressResolverForTesting(null));

  it("requires every resolved address to be public", async () => {
    setHostAddressResolverForTesting(async (host) => {
      if (host === "public.example") return ["93.184.215.14"];
      if (host === "mixed.example") return ["93.184.215.14", "fd00::1"];
      return [];
    });
    await expect(isFetchableUrl("https://public.example/s.xml")).resolves.toBe(
      true,
    );
    await expect(isFetchableUrl("https://mixed.example/s.xml")).resolves.toBe(
      false,
    );
    await expect(isFetchableUrl("https://unknown.example/")).resolves.toBe(
      false,
    );
    await expect(isFetchableUrl("http://openseo:3001/")).resolves.toBe(false);
  });

  it("caches the verdict per hostname", async () => {
    const resolver = vi.fn(async () => ["93.184.215.14"]);
    setHostAddressResolverForTesting(resolver);
    await isFetchableUrl("https://cache.example/a");
    await isFetchableUrl("https://cache.example/b");
    expect(resolver).toHaveBeenCalledTimes(1);
  });
});

const dnsOk = () => dohReply(["93.184.215.14"]);
const redirect = (location: string) =>
  new Response(null, { status: 301, headers: { location } });

describe("resolveStartUrlRedirects", () => {
  beforeEach(() => {
    setHostAddressResolverForTesting(null);
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** Route probe fetches by URL; DoH lookups always resolve clean. */
  function stubFetch(routes: Record<string, () => Response>) {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.includes("dns-query")) return Promise.resolve(dnsOk());
      const route = routes[url];
      return route
        ? Promise.resolve(route())
        : Promise.resolve(new Response(null, { status: 200 }));
    });
  }

  it("follows a cross-domain redirect to the real origin", async () => {
    stubFetch({
      "https://example.net/": () => redirect("https://example.com/"),
    });
    await expect(
      resolveStartUrlRedirects("https://example.net/"),
    ).resolves.toMatchObject({ url: "https://example.com/" });
  });

  it("returns the last URL when the probe fails", async () => {
    vi.mocked(fetch).mockRejectedValue(new Error("network down"));
    await expect(
      resolveStartUrlRedirects("https://example.com/"),
    ).resolves.toMatchObject({ url: "https://example.com/" });
  });

  it("stops after the hop limit on a redirect loop", async () => {
    stubFetch({
      "https://a.example/": () => redirect("https://b.example/"),
      "https://b.example/": () => redirect("https://a.example/"),
    });
    const resolved = await resolveStartUrlRedirects("https://a.example/");
    expect(resolved.url).toMatch(/^https:\/\/(a|b)\.example\/$/);
  });

  it("rejects redirects into blocked targets", async () => {
    stubFetch({
      "https://example.com/": () => redirect("http://192.168.0.10/"),
    });
    await expect(
      resolveStartUrlRedirects("https://example.com/"),
    ).rejects.toMatchObject({
      code: "CRAWL_TARGET_BLOCKED",
    } satisfies Partial<AppError>);
  });

  it("rejects redirects into single-label (container) hosts", async () => {
    stubFetch({
      "https://example.com/": () => redirect("http://openseo:3001/mcp"),
    });
    await expect(
      resolveStartUrlRedirects("https://example.com/"),
    ).rejects.toMatchObject({
      code: "CRAWL_TARGET_BLOCKED",
    } satisfies Partial<AppError>);
  });
});
