import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { discoverUrls } from "@/server/lib/audit/discovery";
import { setHostAddressResolverForTesting } from "@/server/lib/audit/url-policy";
import { shopifyCrawlerHeaders } from "@/shared/crawler-access";

const access = {
  host: "store.example.com",
  headers: shopifyCrawlerHeaders("sig1=(...)", "sig1=:abc:"),
  expiresAt: null,
};

/** The `signature` header sent on the request to `url`, or undefined. */
function signatureSentTo(url: string) {
  const call = vi.mocked(fetch).mock.calls.find((entry) => entry[0] === url);
  return call && new Headers(call[1]?.headers).get("signature");
}

describe("discoverUrls crawler access", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
    setHostAddressResolverForTesting(async () => ["93.184.215.14"]);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    setHostAddressResolverForTesting(null);
  });

  it("drops the signature when robots.txt redirects to another host", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      if (input === "https://store.example.com/robots.txt") {
        return Promise.resolve(
          new Response(null, {
            status: 301,
            headers: { location: "https://cdn.other.test/robots.txt" },
          }),
        );
      }
      return Promise.resolve(new Response("", { status: 404 }));
    });

    await discoverUrls("https://store.example.com", 10, access);

    expect(signatureSentTo("https://store.example.com/robots.txt")).toBe(
      access.headers.Signature,
    );
    expect(signatureSentTo("https://cdn.other.test/robots.txt")).toBeNull();
  });

  it("never fetches sitemaps on hosts that resolve to private addresses", async () => {
    setHostAddressResolverForTesting(async (host) =>
      host === "store.example.com" ? ["93.184.215.14"] : ["172.18.0.4"],
    );
    vi.mocked(fetch).mockImplementation((input) => {
      if (input === "https://store.example.com/robots.txt") {
        return Promise.resolve(
          new Response(
            "User-agent: *\nSitemap: https://internal.example/sitemap.xml\nSitemap: http://openseo:3001/sitemap.xml\n",
            { status: 200 },
          ),
        );
      }
      return Promise.resolve(new Response("", { status: 404 }));
    });

    await discoverUrls("https://store.example.com", 10, access);

    const fetched = vi
      .mocked(fetch)
      .mock.calls.map((entry) => String(entry[0]));
    expect(fetched).toContain("https://store.example.com/robots.txt");
    expect(fetched.some((url) => url.includes("internal.example"))).toBe(false);
    expect(fetched.some((url) => url.includes("openseo"))).toBe(false);
  });
});
