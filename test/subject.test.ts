import { describe, expect, it } from "vitest";
import { makeSignature } from "better-auth/crypto";
import { pairwiseSub, sectorOf } from "../lib/subject";

/**
 * Pinned. If this literal ever has to change, every person's identifier in
 * every app changes with it: each app would meet strangers. Do not update the
 * literal to make the test pass — find what changed the derivation.
 */
const SECRET = "pinned-pairwise-secret-pinned-pairwise-secret";
const SECTOR = "heidi.orangecat.ch";
const USER = "user_0001";
const PINNED = "m3WHe/cShFoAQJRw97b8ZR2x2/jg4L7yo4TXEmCtr28=";
const WORK = "life_6f1c2b9e-3d4a-4e5f-8a7b-0c1d2e3f4a5b";
const HOME = "life_0a9b8c7d-6e5f-4a3b-9c2d-1e0f9a8b7c6d";

describe("pairwiseSub", () => {
  it("gives today's subject, pinned to a literal", () => {
    expect(pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER })).toBe(PINNED);
  });

  it("agrees with the signature @better-auth/oauth-provider issues today", async () => {
    // oauth-provider: makeSignature(`${sector}.${userId}`, pairwiseSecret)
    expect(await makeSignature(`${SECTOR}.${USER}`, SECRET)).toBe(PINNED);
  });

  it("gives the root persona exactly today's subject", () => {
    expect(pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: undefined })).toBe(PINNED);
    expect(pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: USER })).toBe(PINNED);
  });

  it("gives a life_<uuid> persona its own stable subject, different per life and per app", () => {
    const work = pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: WORK });
    const home = pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: HOME });
    expect(work).not.toBe(PINNED);
    expect(home).not.toBe(work);
    expect(pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: WORK })).toBe(work);
    expect(pairwiseSub({ secret: SECRET, sector: "solon.orangecat.ch", userId: USER, persona: WORK })).not.toBe(work);
  });

  it("refuses, never hashes, a persona that looks like a user id but is not this user's", () => {
    expect(() => pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: "user_0002" })).toThrow(/life_<uuid>/);
    expect(() => pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: "Xk9qR2mT7vLp4sN8bW3cY6dF1gH5jA0e" })).toThrow();
  });

  it("refuses anything outside the life_ id space", () => {
    for (const persona of ["", "life_", "life_work", `LIFE_${WORK.slice(5)}`, `${WORK}|persona|x`, `x${WORK}`]) {
      expect(() => pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona }), persona).toThrow();
    }
  });

  it("keeps the pinned root value with life ids in play", () => {
    pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: WORK });
    expect(pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER })).toBe(PINNED);
    expect(pairwiseSub({ secret: SECRET, sector: SECTOR, userId: USER, persona: USER })).toBe(PINNED);
  });

  it("takes the sector from the redirect host, port included", () => {
    expect(sectorOf("https://heidi.orangecat.ch/api/auth/callback/bitbaum-signin")).toBe(SECTOR);
    expect(sectorOf("http://localhost:4201/api/auth/callback/bitbaum-signin")).toBe("localhost:4201");
  });
});
