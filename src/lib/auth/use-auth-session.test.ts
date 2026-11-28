import { beforeEach, describe, expect, it, vi } from "vitest";

const fetchMock = vi.fn();
vi.stubGlobal("fetch", fetchMock);

let hookIndex = 0;
const states: unknown[] = [];
const setters: Array<(value: unknown) => void> = [];

vi.mock("react", async () => {
  const original = await vi.importActual<typeof import("react")>("react");
  return {
    ...original,
    useState: (initialValue: unknown) => {
      const currentIndex = hookIndex;
      hookIndex += 1;
      if (states.length <= currentIndex) {
        states.push(typeof initialValue === "function" ? (initialValue as () => unknown)() : initialValue);
        setters.push((newValue: unknown) => {
          states[currentIndex] =
            typeof newValue === "function"
              ? (newValue as (prev: unknown) => unknown)(states[currentIndex])
              : newValue;
        });
      }
      return [states[currentIndex], setters[currentIndex]];
    },
    useEffect: () => undefined,
    useCallback: (fn: unknown, deps: unknown) => {
      if (!Array.isArray(deps)) {
        throw new Error("useCallback requires a dependency array");
      }
      return fn;
    },
  };
});

import { useAuthSession } from "@/lib/auth/use-auth-session";

const WALLET = `G${"A".repeat(55)}`;

function renderSession() {
  hookIndex = 0;
  // react is mocked above (useState and friends are replaced), so this is not a real render
  // and the hook can be called directly from this test helper.
  // eslint-disable-next-line react-hooks/rules-of-hooks
  return useAuthSession();
}

describe("useAuthSession refresh", () => {
  beforeEach(() => {
    hookIndex = 0;
    states.length = 0;
    setters.length = 0;
    fetchMock.mockReset();
  });

  it("applies each repeated refresh without reopening the callback", async () => {
    fetchMock
      .mockResolvedValueOnce({
        json: async () => ({
          authenticated: true,
          user: {
            email: `wallet:${WALLET}`,
            role: "operator",
            userId: "operator-1",
            exp: 4_000_000_000,
          },
        }),
      })
      .mockResolvedValueOnce({
        json: async () => ({ authenticated: false }),
      });

    await renderSession().refresh();
    const authenticated = renderSession();
    expect(authenticated.authenticated).toBe(true);
    expect(authenticated.role).toBe("operator");
    expect(authenticated.wallet).toBe(WALLET);

    await authenticated.refresh();
    const signedOut = renderSession();
    expect(signedOut.authenticated).toBe(false);
    expect(signedOut.email).toBeNull();
    expect(signedOut.role).toBeNull();
    expect(signedOut.wallet).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/auth/session");
    expect(fetchMock.mock.calls[1]?.[0]).toBe("/api/auth/session");
  });
});
