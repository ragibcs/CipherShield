import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// React Testing Library only auto-registers cleanup when test globals are
// enabled; we import from `vitest` explicitly, so wire it up here.
afterEach(() => {
  cleanup();
});
