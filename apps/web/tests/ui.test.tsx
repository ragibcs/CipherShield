import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Badge, Button, EmptyBox, ErrorBox, StatCard } from "@/components/ui";

describe("UI primitives", () => {
  it("badge renders icon and text (never color alone)", () => {
    render(
      <Badge tone="ok" icon={<svg aria-hidden data-testid="icon" />}>
        verified
      </Badge>,
    );
    expect(screen.getByTestId("icon")).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
  });

  it("stat card shows label, value, and hint", () => {
    render(
      <StatCard label="Vault records" value={4} hint="AES-256-GCM" />,
    );
    expect(screen.getByText("Vault records")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("AES-256-GCM")).toBeInTheDocument();
  });

  it("error box is announced as an alert", () => {
    render(<ErrorBox message="Blocked by policy." />);
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Blocked by policy.");
  });

  it("button disables while loading", () => {
    render(<Button loading>Run</Button>);
    expect(screen.getByRole("button", { name: /run/i })).toBeDisabled();
  });

  it("empty box explains what to do next", () => {
    render(<EmptyBox message="Run the evaluation script to generate metrics." />);
    expect(
      screen.getByText(/evaluation script/i),
    ).toBeInTheDocument();
  });
});
