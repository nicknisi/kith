export function dispatchAuthKitEvent(name: string, detail?: unknown): void {
  document.dispatchEvent(
    new CustomEvent(`authkit:${name}`, {
      detail,
      bubbles: true,
    }),
  );
}
