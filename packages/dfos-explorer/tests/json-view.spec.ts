import { describe, expect, it } from 'vitest';
import { capEntries, ENTRY_CAP } from '../src/components/json-view';

// Guards the DOM-explosion cap: JsonView renders untrusted relay document bytes
// (up to 16MB), so a single node must never paint more than ENTRY_CAP entries at
// once — capEntries is the pure slice that enforces it.
describe('capEntries', () => {
  const many = Array.from({ length: 250 }, (_, i) => i);

  it('caps the visible entries and reports the hidden remainder', () => {
    const { visible, hidden } = capEntries(many, ENTRY_CAP);
    expect(visible).toHaveLength(ENTRY_CAP);
    expect(hidden).toBe(250 - ENTRY_CAP);
    expect(visible[0]).toBe(0);
    expect(visible[ENTRY_CAP - 1]).toBe(ENTRY_CAP - 1);
  });

  it('reveals the next batch as shown grows', () => {
    const { visible, hidden } = capEntries(many, ENTRY_CAP * 2);
    expect(visible).toHaveLength(ENTRY_CAP * 2);
    expect(hidden).toBe(250 - ENTRY_CAP * 2);
  });

  it('hides nothing once shown covers every entry', () => {
    const { visible, hidden } = capEntries(many, 1000);
    expect(visible).toHaveLength(250);
    expect(hidden).toBe(0);
  });

  it('pins a sane default cap', () => {
    expect(ENTRY_CAP).toBe(100);
  });
});
