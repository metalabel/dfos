/*

  VERIFICATION CHECKLIST — the ladder of PASS/FAIL rows under every view

*/

import type { ComponentChildren } from 'preact';

export type CheckState = 'ok' | 'bad' | 'warn' | 'pend';

const GLYPH: Record<CheckState, string> = { ok: '✓', bad: '✗', warn: '⚠', pend: '·' };

export const Check = (props: {
  state: CheckState;
  note?: string | undefined;
  children: ComponentChildren;
}) => (
  <li>
    <span class={`ck ${props.state}`}>{GLYPH[props.state]}</span>
    <span class="ck-txt">
      {props.children}
      {props.note ? <span class="ck-note"> — {props.note}</span> : null}
    </span>
  </li>
);

export const Checks = (props: { children: ComponentChildren }) => (
  <ul class="checks">{props.children}</ul>
);
