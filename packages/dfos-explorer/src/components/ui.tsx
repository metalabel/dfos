/*

  UI PRIMITIVES — panels, pills, key/value grids, term tooltips, links

  Everything is deliberately flat and boring: hairline borders, dense
  monospace, no chrome. The interesting part is the vocabulary — verify pills,
  relay-asserted labels, term definitions — not the widgets.

*/

import type { ComponentChildren } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { copyToClipboard, short } from '../lib/format';

// -----------------------------------------------------------------------------
// panel
// -----------------------------------------------------------------------------

export const Panel = (props: {
  title: ComponentChildren;
  right?: ComponentChildren;
  orient?: ComponentChildren;
  pad?: boolean;
  children: ComponentChildren;
}) => (
  <div class="panel">
    <h2>
      <span>{props.title}</span>
      {props.right ? <span class="panel-right">{props.right}</span> : null}
    </h2>
    {props.orient ? <div class="orient">{props.orient}</div> : null}
    <div class={props.pad === false ? 'body flush' : 'body'}>{props.children}</div>
  </div>
);

// -----------------------------------------------------------------------------
// verify pill
// -----------------------------------------------------------------------------

export type PillState = 'pending' | 'ok' | 'bad' | 'warn';

export const Pill = (props: { state: PillState; children: ComponentChildren }) => (
  <span class={`pill ${props.state}`}>
    {props.state === 'pending' ? <span class="spin">◍</span> : null}
    {props.children}
  </span>
);

// -----------------------------------------------------------------------------
// key/value grid
// -----------------------------------------------------------------------------

export const Kv = (props: { children: ComponentChildren }) => (
  <div class="kv">{props.children}</div>
);

export const KvRow = (props: {
  k: ComponentChildren;
  note?: string;
  children: ComponentChildren;
}) => (
  <>
    <div class="k">
      {props.k}
      {props.note ? <span class="lbl kv-note"> {props.note}</span> : null}
    </div>
    <div class="v">{props.children}</div>
  </>
);

// -----------------------------------------------------------------------------
// term tooltip — dotted underline; click/tap pins the definition to the termbar
// -----------------------------------------------------------------------------

type TermPin = { word: string; def: string } | null;
type TermListener = (pin: TermPin) => void;

const termListeners = new Set<TermListener>();

export const pinTerm = (word: string, def: string): void => {
  for (const fn of termListeners) fn({ word, def });
};

export const Term = (props: { word: string; def: string }) => (
  <span
    class="term"
    tabIndex={0}
    role="button"
    title={props.def}
    aria-label={`${props.word}: ${props.def}`}
    onClick={() => pinTerm(props.word, props.def)}
    onKeyDown={(e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        pinTerm(props.word, props.def);
      }
    }}
  >
    {props.word}
  </span>
);

/** Bottom-pinned definition bar — the touch answer to title= tooltips. */
export const TermBar = () => {
  const [pin, setPin] = useState<TermPin>(null);
  useEffect(() => {
    const fn: TermListener = (p) => setPin(p);
    termListeners.add(fn);
    return () => {
      termListeners.delete(fn);
    };
  }, []);
  if (!pin) return null;
  return (
    <div class="termbar">
      <span class="termbar-x" onClick={() => setPin(null)}>
        ✕ dismiss
      </span>
      <span>
        <b>{pin.word}</b> — {pin.def}
      </span>
    </div>
  );
};

// -----------------------------------------------------------------------------
// links
// -----------------------------------------------------------------------------

export const DidLink = (props: { did: string; full?: boolean }) => (
  <a href={`#/did/${props.did}`} title={props.did}>
    {props.full ? props.did : short(props.did, 14, 6)}
  </a>
);

export const ContentLink = (props: { id: string; full?: boolean }) => (
  <a href={`#/content/${props.id}`} title={props.id}>
    {props.full ? props.id : short(props.id, 14, 6)}
  </a>
);

export const OpLink = (props: { cid: string; full?: boolean }) => (
  <a href={`#/op/${props.cid}`} class="cid" title={props.cid}>
    {props.full ? props.cid : short(props.cid, 12, 8)}
  </a>
);

export const CredLink = (props: { cid: string }) => (
  <a href={`#/cred/${props.cid}`} class="cid" title={props.cid}>
    {short(props.cid, 12, 8)}
  </a>
);

/** kid → linked DID + fragment; genesis ops carry no kid. */
export const KidLink = (props: { kid: string }) => {
  const i = props.kid.indexOf('#');
  if (i <= 0)
    return (
      <span class="muted">
        {props.kid || ''} <span class="lbl">genesis key</span>
      </span>
    );
  return (
    <>
      <DidLink did={props.kid.slice(0, i)} />
      <span class="muted">#{props.kid.slice(i + 1)}</span>
    </>
  );
};

/** Click-to-copy identifier. */
export const Copyable = (props: { value: string; head?: number; tail?: number }) => {
  const [copied, setCopied] = useState(false);
  return (
    <span
      class="cid"
      title={props.value}
      onClick={() => {
        copyToClipboard(props.value);
        setCopied(true);
        setTimeout(() => setCopied(false), 900);
      }}
    >
      {copied ? 'copied ✓' : short(props.value, props.head ?? 12, props.tail ?? 8)}
    </span>
  );
};
