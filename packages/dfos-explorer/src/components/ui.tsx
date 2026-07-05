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
  /** leading trust rule on the header: ok = locally verified, warn = relay-asserted. */
  accent?: 'ok' | 'warn' | 'bad' | undefined;
  children: ComponentChildren;
}) => (
  <div class={props.accent ? `panel acc-${props.accent}` : 'panel'}>
    <h2>
      <span>{props.title}</span>
      {props.right ? <span class="panel-right">{props.right}</span> : null}
    </h2>
    {props.orient ? <div class="orient">{props.orient}</div> : null}
    <div class={props.pad === false ? 'body flush' : 'body'}>{props.children}</div>
  </div>
);

// -----------------------------------------------------------------------------
// trust badge — verified/active = filled ok, attributed = hollow amber,
// revoked/mismatch = filled bad. The one vocabulary for status labels.
// -----------------------------------------------------------------------------

export const Badge = (props: {
  state: 'ok' | 'bad' | 'warn' | 'neutral';
  children: ComponentChildren;
}) => <span class={`badge ${props.state}`}>{props.children}</span>;

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

/**
 * Credential active/revoked chip. `revokedByOp` is the CID of a synced
 * revocation op that names this credential (from the local revocation fold);
 * when present the chip is red and links to that op, else green "active".
 * Relay-asserted until opened — the credential view re-verifies any proof.
 */
export const CredStatus = (props: { revokedByOp?: string | undefined }) =>
  props.revokedByOp ? (
    <a href={`#/op/${props.revokedByOp}`} class="ck bad" title="revoked — open the revocation op">
      revoked
    </a>
  ) : (
    <span class="ck ok">active</span>
  );

/**
 * Middle-truncated identifier with click-to-copy + a full-value title. The one
 * component for rendering a raw id (DID / CID / contentId) inline — swept across
 * the detail views so every bare identifier copies the same way.
 */
export const TruncId = (props: { value: string; head?: number; tail?: number }) => {
  const [copied, setCopied] = useState(false);
  return (
    <span
      class="cid"
      title={`${props.value} — click to copy`}
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

/** Back-compat alias — {@link TruncId} is the canonical name. */
export const Copyable = TruncId;

// -----------------------------------------------------------------------------
// related — the detail-page crosslink panel. Full-width detail pages trade the
// global sidebar for a compact navigational block built from data already
// loaded (no new fetches): who/what this primitive connects to.
// -----------------------------------------------------------------------------

export const Related = (props: { rows: { k: ComponentChildren; v: ComponentChildren }[] }) => {
  const rows = props.rows.filter((r) => r.v != null && r.v !== false);
  if (rows.length === 0) return null;
  return (
    <Panel title="related">
      <div class="kv related">
        {rows.map((r, i) => (
          <>
            <div key={`k${i}`} class="k">
              {r.k}
            </div>
            <div key={`v${i}`} class="v">
              {r.v}
            </div>
          </>
        ))}
      </div>
    </Panel>
  );
};
