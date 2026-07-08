/*

  JSON VIEW — a hand-rolled, dependency-free JSON renderer

  The bare `<pre>{JSON.stringify(x, null, 2)}</pre>` dumps the payload with its
  strings ESCAPED — a multi-line body or a markdown post reads as one endless
  `line1\nline2\n…` run, and long values are truncated at an arbitrary char cap.
  This renders the same value as a collapsible, syntax-coloured tree: multi-line
  strings become indented blocks with REAL newlines, `did:dfos:` and CID-shaped
  strings linkify, and a "raw json" toggle still shows the uncapped
  `JSON.stringify` for copy/paste. No new deps — it's ~120 lines of Preact.

*/

import { useState } from 'preact/hooks';
import { DidLink, TruncId } from './ui';

// did:dfos:<chain> — safe to route to the identity view.
const DID_RE = /^did:dfos:[a-z0-9]+$/i;
// CID-shaped: a long base32-ish token. Rendered copyable (TruncId) rather than
// routed — a bare CID in a payload is as often a document/media hash (no chain
// route) as an op CID, so a link would mislead more than it helps.
const CID_RE = /^[a-z2-7]{46,}$/i;

/** How deep to auto-expand before a node renders collapsed. Payloads are small;
 *  documents nest a level or two — expanding the top keeps the shape visible. */
const AUTO_OPEN_DEPTH = 2;
const INDENT_PX = 14;

const Scalar = (props: { value: string | number | boolean | null }) => {
  const v = props.value;
  if (v === null) return <span class="jv-null">null</span>;
  if (typeof v === 'boolean') return <span class="jv-bool">{String(v)}</span>;
  if (typeof v === 'number') return <span class="jv-num">{String(v)}</span>;
  if (DID_RE.test(v)) return <DidLink did={v} />;
  if (CID_RE.test(v)) return <TruncId value={v} />;
  // real newlines: the whole point — an escaped `\n` run becomes a block.
  if (v.includes('\n')) return <pre class="jv-multiline">{v}</pre>;
  return <span class="jv-str">"{v}"</span>;
};

const Node = (props: { name?: string | undefined; value: unknown; depth: number }) => {
  const { value, depth } = props;
  const container = typeof value === 'object' && value !== null;
  const [open, setOpen] = useState(depth < AUTO_OPEN_DEPTH);
  const pad = { paddingLeft: depth * INDENT_PX };
  const key = props.name !== undefined ? <span class="jv-key">{props.name}: </span> : null;

  if (!container) {
    return (
      <div class="jv-row" style={pad}>
        {key}
        <Scalar value={value as string | number | boolean | null} />
      </div>
    );
  }

  const arr = Array.isArray(value);
  const entries: [string, unknown][] = arr
    ? (value as unknown[]).map((v, i) => [String(i), v])
    : Object.entries(value as Record<string, unknown>);
  const [openBr, closeBr] = arr ? ['[', ']'] : ['{', '}'];
  const count = `${entries.length} ${arr ? (entries.length === 1 ? 'item' : 'items') : entries.length === 1 ? 'key' : 'keys'}`;

  return (
    <div class="jv-node">
      <div class="jv-row jv-toggle" style={pad} onClick={() => setOpen((o) => !o)}>
        <span class="jv-caret">{open ? '▾' : '▸'}</span>
        {key}
        <span class="jv-punct">{openBr}</span>
        {open ? null : (
          <span class="jv-collapsed">
            {' '}
            {count} <span class="jv-punct">{closeBr}</span>
          </span>
        )}
      </div>
      {open ? (
        <>
          {entries.map(([k, v]) => (
            <Node key={k} name={arr ? undefined : k} value={v} depth={depth + 1} />
          ))}
          <div class="jv-row jv-punct" style={pad}>
            {closeBr}
          </div>
        </>
      ) : null}
    </div>
  );
};

/**
 * Render `value` as a collapsible syntax-coloured tree with a raw-json escape
 * hatch. `label` names the raw toggle's context (default "raw json").
 */
export const JsonView = (props: { value: unknown; label?: string }) => {
  const [raw, setRaw] = useState(false);
  return (
    <div class="jsonview">
      <div class="jv-bar">
        <button class={raw ? '' : 'on'} onClick={() => setRaw(false)}>
          tree
        </button>
        <button class={raw ? 'on' : ''} onClick={() => setRaw(true)}>
          {props.label ?? 'raw json'}
        </button>
      </div>
      {raw ? (
        <pre class="jv-raw">{JSON.stringify(props.value, null, 2)}</pre>
      ) : (
        <div class="jv-tree">
          <Node value={props.value} depth={0} />
        </div>
      )}
    </div>
  );
};
