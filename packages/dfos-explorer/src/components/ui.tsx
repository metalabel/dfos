/*

  UI PRIMITIVES — panels, pills, key/value grids, term tooltips, links

  Everything is deliberately flat and boring: hairline borders, dense
  monospace, no chrome. The interesting part is the vocabulary — verify pills,
  relay-asserted labels, term definitions — not the widgets.

*/

import type { ComponentChildren } from 'preact';
import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { useDidProfile } from '../lib/did-profiles';
import { copyToClipboard, short } from '../lib/format';
import type { RevocationStatus } from '../lib/revocations';

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

/**
 * A verdict pill. `def` adds the PLAIN-LANGUAGE layer without touching the
 * verdict: the precise word stays the label — "stale", not "probably fine" — and
 * the plain rendering is one hover or tap away, through exactly the interaction
 * {@link Term} already implements (title tooltip, definition modal on tap). The
 * precise vocabulary is what stays machine-distinguishable; the plain sentence is
 * what makes it legible to someone who has never read the spec. Neither replaces
 * the other.
 */
export const Pill = (props: {
  state: PillState;
  /** plain-language rendering of this verdict — makes the pill a Term affordance */
  def?: string | undefined;
  /** what to pin as the term; defaults to the pill's own text */
  word?: string | undefined;
  children: ComponentChildren;
}) => {
  const spinner = props.state === 'pending' ? <span class="spin">◍</span> : null;
  const def = props.def;
  if (!def)
    return (
      <span class={`pill ${props.state}`}>
        {spinner}
        {props.children}
      </span>
    );
  const word = props.word ?? (typeof props.children === 'string' ? props.children : '');
  return (
    <span
      class={`pill ${props.state} defined`}
      tabIndex={0}
      role="button"
      title={def}
      aria-label={`${word}: ${def}`}
      onClick={() => pinTerm(word, def)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          pinTerm(word, def);
        }
      }}
    >
      {spinner}
      <span class="pill-word">{props.children}</span>
    </span>
  );
};

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
// term tooltip — dotted underline; click/tap opens the definition modal
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

/** Anything that can hold focus inside the dialog — the trap's ring. */
const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * TERM MODAL — the plain-language layer, one tap away.
 *
 * Mounted ONCE, at the app root; {@link pinTerm} (the same call {@link Term} and
 * a defined {@link Pill} have always made) is what opens it. A term tapped while
 * it is already open REPLACES the content rather than stacking — there is only
 * ever one definition on screen.
 *
 * Presentation: a fullscreen sheet on mobile, a centered shadowboxed panel at
 * width — one component, one CSS breakpoint.
 *
 * Interaction contract: dismiss by Escape, backdrop click, or the close button.
 * While open, focus moves into the dialog, Tab is trapped inside it, and closing
 * restores focus to whatever was focused when it opened; body scroll is locked.
 * `role="dialog"` + `aria-modal` + `aria-labelledby` the term word.
 */
export const TermModal = () => {
  const [pin, setPin] = useState<TermPin>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  // where focus came from — captured on OPEN only, so a replace-while-open still
  // returns focus to the element that started the interaction
  const restoreRef = useRef<HTMLElement | null>(null);
  const openRef = useRef(false);

  useEffect(() => {
    const fn: TermListener = (p) => {
      if (p && !openRef.current) {
        const active = document.activeElement;
        restoreRef.current = active instanceof HTMLElement ? active : null;
      }
      openRef.current = p !== null;
      setPin(p);
    };
    termListeners.add(fn);
    return () => {
      termListeners.delete(fn);
    };
  }, []);

  const close = useCallback(() => {
    openRef.current = false;
    setPin(null);
  }, []);

  const open = pin !== null;

  useEffect(() => {
    if (!open) return;
    const panel = panelRef.current;
    panel?.querySelector<HTMLElement>('.termmodal-x')?.focus();

    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
        return;
      }
      if (e.key !== 'Tab' || !panel) return;
      const ring = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (ring.length === 0) {
        e.preventDefault();
        return;
      }
      const first = ring[0] as HTMLElement;
      const last = ring[ring.length - 1] as HTMLElement;
      const active = document.activeElement;
      const inside = active instanceof Node && panel.contains(active);
      if (e.shiftKey ? !inside || active === first : !inside || active === last) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
      }
    };
    // capture, so the trap wins over anything the page binds on keydown
    document.addEventListener('keydown', onKey, true);

    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.removeEventListener('keydown', onKey, true);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, close]);

  // restore focus on close (a no-op on first mount — nothing was captured yet)
  useEffect(() => {
    if (open) return;
    const el = restoreRef.current;
    restoreRef.current = null;
    el?.focus();
  }, [open]);

  if (!pin) return null;
  return (
    <div
      class="termmodal"
      onClick={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <div
        class="termmodal-panel"
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="termmodal-word"
      >
        <div class="termmodal-hd">
          <span class="lbl">definition</span>
          <button class="termmodal-x" onClick={close}>
            ✕ close
          </button>
        </div>
        <div class="termmodal-body">
          <div class="termmodal-word" id="termmodal-word">
            {pin.word}
          </div>
          <p class="termmodal-def">{pin.def}</p>
        </div>
      </div>
    </div>
  );
};

// -----------------------------------------------------------------------------
// pager — the footer of every keyset-paged surface
//
// A relay index serves a KEYSET cursor, not offsets: there is no "page 7", and
// the only honest back is the cursor you walked in on. So the controls are
// first / prev / next, `prev` disabled on a page reached by a deep link (we know
// we're not at the start — that's `offFirst` — but not what came before it).
// -----------------------------------------------------------------------------

export const Pager = (props: {
  /** rows on THIS page — never a corpus total (completeness is outside the proof). */
  count: number;
  noun: string;
  loading: boolean;
  hasNext: boolean;
  hasPrev: boolean;
  offFirst: boolean;
  onFirst: () => void;
  onPrev: () => void;
  onNext: () => void;
}) => (
  <div class="pager">
    <button disabled={!props.offFirst || props.loading} onClick={props.onFirst}>
      ⇤ first
    </button>
    <button disabled={!props.hasPrev || props.loading} onClick={props.onPrev}>
      ‹ prev
    </button>
    <button disabled={!props.hasNext || props.loading} onClick={props.onNext}>
      next ›
    </button>
    <span class="lbl">
      {props.loading
        ? 'loading…'
        : `${props.count} ${props.noun}${props.offFirst ? ' · paged' : ''}`}
    </span>
  </div>
);

// -----------------------------------------------------------------------------
// docs — the one place the SIWD guide slugs live
//
// A verdict says what was observed; it never says what to do about it. These two
// links are the whole action layer, and both detail views point at them from
// every amber and red state — so a visitor who reads "stale" is one click from
// what that means, and a domain owner is one click from the fix.
// -----------------------------------------------------------------------------

export const SETUP_GUIDE = 'https://docs.dfos.com/docs/developers/sign-in-with-dfos/setup';
export const TROUBLESHOOTING_GUIDE =
  'https://docs.dfos.com/docs/developers/sign-in-with-dfos/troubleshooting';

/** An external docs link — new tab, no referrer. */
export const DocsLink = (props: { href: string; children: ComponentChildren }) => (
  <a href={props.href} rel="noreferrer noopener" target="_blank">
    {props.children}
  </a>
);

// -----------------------------------------------------------------------------
// links
// -----------------------------------------------------------------------------

/** A DID, linked — and resolved JIT to its PUBLIC profile name wherever one
 *  exists (lib/did-profiles.ts): the relay index's projection renders first in
 *  the amber `.attr` tier, replaced by the chain-verified name in plain ink.
 *  `plain` opts out for byte-accurate surfaces (json-view); `full` keeps the
 *  literal DID visible next to the name on detail surfaces. */
export const DidLink = (props: { did: string; full?: boolean; plain?: boolean }) => {
  const { profile, tier } = useDidProfile(props.did, !props.plain);
  if (props.plain || !profile) {
    return (
      <a href={`#/did/${props.did}`} title={props.did}>
        {props.full ? props.did : short(props.did, 14, 6)}
      </a>
    );
  }

  const title =
    tier === 'verified'
      ? `${props.did} — public profile, verified in your tab`
      : `${props.did} — name projected by the relay index (attributed); verifying…`;
  return (
    <a href={`#/did/${props.did}`} title={title}>
      <span class={tier === 'verified' ? 'did-name' : 'attr'}>{profile.name}</span>
      {props.full ? (
        <>
          {' '}
          <span class="muted">{props.did}</span>
        </>
      ) : null}
    </a>
  );
};

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
 * Credential status chip — THREE states, because absence is not proof (see
 * lib/revocations.ts). Red "revoked" links to the revoking op when its CID is
 * known; green "active" is licensed ONLY by a completed sweep of the relay set;
 * anything unswept is amber "unknown" and never green. Relay-asserted until
 * opened — the credential view re-verifies any proof.
 */
export const CredStatus = (props: {
  status: RevocationStatus;
  revokedByOp?: string | undefined;
}) => {
  if (props.status === 'revoked') {
    return props.revokedByOp ? (
      <a href={`#/op/${props.revokedByOp}`} class="ck bad" title="revoked — open the revocation op">
        revoked
      </a>
    ) : (
      <span class="ck bad" title="a relay served a revocation for this credential">
        revoked
      </span>
    );
  }
  if (props.status === 'unknown') {
    return (
      <span
        class="ck warn"
        title="no relay answered for this credential — its status is unknown, which is NOT the same as active"
      >
        unknown
      </span>
    );
  }
  return (
    <span class="ck ok" title="no relay we asked holds a revocation — absence is not proof">
      active
    </span>
  );
};

/**
 * Middle-truncated identifier with click-to-copy + a full-value title. The one
 * component for rendering a raw id (DID / CID / contentId) inline — swept across
 * the detail views so every bare identifier copies the same way.
 */
export const TruncId = (props: { value: string; head?: number; tail?: number }) => {
  const [copied, setCopied] = useState(false);
  // `copyable` renders a hover copy glyph so a bare identifier reads as clickable;
  // `copied` suppresses that glyph while the "copied ✓" confirmation shows.
  return (
    <span
      class={copied ? 'cid copyable copied' : 'cid copyable'}
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
