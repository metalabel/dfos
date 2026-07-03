/*

  HOME — orientation + samples

*/

import { Panel, Term } from '../components/ui';
import { GLOSSARY } from '../lib/glossary';

const SAMPLES: { label: string; q: string }[] = [
  { label: 'identity', q: 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e' },
  { label: 'public content', q: 'dn2nc79k7z6ekzfhd43he4v8tr6h236' },
  { label: 'issuer (has credential)', q: 'did:dfos:tz49rzd68z98dfvre622nv2ta3a28vt' },
];

export const Home = (props: { onSample: (q: string) => void }) => (
  <>
    <Panel
      title="explorer"
      orient={
        <>
          Paste a <Term word="DID" def={GLOSSARY['did'] ?? ''} />, a contentId, or an operation{' '}
          <Term word="CID" def={GLOSSARY['cid'] ?? ''} /> above. Everything is fetched over plain
          HTTP from untrusted relays and <b>re-verified in your browser</b> — speed from the relay,
          truth from the math.
        </>
      }
    >
      <div class="placeholder">
        <div class="samples" style={{ justifyContent: 'center', marginBottom: 10 }}>
          <span class="lbl">try</span>
          {SAMPLES.map((s) => (
            <span key={s.q} class="chip" onClick={() => props.onSample(s.q)}>
              {s.label}
            </span>
          ))}
        </div>
        <span class="muted">
          Or sync the full log and click a row in the local index. New here? Read the{' '}
          <a href="#/glossary">glossary</a>.
        </span>
      </div>
    </Panel>
    <Panel title="what this is">
      <div class="kv" style={{ gridTemplateColumns: 'minmax(90px, 120px) 1fr', gap: '8px 12px' }}>
        <div class="k">no backend</div>
        <div class="v muted">
          A static page. Relays are swappable parameters, like RPC endpoints — never authorities.
        </div>
        <div class="k">verify-in-tab</div>
        <div class="v muted">
          Signatures, CIDs, and chain linkage are recomputed locally via{' '}
          <code>@metalabel/dfos-client</code>. The relay's claims render first, then flip to
          verified (or MISMATCH — loudly).
        </div>
        <div class="k">local db</div>
        <div class="v muted">
          The full operation log syncs into IndexedDB in your browser. Chains fold offline; your
          index persists across visits.
        </div>
        <div class="k">no canonical state</div>
        <div class="v muted">
          Completeness is outside the proof. You are seeing what these relays hold — another relay
          may hold more, less, or a fork.
        </div>
      </div>
    </Panel>
  </>
);
