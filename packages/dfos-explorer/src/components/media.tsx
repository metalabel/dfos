/*

  MEDIA PANEL — render a Media{uri, cid?, href?} object honestly

  attachment:// is an opaque host-scoped ref — not fetchable from here; the
  cid IS the integrity commitment. When an href hint exists, the bytes are
  fetched and re-hashed (CIDv1/raw/sha2-256) against the cid in the tab, and
  images preview inline from the verified bytes.

*/

import { useEffect, useState } from 'preact/hooks';
import { short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import {
  fetchBoundedBytes,
  isAttachmentUri,
  rawCidOf,
  safeHttpUrl,
  type MediaObject,
} from '../lib/media';
import { Copyable, Panel, Pill, Term } from './ui';

interface FetchState {
  status: 'ok' | 'failed';
  derivedCid?: string;
  objectUrl?: string;
  bytes?: number;
  mediaType?: string;
}

// hard cap on href-fetched media bytes — a hostile host must not OOM the tab
const MAX_MEDIA_BYTES = 8 * 1024 * 1024;

export const MediaPanel = (props: { title: string; media: MediaObject }) => {
  const { media } = props;
  const [fetched, setFetched] = useState<FetchState | null>(null);
  const safeHref = safeHttpUrl(media.href);

  useEffect(() => {
    let dead = false;
    let url: string | undefined;
    setFetched(null);
    if (!safeHref) return;
    void (async () => {
      // streaming byte-cap fetch — a hostile host cannot OOM the tab past the cap
      const fetched = await fetchBoundedBytes(safeHref, MAX_MEDIA_BYTES);
      if (dead) return;
      if (!fetched) {
        setFetched({ status: 'failed' });
        return;
      }
      const { bytes, mediaType } = fetched;
      const derivedCid = await rawCidOf(bytes);
      if (dead) return;
      // preview ONLY when the bytes provably match the committed cid — never
      // render mismatched bytes as the object's image
      let made: string | undefined;
      if (mediaType.startsWith('image/') && media.cid && derivedCid === media.cid) {
        made = URL.createObjectURL(new Blob([bytes.slice().buffer], { type: mediaType }));
        // the effect may have torn down during the awaits — revoke, don't leak
        if (dead) {
          URL.revokeObjectURL(made);
          return;
        }
        url = made;
      }
      setFetched({
        status: 'ok',
        derivedCid,
        bytes: bytes.length,
        mediaType,
        ...(made ? { objectUrl: made } : {}),
      });
    })();
    return () => {
      dead = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [media.uri, safeHref, media.cid]);

  const cidMatch = media.cid && fetched?.derivedCid ? media.cid === fetched.derivedCid : null;

  return (
    <Panel title={props.title} right={<span class="lbl">media object</span>}>
      <div class="kv">
        <div class="k">uri</div>
        <div class="v">
          {media.uri}
          {isAttachmentUri(media.uri) ? (
            <span class="ck-note"> — opaque host-scoped ref; the cid is the integrity</span>
          ) : null}
        </div>
        {media.cid ? (
          <>
            <div class="k">
              cid <span class="lbl">integrity commitment</span>
            </div>
            <div class="v">
              <Copyable value={media.cid} head={20} tail={8} />
              <span class="ck-note"> — CIDv1 · raw · sha2-256 over the bytes as served</span>
            </div>
          </>
        ) : null}
        {media.href ? (
          <>
            <div class="k">
              href <span class="lbl">non-normative hint</span>
            </div>
            <div class="v">
              {safeHref ? (
                <a href={safeHref} target="_blank" rel="noreferrer noopener">
                  {short(safeHref, 40, 12)}
                </a>
              ) : (
                <span class="err" title={media.href}>
                  {short(media.href, 40, 12)} <span class="lbl">— non-http scheme, not linked</span>
                </span>
              )}
            </div>
          </>
        ) : null}
      </div>
      <div style={{ marginTop: 8 }}>
        {!safeHref ? (
          <span class="ck-note">
            No usable fetch hint — bytes are not addressable from here.{' '}
            {media.cid
              ? 'Anyone who obtains the bytes can verify them against the cid above.'
              : 'Without a cid there is no integrity commitment at all — this ref is pure trust in the host.'}
          </span>
        ) : fetched === null ? (
          <span class="muted">fetching bytes via href…</span>
        ) : fetched.status === 'failed' ? (
          <Pill state="warn">href fetch failed — integrity not checkable from here</Pill>
        ) : (
          <>
            {cidMatch === true ? (
              <Pill state="ok">✓ fetched bytes re-hash to the committed cid</Pill>
            ) : cidMatch === false ? (
              <Pill state="bad">✗ fetched bytes ≠ committed cid — MISMATCH</Pill>
            ) : (
              <Pill state="warn">fetched · no cid to verify against</Pill>
            )}{' '}
            <span class="lbl">
              {fetched.bytes} bytes{fetched.mediaType ? ` · ${fetched.mediaType}` : ''}
            </span>
            {fetched.objectUrl ? (
              <div style={{ marginTop: 8 }}>
                <img
                  src={fetched.objectUrl}
                  alt="media preview (verified bytes)"
                  style={{ maxWidth: 160, maxHeight: 160, border: '1px solid var(--line)' }}
                />
              </div>
            ) : null}
          </>
        )}
      </div>
      <div class="ck-note" style={{ marginTop: 8 }}>
        <Term word="media" def={GLOSSARY['media'] ?? ''} />
      </div>
    </Panel>
  );
};
