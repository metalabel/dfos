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
import { isAttachmentUri, rawCidOf, type MediaObject } from '../lib/media';
import { Copyable, Panel, Pill, Term } from './ui';

interface FetchState {
  status: 'ok' | 'failed';
  derivedCid?: string;
  objectUrl?: string;
  bytes?: number;
  mediaType?: string;
}

export const MediaPanel = (props: { title: string; media: MediaObject }) => {
  const { media } = props;
  const [fetched, setFetched] = useState<FetchState | null>(null);

  useEffect(() => {
    let dead = false;
    let url: string | undefined;
    setFetched(null);
    if (!media.href || !/^https?:\/\//.test(media.href)) return;
    void (async () => {
      try {
        const res = await fetch(media.href as string, {
          mode: 'cors',
          signal: AbortSignal.timeout(20000),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const bytes = new Uint8Array(await res.arrayBuffer());
        const derivedCid = await rawCidOf(bytes);
        const mediaType = res.headers.get('content-type') ?? '';
        if (mediaType.startsWith('image/')) {
          url = URL.createObjectURL(new Blob([bytes.slice().buffer], { type: mediaType }));
        }
        if (!dead)
          setFetched({
            status: 'ok',
            derivedCid,
            bytes: bytes.length,
            mediaType,
            ...(url ? { objectUrl: url } : {}),
          });
      } catch {
        if (!dead) setFetched({ status: 'failed' });
      }
    })();
    return () => {
      dead = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [media.uri, media.href, media.cid]);

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
              <a href={media.href} target="_blank" rel="noreferrer noopener">
                {short(media.href, 40, 12)}
              </a>
            </div>
          </>
        ) : null}
      </div>
      <div style={{ marginTop: 8 }}>
        {!media.href ? (
          <span class="ck-note">
            No fetch hint — bytes are not addressable from here.{' '}
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
