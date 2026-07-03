/*

  PROFILE CARD — render a profile/v1 doc as a legible header

  Name, avatar, description with a verify pill that stays honest: a profile is
  "verified" only when its carrier proved out (artifact signature for a relay,
  bytes→committed-CID for an anchored content chain). The avatar image is shown
  ONLY when the fetched bytes re-hash to the committed cid — never mismatched
  bytes dressed up as someone's face.

*/

import type { ComponentChildren } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { rawCidOf, safeHttpUrl, type MediaObject } from '../lib/media';
import { Pill } from './ui';

const AVATAR_MAX_BYTES = 4 * 1024 * 1024;

/** Small verified-bytes avatar: previews only when bytes match the committed cid. */
const Avatar = (props: { media: MediaObject | null | undefined; fallback: string }) => {
  const media = props.media;
  const safeHref = safeHttpUrl(media?.href);
  const [objectUrl, setObjectUrl] = useState<string | null>(null);

  useEffect(() => {
    let dead = false;
    let url: string | undefined;
    setObjectUrl(null);
    if (!media || !safeHref || !media.cid) return;
    void (async () => {
      try {
        const res = await fetch(safeHref, { mode: 'cors', signal: AbortSignal.timeout(20000) });
        if (!res.ok) return;
        const declared = Number(res.headers.get('content-length') ?? '0');
        if (declared > AVATAR_MAX_BYTES) return;
        const bytes = new Uint8Array(await res.arrayBuffer());
        if (bytes.length > AVATAR_MAX_BYTES) return;
        const type = res.headers.get('content-type') ?? '';
        // integrity gate — bytes MUST re-hash to the committed cid to render
        if (!type.startsWith('image/') || (await rawCidOf(bytes)) !== media.cid) return;
        url = URL.createObjectURL(new Blob([bytes.slice().buffer], { type }));
        if (!dead) setObjectUrl(url);
      } catch {
        // no verified image — fall back to the glyph
      }
    })();
    return () => {
      dead = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [media, safeHref]);

  return (
    <div class="avatar">
      {objectUrl ? (
        <img src={objectUrl} alt="avatar (verified bytes)" />
      ) : (
        <span class="avatar-glyph">{(props.fallback || '·').slice(0, 1).toUpperCase()}</span>
      )}
    </div>
  );
};

export type ProfileVerify = 'verified' | 'relay-asserted' | 'unverified' | 'pending';

const VERIFY_PILL: Record<
  ProfileVerify,
  { state: 'ok' | 'warn' | 'bad' | 'pending'; text: string }
> = {
  verified: { state: 'ok', text: 'verified' },
  'relay-asserted': { state: 'warn', text: 'relay-asserted' },
  unverified: { state: 'bad', text: 'unverified' },
  pending: { state: 'pending', text: 'verifying…' },
};

export const ProfileCard = (props: {
  name?: string | undefined;
  description?: string | undefined;
  avatar?: MediaObject | null | undefined;
  verify: ProfileVerify;
  publicRead?: boolean | undefined;
  meta?: ComponentChildren | undefined;
}) => {
  const pill = VERIFY_PILL[props.verify];
  const name = props.name?.trim() || 'unnamed';
  return (
    <div class="profile-card">
      <Avatar media={props.avatar} fallback={name} />
      <div class="profile-body">
        <div class="profile-name">
          <b>{name}</b>
          <Pill state={pill.state}>{pill.text}</Pill>
          {props.publicRead ? <Pill state="ok">public</Pill> : null}
        </div>
        {props.description ? <div class="profile-desc">{props.description}</div> : null}
        {props.meta ? <div class="profile-meta">{props.meta}</div> : null}
      </div>
    </div>
  );
};
