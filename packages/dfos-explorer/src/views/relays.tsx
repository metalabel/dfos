/*

  RELAYS — manage the untrusted relay set

  Reads fan out across every relay here; the client reports which one answered
  and whether the set agreed. Health chips are live /.well-known probes.

*/

import type { RelayHealth } from '@metalabel/dfos-client';
import { useEffect, useState } from 'preact/hooks';
import { Panel } from '../components/ui';
import { getClient } from '../lib/client';
import { addRelay, DEFAULT_RELAYS, getRelays, removeRelay, subscribeRelays } from '../lib/relays';

export const Relays = () => {
  const [relays, setRelays] = useState(getRelays());
  const [health, setHealth] = useState<Map<string, RelayHealth>>(new Map());
  const [input, setInput] = useState('');
  const [error, setError] = useState('');

  useEffect(() => subscribeRelays(() => setRelays(getRelays())), []);

  useEffect(() => {
    let cancelled = false;
    void getClient()
      .health()
      .then((results) => {
        if (cancelled) return;
        setHealth(new Map(results.map((r) => [r.url, r])));
      });
    return () => {
      cancelled = true;
    };
  }, [relays]);

  const add = (): void => {
    const url = addRelay(input);
    if (!url) {
      setError('not a usable relay url');
      return;
    }
    setError('');
    setInput('');
  };

  return (
    <>
      <Panel
        title="relays"
        right={<span class="lbl">{relays.length} configured</span>}
        orient={
          <>
            Relays are <b>parameters, not authorities</b> — reads fan out across this set and
            everything re-verifies locally. Adding more independent relays strengthens the
            convergence evidence; it never changes the math.
          </>
        }
      >
        <table>
          <thead>
            <tr>
              <th>relay</th>
              <th>status</th>
              <th>relay DID</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {relays.map((url) => {
              const h = health.get(url);
              return (
                <tr key={url}>
                  <td>{url.replace(/^https?:\/\//, '')}</td>
                  <td>
                    {h === undefined ? (
                      <span class="muted">probing…</span>
                    ) : h.ok ? (
                      <span style={{ color: 'var(--ok)' }}>up</span>
                    ) : (
                      <span class="err">unreachable</span>
                    )}
                  </td>
                  <td class="muted">{h?.did ?? ''}</td>
                  <td>
                    <a onClick={() => removeRelay(url)}>remove</a>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div class="bar" style={{ marginTop: 10 }}>
          <input
            placeholder="add relay url…"
            style={{ flex: 1 }}
            value={input}
            onInput={(e) => setInput((e.target as HTMLInputElement).value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') add();
            }}
          />
          <button onClick={add}>add</button>
        </div>
        {error ? (
          <div class="err" style={{ marginTop: 6 }}>
            {error}
          </div>
        ) : null}
        <div class="ck-note" style={{ marginTop: 10 }}>
          The default seed ({DEFAULT_RELAYS.join(', ')}) is a pragmatic starting point, not a
          blessing — remove it any time. Each relay's local-index sync cursor is tracked
          independently; the op pool is a union across relays.
        </div>
      </Panel>
    </>
  );
};
