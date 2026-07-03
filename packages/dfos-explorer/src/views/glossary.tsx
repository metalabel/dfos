/*

  GLOSSARY — how this protocol actually works

*/

import { Panel } from '../components/ui';
import { GLOSSARY_TERMS } from '../lib/glossary';

export const Glossary = () => (
  <Panel
    title="glossary"
    right={<span class="lbl">how this protocol actually works</span>}
    orient={
      <>
        No blockchains, no miners, no global ledger.{' '}
        <b>Signed chains anyone can verify; one relay's partial view.</b>
      </>
    }
  >
    <div class="kv terms">
      {GLOSSARY_TERMS.map((t) => (
        <>
          <div class="k" style={{ color: 'var(--ink)' }}>
            {t.term}
          </div>
          <div class="v muted">{t.def}</div>
        </>
      ))}
    </div>
  </Panel>
);
