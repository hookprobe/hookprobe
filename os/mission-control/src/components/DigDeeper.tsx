/**
 * DigDeeper — the floating "Dig deeper" button (bottom-right, 48 px) and the wide drawer it opens.
 * Progressive disclosure: raw records, the attack path, rule sources and sealed-evidence details
 * are one click away and never shown by default.
 */
import { type Component, type JSX, createSignal } from 'solid-js';
import Drawer from './Drawer';

interface Props {
  /** What the drawer is about, e.g. "Incident" or "QSecBit". */
  title: string;
  /** The evidence path the panel walks, shown under the title. */
  crumb?: string;
  children: JSX.Element;
  footer?: JSX.Element;
}

const DigDeeper: Component<Props> = (props) => {
  const [open, setOpen] = createSignal(false);
  return (
    <>
      <button class="dig-fab" aria-haspopup="dialog" aria-expanded={open()} onClick={() => setOpen(true)}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="6" /><path d="M20 20l-4.5-4.5" /></svg>
        Dig deeper
      </button>
      <Drawer wide open={open()} title={`Dig deeper · ${props.title}`} crumb={props.crumb} onClose={() => setOpen(false)} footer={props.footer}>
        {props.children}
      </Drawer>
    </>
  );
};

export default DigDeeper;
