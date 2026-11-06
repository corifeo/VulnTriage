/*
 * VulnTriage runtime: a tiny template renderer, no dependencies.
 *
 * Templates are plain HTML inside a <template> element with:
 *   {{path}}                    dotted lookup into the values from renderVals()
 *   <sc-for list="{{xs}}" as="x">  repeat children; $index in scope
 *   <sc-if value="{{flag}}">        render children when truthy
 *   onClick="{{fn}}"            event handler (onChange on text fields = input event)
 *
 * A component extends DCLogic, keeps state in this.state and returns its
 * template values from renderVals(). setState() re-renders the whole tree;
 * focus and caret position are restored so typing is not interrupted.
 */
(function (global) {
  'use strict';

  const HOLE = /\{\{\s*([^}]+?)\s*\}\}/g;
  const WHOLE = /^\{\{\s*([^}]+?)\s*\}\}$/;
  const PROPS = { value: 1, checked: 1, disabled: 1 };

  function lookup(scope, path) {
    if (path === 'true') return true;
    if (path === 'false') return false;
    if (path === 'null') return null;
    if (/^-?\d+(\.\d+)?$/.test(path)) return Number(path);
    let v = scope;
    for (const part of path.split('.')) {
      if (v == null) return undefined;
      v = v[part];
    }
    return v;
  }

  function interpolate(text, scope) {
    return text.replace(HOLE, (_, p) => {
      const v = lookup(scope, p);
      return v == null ? '' : String(v);
    });
  }

  function eventName(attr, el) {
    const name = attr.slice(2).toLowerCase();
    if (name === 'change') {
      const tag = el.tagName;
      const type = (el.getAttribute('type') || '').toLowerCase();
      if (tag === 'TEXTAREA' || (tag === 'INPUT' && !['file', 'checkbox', 'radio'].includes(type))) return 'input';
    }
    return name;
  }

  function renderChildren(node, scope, out) {
    for (const child of node.childNodes) renderNode(child, scope, out);
  }

  function renderNode(node, scope, out) {
    if (node.nodeType === 3) {
      out.push(document.createTextNode(interpolate(node.nodeValue, scope)));
      return;
    }
    if (node.nodeType !== 1) return;
    const tag = node.localName;

    if (tag === 'sc-for') {
      const m = WHOLE.exec(node.getAttribute('list') || '');
      const list = m ? lookup(scope, m[1]) : null;
      const as = node.getAttribute('as') || 'item';
      (Array.isArray(list) ? list : []).forEach((item, i) => {
        const s = Object.create(scope);
        s[as] = item;
        s.$index = i;
        renderChildren(node, s, out);
      });
      return;
    }
    if (tag === 'sc-if') {
      const m = WHOLE.exec(node.getAttribute('value') || '');
      if (m && lookup(scope, m[1])) renderChildren(node, scope, out);
      return;
    }

    const el = node.namespaceURI === 'http://www.w3.org/2000/svg'
      ? document.createElementNS(node.namespaceURI, tag)
      : document.createElement(tag);
    const handlers = [];
    const props = [];
    for (const { name, value } of Array.from(node.attributes)) {
      if (name.startsWith('hint-')) continue;
      const whole = WHOLE.exec(value);
      if (name.startsWith('on') && name.length > 2) {
        const fn = whole ? lookup(scope, whole[1]) : null;
        if (typeof fn === 'function') handlers.push([name, fn]);
        continue;
      }
      if (PROPS[name] && whole) {
        props.push([name, lookup(scope, whole[1])]);
        continue;
      }
      if (whole) {
        const v = lookup(scope, whole[1]);
        if (v === false || v == null) continue;
        el.setAttribute(name, v === true ? '' : String(v));
      } else {
        el.setAttribute(name, interpolate(value, scope));
      }
    }
    for (const [name, v] of props) {
      if (name === 'value') el.value = v == null ? '' : String(v);
      else el[name] = !!v;
      if (name !== 'value' && v) el.setAttribute(name, '');
    }
    handlers.forEach(([name, fn]) => el.addEventListener(eventName(name, el), fn));

    const kids = [];
    renderChildren(node.content || node, scope, kids);
    kids.forEach((k) => el.appendChild(k));
    // value on <textarea>/<select> must be set after children exist
    for (const [name, v] of props) if (name === 'value') el.value = v == null ? '' : String(v);
    out.push(el);
  }

  function pathOf(el, root) {
    const path = [];
    while (el && el !== root) {
      const parent = el.parentNode;
      if (!parent) return null;
      path.unshift(Array.prototype.indexOf.call(parent.childNodes, el));
      el = parent;
    }
    return el === root ? path : null;
  }

  function nodeAt(root, path) {
    let n = root;
    for (const i of path) {
      if (!n || !n.childNodes[i]) return null;
      n = n.childNodes[i];
    }
    return n;
  }

  class DCLogic {
    constructor(props) {
      this.props = props || {};
      this.state = {};
      this._mount = null;
    }

    setState(patch) {
      const next = typeof patch === 'function' ? patch(this.state) : patch;
      this.state = Object.assign({}, this.state, next);
      if (this._mount) this._mount.render();
    }

    forceUpdate() {
      if (this._mount) this._mount.render();
    }
  }

  function mount(ComponentClass, root, template, props) {
    const comp = new ComponentClass(props || {});
    const scrollers = () => Array.from(root.querySelectorAll('[data-keep-scroll]'));
    const api = {
      component: comp,
      render() {
        const active = document.activeElement;
        const path = active && root.contains(active) ? pathOf(active, root) : null;
        const sel = active && typeof active.selectionStart === 'number'
          ? [active.selectionStart, active.selectionEnd] : null;
        const scroll = scrollers().map((s) => [s.scrollLeft, s.scrollTop]);

        const out = [];
        renderChildren(template.content, comp.renderVals(), out);
        root.replaceChildren(...out);

        scrollers().forEach((s, i) => {
          if (scroll[i]) { s.scrollLeft = scroll[i][0]; s.scrollTop = scroll[i][1]; }
        });
        if (path) {
          const again = nodeAt(root, path);
          if (again && again.focus && again.tagName === (active && active.tagName)) {
            again.focus({ preventScroll: true });
            if (sel && typeof again.setSelectionRange === 'function') {
              try { again.setSelectionRange(sel[0], sel[1]); } catch (_) { /* not a text field */ }
            }
          }
        }
        if (typeof comp.componentDidUpdate === 'function') comp.componentDidUpdate();
      }
    };
    comp._mount = api;
    api.render();
    if (typeof comp.componentDidMount === 'function') comp.componentDidMount();
    return api;
  }

  global.DCLogic = DCLogic;
  global.VulnTriage = { mount, lookup, interpolate };
})(typeof window !== 'undefined' ? window : globalThis);
