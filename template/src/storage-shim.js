const P = 'app_';
window.storage = {
  async get(k) {
    const v = localStorage.getItem(P + k);
    if (v === null) throw new Error('Key not found: ' + k);
    return { key: k, value: v, shared: false };
  },
  async set(k, v, s = false) {
    localStorage.setItem(P + k, v);
    return { key: k, value: v, shared: s };
  },
  async delete(k) {
    const e = localStorage.getItem(P + k) !== null;
    localStorage.removeItem(P + k);
    return { key: k, deleted: e, shared: false };
  },
  async list(prefix = '') {
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {
      const f = localStorage.key(i);
      if (f.startsWith(P)) {
        const a = f.slice(P.length);
        if (!prefix || a.startsWith(prefix)) keys.push(a);
      }
    }
    return { keys, prefix, shared: false };
  },
};
