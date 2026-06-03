/**
 * MYCEL — Decentraliserat Socialt Nätverk
 * =========================================
 * Arkitektur (enligt specifikationen):
 *  1. Asymmetrisk kryptografi (ECDSA P-256) för identitet & signering
 *  2. IndexedDB för offline-first lokal lagring
 *  3. WebRTC (RTCPeerConnection + RTCDataChannel) för P2P
 *  4. Gossip-protokoll för dataspridning
 *  5. Social Recovery via Shamir-liknande nyckeldelning (simulerad)
 *  6. PWA Service Worker
 */

'use strict';

// ┌─────────────────────────────────────────────────────────┐
// │  KONFIGURATION                                            │
// └─────────────────────────────────────────────────────────┘
const STUN_SERVERS = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ]
};

// ══════════════════════════════════════════════════════════
// 1. KRYPTOGRAFI — WebCrypto API (ECDSA P-256)
// ══════════════════════════════════════════════════════════
const Crypto = {
  /** Generera nytt nyckelpar */
  async generateKeyPair() {
    const kp = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,  // exporterbart
      ['sign', 'verify']
    );
    return kp;
  },

  /** Exportera publik nyckel som hex-sträng */
  async exportPublicKey(key) {
    const raw = await crypto.subtle.exportKey('spki', key);
    return Array.from(new Uint8Array(raw))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  /** Exportera privat nyckel som JWK (för lagring) */
  async exportPrivateKey(key) {
    return crypto.subtle.exportKey('jwk', key);
  },

  /** Importera privat nyckel från JWK */
  async importPrivateKey(jwk) {
    return crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['sign']
    );
  },

  /** Importera publik nyckel från hex */
  async importPublicKey(hex) {
    const bytes = new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));
    return crypto.subtle.importKey(
      'spki', bytes.buffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['verify']
    );
  },

  /** Signera ett meddelande (returnerar hex) */
  async sign(privateKey, message) {
    const data = new TextEncoder().encode(message);
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey, data
    );
    return Array.from(new Uint8Array(sig))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  /** Verifiera signatur */
  async verify(publicKey, message, signatureHex) {
    try {
      const pubKey = await Crypto.importPublicKey(publicKey);
      const data = new TextEncoder().encode(message);
      const sigBytes = new Uint8Array(signatureHex.match(/.{2}/g).map(b => parseInt(b, 16)));
      return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pubKey, sigBytes.buffer, data
      );
    } catch { return false; }
  },

  /** Hash (SHA-256) → hex */
  async hash(str) {
    const data = new TextEncoder().encode(str);
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  /** Generera slumpmässigt UUID */
  uuid() {
    return crypto.randomUUID ? crypto.randomUUID()
      : ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
        (c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))).toString(16));
  }
};

// ══════════════════════════════════════════════════════════
// 2. LOKAL DATABAS — IndexedDB (Offline-First)
// ══════════════════════════════════════════════════════════
const DB = {
  db: null,
  DB_NAME: 'mycel-v1', // overridden per-user at login
  VERSION: 3,

  async open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB.DB_NAME, DB.VERSION);
      req.onupgradeneeded = e => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('identity')) {
          db.createObjectStore('identity', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('posts')) {
          const ps = db.createObjectStore('posts', { keyPath: 'id' });
          ps.createIndex('by_timestamp', 'timestamp');
          ps.createIndex('by_author', 'authorPubkey');
        }
        if (!db.objectStoreNames.contains('peers')) {
          db.createObjectStore('peers', { keyPath: 'pubkey' });
        }
        if (!db.objectStoreNames.contains('seen')) {
          db.createObjectStore('seen', { keyPath: 'id' }); // gossip dedup
        }
        if (!db.objectStoreNames.contains('likes')) {
          const ls = db.createObjectStore('likes', { keyPath: 'id' });
          ls.createIndex('by_post', 'postId');
        }
        if (!db.objectStoreNames.contains('comments')) {
          const cs = db.createObjectStore('comments', { keyPath: 'id' });
          cs.createIndex('by_post', 'postId');
        }
        if (!db.objectStoreNames.contains('comment_likes')) {
          const cl = db.createObjectStore('comment_likes', { keyPath: 'id' });
          cl.createIndex('by_comment', 'commentId');
        }
      };
      req.onsuccess = e => { DB.db = e.target.result; resolve(DB.db); };
      req.onerror = e => reject(e.target.error);
    });
  },

  async put(store, obj) {
    return new Promise((resolve, reject) => {
      const tx = DB.db.transaction(store, 'readwrite');
      tx.objectStore(store).put(obj);
      tx.oncomplete = () => resolve();
      tx.onerror   = e => reject(e.target.error);
      tx.onabort   = e => reject(e.target.error);
    });
  },

  async get(store, key) {
    return new Promise((resolve, reject) => {
      const tx = DB.db.transaction(store, 'readonly');
      tx.objectStore(store).get(key).onsuccess = e => resolve(e.target.result);
      tx.onerror = () => resolve(null);
    });
  },

  async getAll(store, index = null, query = null) {
    return new Promise((resolve, reject) => {
      const tx = DB.db.transaction(store, 'readonly');
      const s = tx.objectStore(store);
      const req = index ? s.index(index).getAll(query) : s.getAll();
      req.onsuccess = e => resolve(e.target.result || []);
      req.onerror = () => resolve([]);
    });
  },

  async delete(store, key) {
    return new Promise((resolve, reject) => {
      const tx = DB.db.transaction(store, 'readwrite');
      tx.objectStore(store).delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror    = e => reject(e.target.error);
    });
  },

  async clear(store) {
    return new Promise((resolve) => {
      const tx = DB.db.transaction(store, 'readwrite');
      tx.objectStore(store).clear().onsuccess = () => resolve();
    });
  }
};

// ══════════════════════════════════════════════════════════
// 3. IDENTITETSHANTERING
// ══════════════════════════════════════════════════════════
const Identity = {
  current: null,
  privateKey: null,

  async create(name, bio = '') {
    UI.setKeyGenStatus('Genererar kryptografiska nycklar...');
    const kp = await Crypto.generateKeyPair();
    const pubkey = await Crypto.exportPublicKey(kp.publicKey);
    const privkeyJwk = await Crypto.exportPrivateKey(kp.privateKey);
    const id = {
      id: 'self',
      name,
      bio,
      pubkey,
      privkeyJwk,
      deviceId: Crypto.uuid(),
      createdAt: Date.now()
    };
    await DB.put('identity', id);
    Identity.current = id;
    Identity.privateKey = kp.privateKey;
    UI.setKeyGenStatus('✓ Nycklar genererade och sparade lokalt');
    return id;
  },

  async load() {
    const id = await DB.get('identity', 'self');
    if (!id) return null;
    if (!id.deviceId) {
      id.deviceId = Crypto.uuid();
      await DB.put('identity', id);
    }
    Identity.current = id;
    console.log('[Identity] Publik nyckel:', id.pubkey);
    try {
      Identity.privateKey = await Crypto.importPrivateKey(id.privkeyJwk);
    } catch {
      Identity.privateKey = null;
      console.warn('[Identity] crypto.subtle ej tillgängligt — kräver HTTPS');
    }
    return id;
  },

  async sign(message) {
    if (!Identity.privateKey) throw new Error('Ingen privat nyckel laddad');
    return Crypto.sign(Identity.privateKey, message);
  },

  shortKey(pubkey) {
    if (!pubkey) return '???';
    return pubkey.slice(0, 8) + '…' + pubkey.slice(-6);
  },

  avatarEmoji(pubkey) {
    const emojis = ['🌱', '🌿', '🍀', '🌲', '🍄', '🌾', '🌸', '🌺', '🌻', '🌼', '🍁', '🦋', '🐝', '🐞', '🦎', '🐸', '🦊', '🐺', '🦁', '🐬'];
    const idx = parseInt((pubkey || '0').slice(-4), 16) % emojis.length;
    return emojis[idx];
  },

  avatarHTML(pubkey) {
    const image = Identity.current?.pubkey === pubkey
      ? Identity.current?.profileImage
      : Peers.imageCache.get(pubkey);
    if (image) {
      return `<img src="${image}" alt="" style="width:100%;height:100%;border-radius:50%;object-fit:cover;display:block;">`;
    }
    return Identity.avatarEmoji(pubkey);
  },

  /** Social Recovery — dela privat nyckel i N fragment */
  async createRecoveryShards(n = 3) {
    const jwkStr = JSON.stringify(Identity.current.privkeyJwk);
    // Simulerad Shamir-delning: XOR-baserad för demo
    const encoder = new TextEncoder();
    const data = encoder.encode(jwkStr);
    const shards = [];
    let xorAccum = new Uint8Array(data.length);

    for (let i = 0; i < n - 1; i++) {
      const rand = crypto.getRandomValues(new Uint8Array(data.length));
      shards.push(Array.from(rand).map(b => b.toString(16).padStart(2, '0')).join(''));
      for (let j = 0; j < data.length; j++) xorAccum[j] ^= rand[j];
    }
    // Sista shard = data XOR alla övriga
    const lastShard = new Uint8Array(data.length);
    for (let j = 0; j < data.length; j++) lastShard[j] = data[j] ^ xorAccum[j];
    shards.push(Array.from(lastShard).map(b => b.toString(16).padStart(2, '0')).join(''));

    return shards;
  }
};

// ══════════════════════════════════════════════════════════
// 4. INLÄGG (Posts)
// ══════════════════════════════════════════════════════════
const Posts = {
  async create(text) {
    if (!Identity.current) throw new Error('Inte inloggad');
    const id = Crypto.uuid();
    const timestamp = Date.now();
    const payload = JSON.stringify({ id, text, authorPubkey: Identity.current.pubkey, timestamp });
    const signature = await Identity.sign(payload);

    const post = {
      id, text,
      authorPubkey: Identity.current.pubkey,
      authorName: Identity.current.name,
      timestamp,
      signature,
      hops: 0,
      local: true
    };

    await DB.put('posts', post);
    await DB.put('seen', { id }); // markera som sedd (gossip-dedup)
    return post;
  },

  async getAll() {
    const posts = await DB.getAll('posts');
    return posts.sort((a, b) => b.timestamp - a.timestamp);
  },

  async delete(id) {
    await DB.delete('posts', id);
    // I ett riktigt system: skicka delete-signal via gossip
    Gossip.broadcast({ type: 'delete', id });
  },

  async receiveFromGossip(post) {
    // Deduplika
    const seen = await DB.get('seen', post.id);
    if (seen) return false;

    // Acceptera bara inlägg från direkta vänner
    const peers = await Peers.getAll();
    const isKnownAuthor = peers.some(p => p.pubkey === post.authorPubkey);
    if (!isKnownAuthor) return false;

    // Verifiera signatur
    const payload = JSON.stringify({
      id: post.id, text: post.text,
      authorPubkey: post.authorPubkey,
      timestamp: post.timestamp
    });
    const valid = await Crypto.verify(post.authorPubkey, payload, post.signature);
    if (!valid) {
      console.warn('Ogiltig signatur på inlägg:', post.id);
      UI.toast('⚠️ Mottog inlägg med ogiltig signatur', 'error');
      return false;
    }

    post.hops = (post.hops || 0) + 1;
    post.local = false;
    await DB.put('posts', post);
    await DB.put('seen', { id: post.id });
    return true;
  }
};

// ══════════════════════════════════════════════════════════
// 4b. GILLNINGAR (Likes)
// ══════════════════════════════════════════════════════════
const Likes = {
  /** Spara en gillning lokalt. id = postId:likerPubkey (idempotent). */
  async add(like) {
    const id = `${like.postId}:${like.likerPubkey}`;
    await DB.put('likes', { ...like, id });
    return id;
  },

  /** Hämta alla gillningar för ett inlägg. */
  async getForPost(postId) {
    return DB.getAll('likes', 'by_post', postId);
  },

  /** Returnera true om pubkey redan gillat postId. */
  async has(postId, pubkey) {
    return !!(await DB.get('likes', `${postId}:${pubkey}`));
  },

  /** Hämta alla gillningar (för synkronisering). */
  async getAll() {
    return DB.getAll('likes');
  }
};

// ══════════════════════════════════════════════════════════
// 4c. KOMMENTARER (Comments)
// ══════════════════════════════════════════════════════════
const Comments = {
  async create(postId, text) {
    if (!Identity.current) throw new Error('Inte inloggad');
    const id = Crypto.uuid();
    const timestamp = Date.now();
    const payload = JSON.stringify({ id, postId, text, authorPubkey: Identity.current.pubkey, timestamp });
    const signature = await Identity.sign(payload);
    const comment = {
      id, postId, text,
      authorPubkey: Identity.current.pubkey,
      authorName: Identity.current.name,
      timestamp, signature, hops: 0
    };
    await DB.put('comments', comment);
    await DB.put('seen', { id: `c:${id}` });
    return comment;
  },

  async getAll() {
    return DB.getAll('comments');
  },

  async receiveFromGossip(comment) {
    const seenKey = `c:${comment.id}`;
    if (await DB.get('seen', seenKey)) return false;
    const payload = JSON.stringify({
      id: comment.id, postId: comment.postId, text: comment.text,
      authorPubkey: comment.authorPubkey, timestamp: comment.timestamp
    });
    const valid = await Crypto.verify(comment.authorPubkey, payload, comment.signature);
    if (!valid) { console.warn('Ogiltig signatur på kommentar:', comment.id); return false; }
    comment.hops = (comment.hops || 0) + 1;
    await DB.put('comments', comment);
    await DB.put('seen', { id: seenKey });
    return true;
  }
};

// ══════════════════════════════════════════════════════════
// 4d. KOMMENTARGILLNINGAR (CommentLikes)
// ══════════════════════════════════════════════════════════
const CommentLikes = {
  async add(like) {
    const id = `${like.commentId}:${like.likerPubkey}`;
    await DB.put('comment_likes', { ...like, id });
    return id;
  },

  async has(commentId, pubkey) {
    return !!(await DB.get('comment_likes', `${commentId}:${pubkey}`));
  },

  async getAll() {
    return DB.getAll('comment_likes');
  }
};

// ══════════════════════════════════════════════════════════
// 4e. AVISERINGAR
// ══════════════════════════════════════════════════════════
const Notifications = {
  _lsKey: 'mycel-notif-last-read',

  getLastRead() {
    return parseInt(localStorage.getItem(Notifications._lsKey) || '0');
  },

  markAllRead() {
    localStorage.setItem(Notifications._lsKey, Date.now().toString());
  },

  async getAll() {
    if (!Identity.current) return [];
    const myPk = Identity.current.pubkey;
    const lastRead = Notifications.getLastRead();

    const [posts, likes, comments, commentLikes] = await Promise.all([
      Posts.getAll(), Likes.getAll(), Comments.getAll(), CommentLikes.getAll()
    ]);

    const myPosts = new Map(posts.filter(p => p.authorPubkey === myPk).map(p => [p.id, p]));
    const myComments = new Map(comments.filter(c => c.authorPubkey === myPk).map(c => [c.id, c]));
    const myCommentedPostIds = new Set([...myComments.values()].map(c => c.postId));

    const notifs = [];

    for (const like of likes) {
      if (like.timestamp > lastRead && myPosts.has(like.postId) && like.likerPubkey !== myPk) {
        const post = myPosts.get(like.postId);
        notifs.push({ type: 'post_like', actor: like.likerName || like.likerPubkey.slice(0,8), ref: post.text, timestamp: like.timestamp });
      }
    }
    for (const c of comments) {
      if (c.timestamp > lastRead && c.authorPubkey !== myPk) {
        if (myPosts.has(c.postId)) {
          const post = myPosts.get(c.postId);
          notifs.push({ type: 'post_comment', actor: c.authorName || c.authorPubkey.slice(0,8), ref: post.text, extra: c.text, timestamp: c.timestamp });
        } else if (myCommentedPostIds.has(c.postId)) {
          const post = posts.find(p => p.id === c.postId);
          notifs.push({ type: 'thread_comment', actor: c.authorName || c.authorPubkey.slice(0,8), ref: post ? post.text : '', extra: c.text, timestamp: c.timestamp });
        }
      }
    }
    for (const cl of commentLikes) {
      if (cl.timestamp > lastRead && myComments.has(cl.commentId) && cl.likerPubkey !== myPk) {
        const comment = myComments.get(cl.commentId);
        notifs.push({ type: 'comment_like', actor: cl.likerName || cl.likerPubkey.slice(0,8), ref: comment.text, timestamp: cl.timestamp });
      }
    }

    return notifs.sort((a, b) => b.timestamp - a.timestamp);
  },

  async unreadCount() {
    return (await Notifications.getAll()).length;
  }
};

// ══════════════════════════════════════════════════════════
// 5. PEER-HANTERING
// ══════════════════════════════════════════════════════════
const Peers = {
  connections: new Map(), // pubkey:deviceId → { channel, lastSeen, name }
  imageCache: new Map(),  // pubkey → dataURL

  async getAll() {
    return DB.getAll('peers');
  },

  async add(peer) {
    await DB.put('peers', {
      pubkey: peer.pubkey,
      name: peer.name || 'Okänd',
      addedAt: Date.now(),
      lastSeen: peer.lastSeen || Date.now()
    });
  },

  async loadImageCache() {
    const peers = await DB.getAll('peers');
    for (const p of peers) {
      if (p.profileImage) Peers.imageCache.set(p.pubkey, p.profileImage);
    }
  },

  async storeImage(pubkey, image) {
    Peers.imageCache.set(pubkey, image);
    const peer = await DB.get('peers', pubkey);
    if (peer) {
      peer.profileImage = image;
      await DB.put('peers', peer);
    }
  },

  /** Skapa identitetskod (pubkey+namn) att visa som QR/text för lokal återkänning */
  identityInfo() {
    if (!Identity.current) return '';
    return btoa(JSON.stringify({
      pk: Identity.current.pubkey,
      n: Identity.current.name
    }));
  },

  onlineCount() {
    const seen = new Set();
    for (const [key, conn] of Peers.connections) {
      if (conn.channel?.readyState === 'open') {
        const pk = key.includes(':') ? key.split(':')[0] : key;
        seen.add(pk);
      }
    }
    return seen.size;
  },

  /** Bygger anslutningsnyckel: pubkey:deviceId (eller bara pubkey om deviceId saknas) */
  connKey(pubkey, deviceId) {
    return deviceId ? `${pubkey}:${deviceId}` : pubkey;
  },

  /** Returnerar alla anslutningsposter för en given pubkey (alla enheter) */
  channelsFor(pubkey) {
    const result = [];
    for (const [key, conn] of Peers.connections) {
      if (key === pubkey || key.startsWith(pubkey + ':')) result.push(conn);
    }
    return result;
  },

  /** Returnerar första öppna kanalen för en pubkey (bakåtkompatibel hjälpare) */
  connFor(pubkey) {
    const channels = Peers.channelsFor(pubkey);
    return channels.find(c => c.channel?.readyState === 'open') || channels[0] || null;
  }
};

// ══════════════════════════════════════════════════════════
// 6. MANUELL SIGNALERING — serverlös WebRTC
// ══════════════════════════════════════════════════════════
// Flöde:
//   Steg 1 (A): createOffer()  → kopierar kod → skickar till B via SMS/etc.
//   Steg 2 (B): acceptOffer() → kopierar kod → skickar tillbaka till A
//   Steg 3 (A): acceptAnswer() → anslutning öppnas
// Ingen server krävs. Signaleringen sker via valfri kanal.
const ManualSignaling = {
  _pending: new Map(), // tempId → { pc, peerRef }
  _rcCodes: new Map(), // peerPubkey → { name, code } — automatiskt genererade återanslutningskoder

  /** Bygger localStorage-nyckel för auto-återanslutning */
  _lsKey(type, fromSlice, toSlice) {
    return `mycel-rc-${type}-${fromSlice}-${toSlice}`;
  },

  /**
   * Körs vid sidladdning för varje känd peer.
   * Försöker återansluta automatiskt via localStorage (samma enhet)
   * och genererar nya offer-koder att skicka manuellt (olika enheter).
   */
  async autoReconnect(savedPeers) {
    if (!savedPeers.length || !Identity.current) return;
    const myPk = Identity.current.pubkey;
    const mySlice = myPk.slice(0, 16);

    // Rensa utgångna localStorage-poster (> 2 h)
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (!k?.startsWith('mycel-rc-')) continue;
      try {
        const val = JSON.parse(localStorage.getItem(k));
        if (val.ts && Date.now() - val.ts > 7200000) localStorage.removeItem(k);
      } catch { localStorage.removeItem(k); }
    }

    // Lyssna på storage-events — automatiskt utbyte om båda flikar/fönster är öppna
    window.addEventListener('storage', async (e) => {
      if (!e.key?.startsWith('mycel-rc-') || !e.newValue) return;
      const curPk = Identity.current?.pubkey;
      if (!curPk) return;
      const curSlice = curPk.slice(0, 16);

      for (const peer of (await Peers.getAll())) {
        const peerSlice = peer.pubkey.slice(0, 16);
        // Inkommande offer (från peer till mig) — jag är responder
        if (e.key === ManualSignaling._lsKey('o', peerSlice, curSlice)) {
          try {
            const { code } = JSON.parse(e.newValue);
            const answerCode = await ManualSignaling.acceptOffer(code);
            localStorage.setItem(
              ManualSignaling._lsKey('a', curSlice, peerSlice),
              JSON.stringify({ code: answerCode, ts: Date.now() })
            );
            localStorage.removeItem(e.key);
          } catch { }
          return;
        }
        // Inkommande answer (från peer till mig) — jag är initiator
        if (e.key === ManualSignaling._lsKey('a', peerSlice, curSlice)) {
          try {
            const { code } = JSON.parse(e.newValue);
            await ManualSignaling.acceptAnswer(code);
            localStorage.removeItem(e.key);
            ManualSignaling._rcCodes.delete(peer.pubkey);
            UI.renderPeers();
          } catch { }
          return;
        }
        // Inkommande req (responder saknar offer) — jag är initiator, skapa nytt offer
        if (e.key === ManualSignaling._lsKey('req', peerSlice, curSlice)) {
          try {
            localStorage.removeItem(e.key);
            const conn = Peers.connFor(peer.pubkey);
            if (conn?.channel?.readyState === 'open') return;
            const { code } = await ManualSignaling.createOffer();
            localStorage.setItem(
              ManualSignaling._lsKey('o', curSlice, peerSlice),
              JSON.stringify({ code, ts: Date.now() })
            );
            ManualSignaling._rcCodes.set(peer.pubkey, { name: peer.name, code });
            UI.renderPeers();
          } catch { }
          return;
        }
      }
    });

    // Hantera varje känd peer
    for (const peer of savedPeers) {
      const peerSlice = peer.pubkey.slice(0, 16);
      const conn = Peers.connFor(peer.pubkey);
      if (conn?.channel?.readyState === 'open') continue; // redan ansluten

      // Bokstavsordning avgör vem som initerar (stabilt, undviker dubbla offer)
      const iAmInitiator = myPk < peer.pubkey;

      if (iAmInitiator) {
        // Kolla om peer redan svarat på ett offer från den här sessionen
        const savedAnswer = localStorage.getItem(ManualSignaling._lsKey('a', peerSlice, mySlice));
        if (savedAnswer) {
          try {
            const { code } = JSON.parse(savedAnswer);
            await ManualSignaling.acceptAnswer(code);
            localStorage.removeItem(ManualSignaling._lsKey('a', peerSlice, mySlice));
            continue;
          } catch {
            localStorage.removeItem(ManualSignaling._lsKey('a', peerSlice, mySlice));
          }
        }
        // Generera ett nytt offer (skriver över eventuellt gammalt)
        try {
          const { code } = await ManualSignaling.createOffer();
          localStorage.setItem(
            ManualSignaling._lsKey('o', mySlice, peerSlice),
            JSON.stringify({ code, ts: Date.now() })
          );
          ManualSignaling._rcCodes.set(peer.pubkey, { name: peer.name, code });
        } catch { }
      } else {
        // Jag är responder — kolla om initiatorns offer finns redan
        const savedOffer = localStorage.getItem(ManualSignaling._lsKey('o', peerSlice, mySlice));
        if (savedOffer) {
          try {
            const { code } = JSON.parse(savedOffer);
            const answerCode = await ManualSignaling.acceptOffer(code);
            localStorage.setItem(
              ManualSignaling._lsKey('a', mySlice, peerSlice),
              JSON.stringify({ code: answerCode, ts: Date.now() })
            );
            localStorage.removeItem(ManualSignaling._lsKey('o', peerSlice, mySlice));
            continue;
          } catch { }
        }
        // Inget offer hittades — signalera till initiator att vi vill återansluta
        localStorage.setItem(
          ManualSignaling._lsKey('req', mySlice, peerSlice),
          JSON.stringify({ ts: Date.now() })
        );
      }
    }

    UI.renderPeers(); // Uppdatera UI med eventuella återanslutningskoder
  },

  /** Skapar en WebRTC RTCPeerConnection och kopplar datalyssnare */
  _makePC(isInitiator, connKey, peerRef) {
    const pc = new RTCPeerConnection(STUN_SERVERS);

    const setupChannel = (ch) => {
      const onOpen = () => {
        const pubkey = peerRef.pubkey;
        const finalKey = Peers.connKey(pubkey, peerRef.deviceId);
        const entry = Peers.connections.get(connKey) || {};
        entry.channel = ch;
        entry.name = peerRef.name;
        entry.lastSeen = Date.now();
        Peers.connections.set(finalKey, entry);
        if (connKey !== finalKey) Peers.connections.delete(connKey);

        // Spara kontaktuppgifter i localStorage vid lyckad anslutning
        try {
          const contacts = JSON.parse(localStorage.getItem('mycel-contacts') || '[]');
          const idx = contacts.findIndex(c => c.pubkey === pubkey);
          const record = { pubkey, name: peerRef.name, lastConnected: Date.now() };
          if (idx >= 0) contacts[idx] = record;
          else contacts.push(record);
          localStorage.setItem('mycel-contacts', JSON.stringify(contacts));
        } catch { }

        UI.updateConnectionStatus(true);
        UI.renderPeers();
        UI.updateStats();
        UI.toast(`✓ Direkt P2P-koppling öppen med ${peerRef.name || pubkey.slice(0, 8)}`, 'success');
        setTimeout(() => Gossip.syncWithPeer(pubkey), 300);
        // Håll MQTT aktivt som bakgrundssäkring för snabb återanslutning om en peer laddar om.
      };

      if (ch.readyState === 'open') {
        onOpen();
      } else {
        ch.onopen = onOpen;
      }

      ch.onclose = () => {
        const pubkey = peerRef.pubkey;
        const finalKey = Peers.connKey(pubkey, peerRef.deviceId);
        const entry = Peers.connections.get(finalKey);
        if (entry) entry.channel = null;
        UI.renderPeers();
        UI.updateConnectionStatus(Peers.onlineCount() > 0);
        // Säkerställ att MQTT är aktivt för att kunna omförhandla WebRTC
        if (!MqttSignaling.client?.connected) {
          MqttSignaling.client = null;
          MqttSignaling.connect();
        }
        // Initiator skapar nytt offer när kanalen stängs
        if (isInitiator && pubkey) {
          setTimeout(async () => {
            const cur = Peers.connFor(pubkey);
            if (cur?.channel?.readyState === 'open') return;
            try {
              const { code } = await ManualSignaling.createOffer();
              // Primärt: WebSocket (cross-browser)
              const sent = MqttSignaling.sendOffer(pubkey, code);
              // Fallback: localStorage (samma browser, olika flikar)
              if (!sent) {
                const mySlice = Identity.current?.pubkey?.slice(0, 16);
                const peerSlice = pubkey.slice(0, 16);
                if (mySlice && peerSlice) {
                  localStorage.setItem(
                    ManualSignaling._lsKey('o', mySlice, peerSlice),
                    JSON.stringify({ code, ts: Date.now() })
                  );
                }
              }
              ManualSignaling._rcCodes.set(pubkey, { name: peerRef.name, code });
              UI.renderPeers();
            } catch { }
          }, 1500);
        }
      };
      ch.onmessage = async (e) => {
        let msg; try { msg = JSON.parse(e.data); } catch { return; }
        await Gossip.handleMessage(msg, peerRef.pubkey);
      };
    };

    if (isInitiator) {
      setupChannel(pc.createDataChannel('mycel', { ordered: false }));
    } else {
      pc.ondatachannel = (e) => setupChannel(e.channel);
    }

    // Rensa kanal vid frånkoppling. OBS: 'disconnected' är ofta övergående och
    // återhämtar sig av sig själv — ge ICE en frist innan vi river ned. Endast
    // 'failed'/'closed' är slutgiltiga och river ned direkt.
    let _disconnectTimer = null;
    const _clearChannel = () => {
      const finalKey = Peers.connKey(peerRef.pubkey, peerRef.deviceId);
      const entry = Peers.connections.get(finalKey);
      if (entry?.channel) { entry.channel = null; UI.renderPeers(); }
    };
    const _onState = (state) => {
      if (state === 'connected' || state === 'completed') {
        // Återhämtad — avbryt ev. nedräkning
        if (_disconnectTimer) { clearTimeout(_disconnectTimer); _disconnectTimer = null; }
      } else if (state === 'failed' || state === 'closed') {
        if (_disconnectTimer) { clearTimeout(_disconnectTimer); _disconnectTimer = null; }
        _clearChannel();
      } else if (state === 'disconnected') {
        // Vänta och se om ICE återhämtar sig innan vi river ned
        if (!_disconnectTimer) {
          _disconnectTimer = setTimeout(() => {
            _disconnectTimer = null;
            if (['disconnected', 'failed', 'closed'].includes(pc.iceConnectionState)) _clearChannel();
          }, 8000);
        }
      }
    };
    pc.onconnectionstatechange = () => _onState(pc.connectionState);
    pc.oniceconnectionstatechange = () => _onState(pc.iceConnectionState);

    return pc;
  },

  /** Väntar tills ICE-insamling är klar (alla noder funna), max 6 s */
  _waitForIce(pc) {
    return new Promise(resolve => {
      if (pc.iceGatheringState === 'complete') { resolve(); return; }
      const handler = () => {
        if (pc.iceGatheringState === 'complete') {
          pc.removeEventListener('icegatheringstatechange', handler);
          resolve();
        }
      };
      pc.addEventListener('icegatheringstatechange', handler);
      setTimeout(resolve, 3000);
    });
  },

  /**
   * Steg 1 — du skapar en inbjudningskod att skicka till din vän.
   * Returnerar { code, tempId }
   */
  async createOffer() {
    const tempId = 'p_' + Date.now();
    const peerRef = { pubkey: null, name: null, deviceId: null };
    Peers.connections.set(tempId, { name: '…', _pendingOffer: true });

    const pc = ManualSignaling._makePC(true, tempId, peerRef);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await ManualSignaling._waitForIce(pc);

    ManualSignaling._pending.set(tempId, { pc, peerRef });

    return {
      code: btoa(JSON.stringify({
        v: 1, t: 'o',
        sdp: pc.localDescription.sdp,
        pk: Identity.current.pubkey,
        n: Identity.current.name,
        id: tempId,
        did: Identity.current.deviceId
      })),
      tempId
    };
  },

  /**
   * Steg 2 — din vän klistrar in din kod, får en svarskod att skicka tillbaka.
   * Returnerar svarskoden.
   */
  async acceptOffer(encoded) {
    let data;
    try { data = JSON.parse(atob(encoded.replace(/\s+/g, ''))); } catch { throw new Error('Ogiltig inbjudningskod'); }
    if (data.t !== 'o') throw new Error('Det här är ett svar, inte en inbjudan');
    if (data.pk === Identity.current?.pubkey && data.did === Identity.current?.deviceId) throw new Error('Det är din egen nyckel!');

    const peerPubkey = data.pk;
    const name = data.n;
    const peerRef = { pubkey: peerPubkey, name, deviceId: data.did || null };
    const peerConnKey = Peers.connKey(peerPubkey, data.did);
    Peers.connections.set(peerConnKey, { name, _pendingOffer: true });

    const pc = ManualSignaling._makePC(false, peerConnKey, peerRef);
    await pc.setRemoteDescription({ type: 'offer', sdp: data.sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await ManualSignaling._waitForIce(pc);

    await Peers.add({ pubkey: peerPubkey, name });
    Network.addNode(peerPubkey, name);
    MqttSignaling.subscribeToPeer(peerPubkey);
    UI.renderPeers();

    return btoa(JSON.stringify({
      v: 1, t: 'a',
      sdp: pc.localDescription.sdp,
      pk: Identity.current.pubkey,
      n: Identity.current.name,
      id: data.id,
      did: Identity.current.deviceId
    }));
  },

  /**
   * Steg 3 — du klistrar in svarskoden från din vän, anslutningen öppnas.
   */
  async acceptAnswer(encoded) {
    let data;
    try { data = JSON.parse(atob(encoded.replace(/\s+/g, ''))); } catch { throw new Error('Ogiltig svarskod'); }
    if (data.t !== 'a') throw new Error('Det här är en inbjudan, inte ett svar');

    const pending = ManualSignaling._pending.get(data.id);
    if (!pending) throw new Error('Ingen matchande inbjudan. Skapa en ny.');
    ManualSignaling._pending.delete(data.id);

    pending.peerRef.pubkey = data.pk;
    pending.peerRef.name = data.n;
    pending.peerRef.deviceId = data.did || null;

    // Flytta connection-entry till rätt nyckel (tempId → pubkey:deviceId)
    const finalKey = Peers.connKey(data.pk, data.did);
    const byId = Peers.connections.get(data.id);
    if (byId) { Peers.connections.delete(data.id); Peers.connections.set(finalKey, byId); }
    // Hantera fallet att onopen hann köra innan acceptAnswer (sparades under null-nyckeln)
    const byNull = Peers.connections.get(null);
    if (byNull) {
      Peers.connections.delete(null);
      Peers.connections.set(finalKey, byNull);
      byNull.name = data.n;
      if (byNull.channel?.readyState === 'open') {
        setTimeout(() => Gossip.syncWithPeer(data.pk), 100);
      }
    }

    await pending.pc.setRemoteDescription({ type: 'answer', sdp: data.sdp });
    await Peers.add({ pubkey: data.pk, name: data.n });
    Network.addNode(data.pk, data.n);
    MqttSignaling.subscribeToPeer(data.pk);
    UI.renderPeers();
  },

  /** Autodetektera om inklistrad kod är inbjudan eller svar, kör rätt funktion */
  async handlePastedCode(encoded) {
    const clean = encoded.replace(/\s+/g, '');
    // Utfärda hjälpsamt felmeddelande om användaren klistrat in sin pubkey istället
    if (/^[0-9a-f]{40,}$/i.test(clean)) {
      throw new Error('Det här är en publik nyckel, inte en anslutningskod. Anslutningskoden får du genom att din vän klickar \u201cSkapa inbjudningskod\u201d.');
    }
    let data;
    try { data = JSON.parse(atob(clean)); } catch { throw new Error('Ogiltig kod — se till att kopiera hela koden utan radbrytningar.'); }
    if (data.t === 'o') {
      const answerCode = await ManualSignaling.acceptOffer(encoded);
      return { action: 'answered', code: answerCode, toPk: data.pk, toDid: data.did };
    }
    if (data.t === 'a') {
      await ManualSignaling.acceptAnswer(encoded);
      return { action: 'connected' };
    }
    throw new Error('Okänd kodtyp');
  }
};

// ══════════════════════════════════════════════════════════
// 7. GOSSIP-PROTOKOLL
// ══════════════════════════════════════════════════════════
const Gossip = {
  active: true,

  init() {
    // Inget att initiera — anslutningar görs manuellt via ManualSignaling
  },

  async handleMessage(msg, fromPubkey) {
    if (!msg || !msg.type) return;
    switch (msg.type) {
      case 'post':
        if (Gossip.active && msg.post) {
          const isNew = await Posts.receiveFromGossip(msg.post);
          if (isNew) {
            UI.renderFeed();
            UI.toast(`📨 Nytt inlägg från ${msg.post.authorName || 'okänd'}`, 'info');
            // Vidarebefordra till andra peers (gossip hop)
            Gossip.forwardToOthers(msg, fromPubkey);
          }
        }
        break;

      case 'sync_request': {
        // Skicka bara egna inlägg — aldrig vidarebefordra andras inlägg
        const allPosts = await Posts.getAll();
        const posts = allPosts.filter(p => p.authorPubkey === Identity.current?.pubkey);
        const likes = await Likes.getAll();
        const comments = await Comments.getAll();
        const commentLikes = await CommentLikes.getAll();
        const conn = Peers.connFor(fromPubkey);
        if (conn?.channel?.readyState === 'open') {
          conn.channel.send(JSON.stringify({
            type: 'sync_response',
            from: Identity.current.pubkey,
            posts, likes, comments, commentLikes
          }));
        }
        break;
      }

      case 'sync_response': {
        let newCount = 0;
        if (msg.posts && Array.isArray(msg.posts)) {
          for (const post of msg.posts) {
            const isNew = await Posts.receiveFromGossip(post);
            if (isNew) newCount++;
          }
        }
        if (msg.likes && Array.isArray(msg.likes)) {
          for (const like of msg.likes) {
            if (like?.postId && like?.likerPubkey) await Likes.add(like);
          }
        }
        if (msg.comments && Array.isArray(msg.comments)) {
          for (const comment of msg.comments) {
            await Comments.receiveFromGossip(comment);
          }
        }
        if (msg.commentLikes && Array.isArray(msg.commentLikes)) {
          for (const cl of msg.commentLikes) {
            if (cl?.commentId && cl?.likerPubkey) await CommentLikes.add(cl);
          }
        }
        if (newCount > 0) {
          UI.renderFeed();
          UI.updateNotificationBadge();
          UI.toast(`🔄 Synkroniserade ${newCount} nya inlägg`, 'info');
        } else if (msg.likes?.length || msg.comments?.length || msg.commentLikes?.length) {
          UI.renderFeed();
          UI.updateNotificationBadge();
        }
        break;
      }

      case 'delete':
        if (msg.id) {
          await DB.delete('posts', msg.id);
          UI.renderFeed();
        }
        break;

      case 'like':
        if (msg.like?.postId && msg.like?.likerPubkey) {
          await Likes.add(msg.like);
          UI.renderFeed();
          UI.updateNotificationBadge();
          Gossip.forwardToOthers(msg, fromPubkey);
        }
        break;

      case 'comment':
        if (Gossip.active && msg.comment) {
          const isNew = await Comments.receiveFromGossip(msg.comment);
          if (isNew) {
            UI.renderFeed();
            UI.updateNotificationBadge();
            Gossip.forwardToOthers(msg, fromPubkey);
          }
        }
        break;

      case 'comment_like':
        if (msg.like?.commentId && msg.like?.likerPubkey) {
          await CommentLikes.add(msg.like);
          UI.renderFeed();
          UI.updateNotificationBadge();
          Gossip.forwardToOthers(msg, fromPubkey);
        }
        break;

      case 'profile_image':
        if (msg.pubkey && msg.image && msg.pubkey !== Identity.current?.pubkey) {
          await Peers.storeImage(msg.pubkey, msg.image);
          const node = Network.nodes.get(msg.pubkey);
          if (node) {
            const img = new Image();
            img.onload = () => { node.img = img; };
            img.src = msg.image;
          }
          UI.renderFeed();
          UI.renderPeers();
        }
        break;

      case 'closing':
        // Avsändaren håller på att ladda om/stänga — återanslut MQTT omedelbart
        // så att vi inte behöver vänta på ICE-timeout (~30 s) för att märka frånvaron.
        if (!MqttSignaling.client?.connected) {
          MqttSignaling.client = null;
          setTimeout(() => MqttSignaling.connect(), 500);
        }
        break;
    }
  },

  broadcast(message) {
    if (!Gossip.active) return;
    for (const [pubkey, conn] of Peers.connections) {
      if (conn.channel?.readyState === 'open') {
        try {
          conn.channel.send(JSON.stringify({
            ...message,
            from: Identity.current?.pubkey
          }));
        } catch (err) {
          console.warn('Kunde inte skicka till peer:', pubkey, err);
        }
      }
    }
  },

  async syncWithPeer(pubkey) {
    const conn = Peers.connFor(pubkey);
    if (!conn?.channel || conn.channel.readyState !== 'open') return;
    conn.channel.send(JSON.stringify({
      type: 'sync_request',
      from: Identity.current.pubkey
    }));
    if (Identity.current?.profileImage) {
      conn.channel.send(JSON.stringify({
        type: 'profile_image',
        pubkey: Identity.current.pubkey,
        image: Identity.current.profileImage
      }));
    }
  },

  forwardToOthers(msg, exceptPubkey) {
    if (msg.post && msg.post.hops >= 6) return; // max 6 hopp
    if (msg.comment && msg.comment.hops >= 6) return;
    for (const [key, conn] of Peers.connections) {
      const pubkey = key.includes(':') ? key.split(':')[0] : key;
      if (pubkey === exceptPubkey) continue;
      if (conn.channel?.readyState === 'open') {
        try {
          conn.channel.send(JSON.stringify({
            ...msg,
            from: Identity.current?.pubkey
          }));
        } catch { }
      }
    }
  }
};

// ══════════════════════════════════════════════════════════
// 7. NÄTVERKSVISUALISERING (Canvas)
// ══════════════════════════════════════════════════════════
const Network = {
  nodes: new Map(), // pubkey → { x, y, name, emoji }
  edges: [],
  animFrame: null,

  init() {
    const canvas = document.getElementById('network-canvas');
    if (!canvas) return;
    Network.canvas = canvas;
    Network.ctx = canvas.getContext('2d');

    // Lägg till self-nod
    if (Identity.current) {
      Network.addNode(Identity.current.pubkey, Identity.current.name, true);
    }
    Network.startRender();
  },

  addNode(pubkey, name, isSelf = false) {
    if (Network.nodes.has(pubkey)) return;
    const canvas = document.getElementById('network-canvas');
    const W = canvas?.clientWidth || 400;
    const H = canvas?.clientHeight || 200;
    const angle = Math.random() * Math.PI * 2;
    const r = 40 + Math.random() * 60;
    const node = {
      x: W / 2 + Math.cos(angle) * (isSelf ? 0 : r),
      y: H / 2 + Math.sin(angle) * (isSelf ? 0 : r),
      name, isSelf,
      emoji: Identity.avatarEmoji(pubkey),
      img: null,
      vx: (Math.random() - 0.5) * 0.5,
      vy: (Math.random() - 0.5) * 0.5
    };
    Network.nodes.set(pubkey, node);
    const imgSrc = isSelf
      ? Identity.current?.profileImage
      : Peers.imageCache.get(pubkey);
    if (imgSrc) {
      const img = new Image();
      img.onload = () => { node.img = img; };
      img.src = imgSrc;
    }

    if (!isSelf && Identity.current) {
      Network.edges.push({ a: Identity.current.pubkey, b: pubkey });
    }
  },

  startRender() {
    if (Network.animFrame) cancelAnimationFrame(Network.animFrame);
    const tick = () => {
      Network.draw();
      Network.animFrame = requestAnimationFrame(tick);
    };
    tick();
  },

  draw() {
    const canvas = Network.canvas;
    if (!canvas || !Network.ctx) return;
    const ctx = Network.ctx;
    const W = canvas.clientWidth || canvas.width;
    const H = canvas.clientHeight || canvas.height;
    canvas.width = W; canvas.height = H;

    ctx.clearRect(0, 0, W, H);

    // Physics: gentle drift
    for (const [, node] of Network.nodes) {
      node.x += node.vx;
      node.y += node.vy;
      if (node.x < 20 || node.x > W - 20) node.vx *= -1;
      if (node.y < 20 || node.y > H - 20) node.vy *= -1;
    }

    // Repulsion
    const arr = [...Network.nodes.values()];
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        const dx = arr[j].x - arr[i].x;
        const dy = arr[j].y - arr[i].y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < 80) {
          const f = (80 - dist) / 80 * 0.3;
          arr[i].vx -= dx / dist * f;
          arr[i].vy -= dy / dist * f;
          arr[j].vx += dx / dist * f;
          arr[j].vy += dy / dist * f;
        }
      }
    }

    // Draw edges
    for (const edge of Network.edges) {
      const a = Network.nodes.get(edge.a);
      const b = Network.nodes.get(edge.b);
      if (!a || !b) continue;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.strokeStyle = 'rgba(58,122,66,0.4)';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Animated data packet
      const t = (Date.now() / 1200) % 1;
      const px = a.x + (b.x - a.x) * t;
      const py = a.y + (b.y - a.y) * t;
      ctx.beginPath();
      ctx.arc(px, py, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(124,252,138,0.8)';
      ctx.fill();
    }

    // Draw nodes
    for (const [pubkey, node] of Network.nodes) {
      const isSelected = pubkey === Identity.current?.pubkey;
      ctx.beginPath();
      ctx.arc(node.x, node.y, isSelected ? 14 : 10, 0, Math.PI * 2);
      ctx.fillStyle = isSelected ? 'rgba(124,252,138,0.2)' : 'rgba(26,26,40,0.9)';
      ctx.strokeStyle = isSelected ? '#7cfc8a' : '#3a3a60';
      ctx.lineWidth = isSelected ? 2 : 1;
      ctx.fill();
      ctx.stroke();

      // Avatar: profilbild eller emoji
      const nr = isSelected ? 14 : 10;
      if (node.img) {
        ctx.save();
        ctx.beginPath();
        ctx.arc(node.x, node.y, nr, 0, Math.PI * 2);
        ctx.clip();
        ctx.drawImage(node.img, node.x - nr, node.y - nr, nr * 2, nr * 2);
        ctx.restore();
      } else {
        ctx.font = `${isSelected ? 14 : 12}px serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.emoji, node.x, node.y);
      }

      // Name
      ctx.font = '9px Space Mono, monospace';
      ctx.fillStyle = 'rgba(112,112,160,0.8)';
      ctx.fillText(node.name?.slice(0, 12) || '?', node.x, node.y + 18);
    }
  }
};

// ══════════════════════════════════════════════════════════
// 8. QR-KOD GENERATOR (ren Canvas-implementation)
// ══════════════════════════════════════════════════════════
const QR = {
  /** Minimalistisk QR-kod via URL-omdirigering
   *  Skapar en stiliserad representation */
  drawInviteCode(canvas, text) {
    const ctx = canvas.getContext('2d');
    const size = canvas.width;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);

    // Använd en visuell kod istället för riktig QR
    // (riktig QR kräver ett externt bibliotek)
    ctx.fillStyle = '#000000';

    // Rita ett enkelt unikt mönster baserat på texten
    const hash = [...text].reduce((h, c) => ((h << 5) - h + c.charCodeAt(0)) | 0, 0);
    const seed = Math.abs(hash);

    const cells = 21;
    const cellSize = size / (cells + 4);
    const offset = cellSize * 2;

    // Finder patterns (hörn)
    const drawFinder = (x, y) => {
      ctx.fillRect(x, y, cellSize * 7, cellSize * 7);
      ctx.fillStyle = '#fff';
      ctx.fillRect(x + cellSize, y + cellSize, cellSize * 5, cellSize * 5);
      ctx.fillStyle = '#000';
      ctx.fillRect(x + cellSize * 2, y + cellSize * 2, cellSize * 3, cellSize * 3);
    };
    drawFinder(offset, offset);
    drawFinder(size - offset - cellSize * 7, offset);
    drawFinder(offset, size - offset - cellSize * 7);

    // Data-celler (pseudo-slumpmässiga baserat på texten)
    let rng = seed;
    for (let row = 0; row < cells; row++) {
      for (let col = 0; col < cells; col++) {
        // Hoppa över finder-pattern-zoner
        if ((row < 9 && col < 9) || (row < 9 && col > cells - 9) || (row > cells - 9 && col < 9)) continue;
        rng = (rng * 1664525 + 1013904223) & 0xffffffff;
        if (rng % 3 === 0) {
          ctx.fillStyle = '#000';
          ctx.fillRect(offset + col * cellSize, offset + row * cellSize, cellSize - 0.5, cellSize - 0.5);
        }
      }
    }

    // Label
    ctx.fillStyle = '#333';
    ctx.font = `bold 8px monospace`;
    ctx.textAlign = 'center';
    ctx.fillText('MYCEL', size / 2, size - 4);
  }
};

// ══════════════════════════════════════════════════════════
// 9. UI
// ══════════════════════════════════════════════════════════
const UI = {
  currentScreen: 'feed',

  toast(msg, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    document.getElementById('toast-container').appendChild(el);
    setTimeout(() => el.remove(), 3500);
  },

  setKeyGenStatus(msg) {
    const el = document.getElementById('key-gen-status');
    if (el) el.textContent = msg;
  },

  showScreen(name) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const target = document.getElementById(`screen-${name}`);
    if (target) target.classList.add('active');

    document.querySelectorAll('.nav-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.screen === name);
    });
    UI.currentScreen = name;
    sessionStorage.setItem('activeScreen', name);

    if (name === 'feed') UI.renderFeed();
    if (name === 'peers') { UI.renderPeers(); UI.renderQR(); }
    if (name === 'identity') UI.renderIdentity();
    if (name === 'notifications') UI.renderNotifications();
  },

  showMainApp() {
    document.getElementById('screen-onboard').classList.remove('active');
    document.getElementById('bottom-nav').style.display = 'block';
    const savedScreen = sessionStorage.getItem('activeScreen') || 'feed';
    UI.showScreen(savedScreen);
    if (!UI._feedPollInterval) {
      UI._feedPollInterval = setInterval(() => {
        if (UI.currentScreen === 'feed') UI.renderFeed();
      }, 2500);
    }
  },

  _feedVersion: 0,

  renderFeed() {
    if (document.activeElement?.classList.contains('comment-input')) return;
    const version = ++UI._feedVersion;
    const myPk = Identity.current?.pubkey;
    // Kom ihåg vilka kommentarssektioner som är öppna innan vi bygger om DOM:en
    const openComments = new Set(
      [...document.querySelectorAll('.post-comments:not([hidden])')].map(el => el.dataset.postId)
    );
    Promise.all([Posts.getAll(), Likes.getAll(), Comments.getAll(), CommentLikes.getAll()])
      .then(([posts, allLikes, allComments, allCommentLikes]) => {
        if (UI._feedVersion !== version) return; // ett nyare anrop hann före — avbryt
        const container = document.getElementById('feed-list');
        const label = document.getElementById('feed-label');
        if (!container) return;

        // Indexera gillningar per inlägg
        const likesByPost = new Map();
        for (const like of allLikes) {
          if (!likesByPost.has(like.postId)) likesByPost.set(like.postId, []);
          likesByPost.get(like.postId).push(like);
        }
        // Indexera kommentarer per inlägg (äldst först)
        const commentsByPost = new Map();
        for (const c of allComments) {
          if (!commentsByPost.has(c.postId)) commentsByPost.set(c.postId, []);
          commentsByPost.get(c.postId).push(c);
        }
        for (const arr of commentsByPost.values()) arr.sort((a, b) => a.timestamp - b.timestamp);
        // Indexera kommentargillningar per kommentar
        const likesByComment = new Map();
        for (const cl of allCommentLikes) {
          if (!likesByComment.has(cl.commentId)) likesByComment.set(cl.commentId, []);
          likesByComment.get(cl.commentId).push(cl);
        }

        label.textContent = `Flöde — ${posts.length} inlägg`;

        if (posts.length === 0) {
          container.innerHTML = `
            <div class="card text-muted text-center" style="font-size:13px;padding:32px;">
              Inga inlägg ännu.<br>
              <span style="font-size:11px;margin-top:8px;display:block;">
                Skriv ditt första inlägg ovan, eller anslut till en vän för att se dennes flöde.
              </span>
            </div>`;
          return;
        }

        container.innerHTML = posts.map(p => {
          // Inläggsgillningar
          const likes = likesByPost.get(p.id) || [];
          const iLiked = likes.some(l => l.likerPubkey === myPk);
          const hasLikes = likes.length > 0;
          const likeNames = likes.map(l => escHtml(l.likerName || l.likerPubkey.slice(0, 8))).join(', ');
          const likeClass = iLiked ? ' liked' : (hasLikes ? ' has-likes' : '');
          const likeLabel = hasLikes ? `♥ ${likes.length}` : '♡ gilla';

          // Kommentarer
          const comments = commentsByPost.get(p.id) || [];
          const commentsHtml = comments.map(c => {
            const cLikes = likesByComment.get(c.id) || [];
            const cLiked = cLikes.some(l => l.likerPubkey === myPk);
            const cHasLikes = cLikes.length > 0;
            const cLikeClass = cLiked ? ' liked' : (cHasLikes ? ' has-likes' : '');
            const cLikeLabel = cHasLikes ? `♥ ${cLikes.length}` : '♡';
            const cLikeTitle = cLikes.map(l => escHtml(l.likerName || l.likerPubkey.slice(0, 8))).join(', ');
            return `<div class="comment">
              <div class="avatar" style="font-size:18px;line-height:1">${Identity.avatarHTML(c.authorPubkey)}</div>
              <div class="comment-body">
                <div class="comment-meta"><strong>${escHtml(c.authorName || 'Okänd')}</strong>${timeAgo(c.timestamp)}</div>
                <div class="comment-text">${escHtml(c.text)}</div>
                <button class="post-action-btn${cLikeClass}" onclick="UI.likeComment('${c.id}')" title="${cLikeTitle}" style="font-size:15px;padding:1px 4px">${cLikeLabel}</button>
              </div>
            </div>`;
          }).join('');

          return `
          <div class="post-card" data-id="${p.id}">
            <div class="post-header">
              <div class="avatar">${Identity.avatarHTML(p.authorPubkey)}</div>
              <div class="post-author">
                <strong>${escHtml(p.authorName || 'Okänd')}</strong>
                <span>${timeAgo(p.timestamp)}</span>
              </div>
              <div class="post-sig" title="Kryptografiskt signerat inlägg">🔏 verifierat</div>
            </div>
            <div class="post-content">${escHtml(p.text)}</div>
            <div class="post-footer">
              <button class="post-action-btn${likeClass}" onclick="UI.likePost('${p.id}')" title="${likeNames}" style="font-size:15px">${likeLabel}</button>
              <button class="post-action-btn" onclick="UI.toggleComments('${p.id}')" style="font-size:15px">💬${comments.length > 0 ? ` ${comments.length}` : ''}</button>
              ${p.local ? `<button class="post-action-btn" onclick="UI.deletePost('${p.id}')">🗑 radera</button>` : ''}
              <span class="hops">${p.hops > 0 ? `${p.hops} hopp` : 'lokalt'}</span>
            </div>
            <div class="post-comments" data-post-id="${p.id}" id="comments-${p.id}" hidden>
              ${commentsHtml}
              <div class="comment-form">
                <input type="text" class="comment-input" id="comment-input-${p.id}"
                  placeholder="Skriv en kommentar…" maxlength="500"
                  onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();UI.addComment('${p.id}');}">
                <button class="comment-submit" onclick="UI.addComment('${p.id}')">→</button>
              </div>
            </div>
          </div>`;
        }).join('');

        // Återöppna kommentarssektioner som var öppna innan rendern
        for (const postId of openComments) {
          const el = document.getElementById(`comments-${postId}`);
          if (el) el.hidden = false;
        }
      })
      .catch(err => console.error('[renderFeed]', err));
  },

  async likePost(id) {
    const myPk = Identity.current?.pubkey;
    if (!myPk) return;
    if (await Likes.has(id, myPk)) {
      UI.toast('Du har redan gillat detta inlägg', 'info');
      return;
    }
    const like = {
      postId: id,
      likerPubkey: myPk,
      likerName: Identity.current.name,
      timestamp: Date.now()
    };
    await Likes.add(like);
    Gossip.broadcast({ type: 'like', like });
    UI.renderFeed();
    UI.toast('♥ Gillat!', 'success');
  },

  toggleComments(postId) {
    const el = document.getElementById(`comments-${postId}`);
    if (!el) return;
    el.hidden = !el.hidden;
    if (!el.hidden) {
      const input = document.getElementById(`comment-input-${postId}`);
      if (input) setTimeout(() => input.focus(), 0);
    }
  },

  async addComment(postId) {
    const input = document.getElementById(`comment-input-${postId}`);
    const text = input?.value.trim();
    if (!text) return;
    input.value = '';
    input.blur();
    const comment = await Comments.create(postId, text);
    Gossip.broadcast({ type: 'comment', comment });
    UI.renderFeed();
    setTimeout(() => {
      const el = document.getElementById(`comments-${postId}`);
      if (el) el.hidden = false;
      const newInput = document.getElementById(`comment-input-${postId}`);
      if (newInput) newInput.focus();
    }, 0);
  },

  async likeComment(commentId) {
    const myPk = Identity.current?.pubkey;
    if (!myPk) return;
    if (await CommentLikes.has(commentId, myPk)) {
      UI.toast('Du har redan gillat denna kommentar', 'info');
      return;
    }
    const like = { commentId, likerPubkey: myPk, likerName: Identity.current.name, timestamp: Date.now() };
    await CommentLikes.add(like);
    Gossip.broadcast({ type: 'comment_like', like });
    // Hitta postId för att hålla kommentarssektionen öppen
    const allComments = await Comments.getAll();
    const comment = allComments.find(c => c.id === commentId);
    UI.renderFeed();
    if (comment) {
      setTimeout(() => {
        const el = document.getElementById(`comments-${comment.postId}`);
        if (el) el.hidden = false;
      }, 0);
    }
  },

  async deletePost(id) {
    if (!confirm('Radera detta inlägg?')) return;
    await Posts.delete(id);
    UI.renderFeed();
    UI.toast('🗑 Inlägg raderat', 'info');
  },

  renderPeers() {
    const list = document.getElementById('peers-list');
    if (!list) return;
    Peers.getAll().then(peers => {
      if (peers.length === 0) {
        list.innerHTML = `<div class="card text-muted text-center" style="font-size:12px;">
          Inga vänner ännu — skicka en inbjudningskod för att komma igång.
        </div>`;
        return;
      }
      list.innerHTML = peers.map(p => {
        const conn = Peers.connFor(p.pubkey);
        const isOnline = conn?.channel?.readyState === 'open';
        const statusClass = isOnline ? 'online' : '';
        const statusText = isOnline ? 'online' : 'frånkopplad';
        const rc = ManualSignaling._rcCodes.get(p.pubkey);
        const rcSection = (!isOnline && rc) ? `
          <div style="width:100%;margin-top:10px;border-top:1px solid var(--border);padding-top:10px;">
            <div style="font-size:10px;color:var(--text-muted);margin-bottom:6px;">
              📡 Återanslutningskod — skicka till ${escHtml(p.name)}:
            </div>
            <div style="font-family:monospace;font-size:9px;word-break:break-all;background:var(--bg-secondary);padding:6px 8px;border-radius:6px;max-height:56px;overflow:auto;user-select:all;">${escHtml(rc.code)}</div>
            <button class="btn btn-ghost btn-sm w-full" style="margin-top:6px;" data-copy-rc="${escHtml(p.pubkey)}">
              📋 Kopiera kod
            </button>
          </div>
        ` : '';
        return `
          <div class="peer-card" style="flex-wrap:wrap;align-items:flex-start;">
            <div style="display:flex;align-items:center;gap:10px;width:100%;">
              <div class="avatar">${Identity.avatarHTML(p.pubkey)}</div>
              <div class="peer-info">
                <strong>${escHtml(p.name)}</strong>
                <span>${Identity.shortKey(p.pubkey)}</span>
              </div>
              <span class="peer-status ${statusClass}">${statusText}</span>
            </div>
            ${rcSection}
          </div>
        `;
      }).join('');

      // Koppla kopiera-lyssnare för återanslutningskoder (undviker HTML-injection i onclick)
      list.querySelectorAll('[data-copy-rc]').forEach(btn => {
        btn.addEventListener('click', () => {
          const pk = btn.dataset.copyRc;
          const entry = ManualSignaling._rcCodes.get(pk);
          if (!entry) return;
          navigator.clipboard?.writeText(entry.code)
            .then(() => UI.toast('📋 Återanslutningskod kopierad!', 'success'))
            .catch(() => UI.toast('Kunde inte kopiera automatiskt', 'error'));
        });
      });

      // Uppdatera badge
      const badge = document.getElementById('peer-badge');
      if (peers.length > 0) {
        badge.style.display = 'flex';
        badge.textContent = peers.length;
      }
    });
  },

  renderQR() {
    const canvas = document.getElementById('qr-canvas');
    const identityText = document.getElementById('identity-info-text');
    if (!Identity.current) return;
    if (identityText) identityText.textContent = Identity.current.pubkey;
    if (!canvas) return;
    const info = `${Identity.current.name} · ${Identity.shortKey(Identity.current.pubkey)}`;
    QR.drawInviteCode(canvas, info);
  },

  renderIdentity() {
    if (!Identity.current) return;
    const id = Identity.current;
    const emoji = Identity.avatarEmoji(id.pubkey);

    const idAv = document.getElementById('id-avatar');
    if (id.profileImage) {
      idAv.innerHTML = `<img src="${id.profileImage}" alt="">`;
    } else {
      idAv.textContent = emoji;
    }
    document.getElementById('id-name').textContent = id.name;
    document.getElementById('id-bio').textContent = id.bio || 'Ingen biografi';

    // Recovery shards UI
    const shardList = document.getElementById('recovery-shards-list');
    const shards = JSON.parse(localStorage.getItem('mycel-recovery-shards') || '[]');
    if (shards.length > 0) {
      shardList.innerHTML = shards.map((_, i) => `
        <div class="recovery-shard">
          <div class="shard-peer">Fragment ${i + 1} av ${shards.length}</div>
          <div class="shard-hash">${shards[i].slice(0, 32)}…</div>
        </div>
      `).join('');
    } else {
      shardList.innerHTML = '<p class="text-muted" style="font-size:11px;">Ingen recovery konfigurerad.</p>';
    }

    UI.updateStats();
  },

  async updateStats() {
    const posts = await Posts.getAll();
    const peers = await Peers.getAll();
    const kb = JSON.stringify(posts).length / 1024;

    const sp = document.getElementById('stat-posts');
    const spe = document.getElementById('stat-peers');
    const sk = document.getElementById('stat-kb');
    if (sp) sp.textContent = posts.length;
    if (spe) spe.textContent = peers.length;
    if (sk) sk.textContent = kb.toFixed(1);
  },

  updateConnectionStatus(online) {
    const dot = document.getElementById('connection-dot');
    const label = document.getElementById('connection-label');
    if (dot) dot.className = `status-dot ${online ? 'online' : ''}`;
    if (label) label.textContent = online ? `Online · ${Peers.onlineCount()} vänner` : 'Offline';
  },

  async updateNotificationBadge() {
    const count = await Notifications.unreadCount();
    const badge = document.getElementById('notification-badge');
    if (!badge) return;
    if (count > 0) {
      badge.textContent = count > 9 ? '9+' : count;
      badge.style.display = 'flex';
    } else {
      badge.style.display = 'none';
    }
  },

  renderNotifications() {
    const container = document.getElementById('notifications-list');
    if (!container) return;
    container.innerHTML = '<p class="text-muted" style="padding:32px;text-align:center;font-size:13px;">Laddar…</p>';
    Notifications.getAll().then(notifs => {
      if (notifs.length === 0) {
        container.innerHTML = '<p class="text-muted" style="padding:32px;text-align:center;font-size:13px;">Inga nya aviseringar</p>';
      } else {
        const labels = {
          post_like:      (n) => `<strong>${escHtml(n.actor)}</strong> gillade ditt inlägg: <em>"${escHtml(n.ref.slice(0,60))}…"</em>`,
          post_comment:   (n) => `<strong>${escHtml(n.actor)}</strong> kommenterade ditt inlägg: <em>"${escHtml((n.extra||'').slice(0,60))}…"</em>`,
          thread_comment: (n) => `<strong>${escHtml(n.actor)}</strong> kommenterade i en tråd du deltar i: <em>"${escHtml((n.extra||'').slice(0,60))}…"</em>`,
          comment_like:   (n) => `<strong>${escHtml(n.actor)}</strong> gillade din kommentar: <em>"${escHtml(n.ref.slice(0,60))}…"</em>`,
        };
        container.innerHTML = notifs.map(n =>
          `<div class="notification-item"><span>${labels[n.type]?.(n) ?? ''}</span><span class="notification-time">${timeAgo(n.timestamp)}</span></div>`
        ).join('');
      }
      Notifications.markAllRead();
      UI.updateNotificationBadge();
    });
  },

  updateHeaderCompose() {
    if (!Identity.current) return;
    const av = document.getElementById('compose-avatar');
    const nm = document.getElementById('compose-name-display');
    if (av) {
      if (Identity.current.profileImage) {
        av.innerHTML = `<img src="${Identity.current.profileImage}" alt="">`;
      } else {
        av.textContent = Identity.avatarEmoji(Identity.current.pubkey);
      }
    }
    if (nm) nm.textContent = Identity.current.name;
  }
};

// ══════════════════════════════════════════════════════════
// 10. PWA SERVICE WORKER
// ══════════════════════════════════════════════════════════
const SW = {
  async register() {
    if ('serviceWorker' in navigator) {
      try {
        const reg = await navigator.serviceWorker.register('sw.js');
        return true;
      } catch (err) {
        return false;
      }
    }
    return false;
  }
};

// ══════════════════════════════════════════════════════════
// 11. MQTT-SIGNALING (automatisk återanslutning, cross-browser, ingen server)
// ══════════════════════════════════════════════════════════
// MQTT används bara som uppstarts-signalering för att etablera WebRTC.
// När alla kända peers är anslutna via WebRTC kopplas MQTT ned helt.
//
// Flöde:
//   1. Klient startar → prenumererar på mycel/inbox/{myPubkey}
//   2. Uppstartsskur: annonsera oss med beacon (3 gånger), sedan bara lyssna
//   3. Mottagen beacon → svara med beacon-ack så nystartad peer vet att vi finns
//   4. Initiator (lägre composite) → skapar och skickar offer
//   5. Responder → skapar och skickar answer → WebRTC-kanal öppnas
//   6. Alla peers anslutna → MQTT kopplas ned. Vid kanalstängning återansluts MQTT.
const MqttSignaling = {
  client: null,
  BROKER: 'wss://broker.emqx.io:8084/mqtt',
  _beaconTimer: null,
  _lastOfferTo: new Map(), // 'peerPk:peerDid' → timestamp (undvik offer-spam)

  connect() {
    if (!Identity.current) return;
    if (typeof mqtt === 'undefined') {
      console.warn('[MQTT] mqtt.js ej laddat — automatisk signalering inaktiv');
      return;
    }
    if (MqttSignaling.client) return; // redan ansluten eller håller på att ansluta

    const myPk = Identity.current.pubkey;
    const clientId = `mycel-${myPk.slice(0, 16)}-${Date.now()}`;
    console.log('[MQTT] Ansluter till broker…');

    const client = mqtt.connect(MqttSignaling.BROKER, {
      clientId,
      clean: true,
      reconnectPeriod: 5000,
      connectTimeout: 15000,
    });
    MqttSignaling.client = client;

    const myDid = Identity.current.deviceId;

    client.on('connect', () => {
      console.log('[MQTT] Ansluten till broker');
      // Prenumerera på broadcast-ämne (beacons) och enhetsspecifikt ämne (offer/answer)
      client.subscribe([`mycel/inbox/${myPk}`, `mycel/inbox/${myPk}/${myDid}`], (err) => {
        if (err) { console.warn('[MQTT] Prenumerationsfel:', err.message); return; }
        console.log('[MQTT] Lyssnar på mycel/inbox/' + myPk.slice(0, 12) + '…');
        // Uppstartsskur: annonsera oss några gånger för att nå redan online-peers,
        // sedan bara lyssna. Nystartade peers annonserar själva och når oss då.
        MqttSignaling._sendBeacons();
        let burst = 0;
        clearInterval(MqttSignaling._beaconTimer);
        MqttSignaling._beaconTimer = setInterval(() => {
          if (++burst >= 3) { clearInterval(MqttSignaling._beaconTimer); MqttSignaling._beaconTimer = null; return; }
          MqttSignaling._sendBeacons();
        }, 5000);
      });
    });

    client.on('message', async (_topic, payload) => {
      const raw = payload.toString();
      if (!raw) return;
      let msg; try { msg = JSON.parse(raw); } catch { return; }
      if (!msg?.from) return;
      // Ignorera eget eko (samma enhet)
      if (msg.from === myPk && msg.did === myDid) return;

      console.log('[MQTT] ← %s från %s', msg.type, msg.from.slice(0, 12));

      if (msg.type === 'beacon') {
        // Ignorera bara om exakt denna enhet (pubkey:deviceId) redan är ansluten
        if (Peers.connections.get(Peers.connKey(msg.from, msg.did))?.channel?.readyState === 'open') return;
        // Svara bara på kända peers (eller egna enheter) — förhindrar oönskad återanslutning
        const isSameIdentity = msg.from === myPk;
        if (!isSameIdentity) {
          const knownPeers = await Peers.getAll();
          if (!knownPeers.some(p => p.pubkey === msg.from)) return;
        }
        // Svara med egen beacon så att nystartad peer vet att vi är online
        const replyTarget = msg.did ? `mycel/inbox/${msg.from}/${msg.did}` : `mycel/inbox/${msg.from}`;
        client.publish(replyTarget, JSON.stringify({ type: 'beacon-ack', from: myPk, did: myDid }));
        // Initiator (lägre composite) skapar offer
        if ((myPk + ':' + myDid) < (msg.from + ':' + (msg.did || ''))) {
          await MqttSignaling._sendOfferTo(msg.from, msg.did, isSameIdentity);
        }

      } else if (msg.type === 'beacon-ack') {
        // Svar på vår uppstarts-beacon — initiator skapar offer
        if (Peers.connections.get(Peers.connKey(msg.from, msg.did))?.channel?.readyState === 'open') return;
        const isSameIdentity = msg.from === myPk;
        if (!isSameIdentity) {
          const knownPeers = await Peers.getAll();
          if (!knownPeers.some(p => p.pubkey === msg.from)) return;
        }
        if ((myPk + ':' + myDid) < (msg.from + ':' + (msg.did || ''))) {
          await MqttSignaling._sendOfferTo(msg.from, msg.did, isSameIdentity);
        }

      } else if (msg.type === 'offer') {
        // Ignorera bara om exakt denna enhet (pubkey:deviceId) redan är ansluten
        if (Peers.connections.get(Peers.connKey(msg.from, msg.did))?.channel?.readyState === 'open') return;
        // Acceptera bara offer från kända peers (eller egna enheter)
        const isSameIdentityOffer = msg.from === myPk;
        if (!isSameIdentityOffer) {
          const knownPeers = await Peers.getAll();
          if (!knownPeers.some(p => p.pubkey === msg.from)) return;
        }
        try {
          const answerCode = await ManualSignaling.acceptOffer(msg.code);
          // Svara riktat till avsändarens specifika enhet
          const answerTarget = msg.did
            ? `mycel/inbox/${msg.from}/${msg.did}`
            : `mycel/inbox/${msg.from}`;
          client.publish(answerTarget, JSON.stringify({
            type: 'answer', from: myPk, did: myDid, code: answerCode
          }));
          console.log('[MQTT] → answer till %s', msg.from.slice(0, 12));
        } catch (err) {
          console.warn('[MQTT] Offer-fel:', err.message);
        }

      } else if (msg.type === 'answer') {
        // Jag är initiator — kontrollera om just denna enhet redan är ansluten
        const connKey = Peers.connKey(msg.from, msg.did);
        const existing = Peers.connections.get(connKey);
        if (existing?.channel?.readyState === 'open') return;
        try {
          await ManualSignaling.acceptAnswer(msg.code);
          console.log('[MQTT] Svar godkänt från %s — WebRTC öppnas', msg.from.slice(0, 12));
        } catch (err) {
          console.warn('[MQTT] Answer-fel:', err.message);
          // Försök inte igen om tempId redan är förbrukat (t.ex. av en annan enhet)
          if (!err.message.includes('Ingen matchande inbjudan')) {
            MqttSignaling._lastOfferTo.delete(msg.from + ':' + (msg.did || ''));
          }
        }
      }
    });

    client.on('close', () => {
      console.log('[MQTT] Frånkopplad — försöker återansluta…');
      clearInterval(MqttSignaling._beaconTimer);
    });

    client.on('error', err => console.warn('[MQTT] Fel:', err.message));
  },

  async _sendBeacons() {
    if (!MqttSignaling.client?.connected || !Identity.current) return;
    const myPk = Identity.current.pubkey;
    const myDid = Identity.current.deviceId;
    const beaconPayload = JSON.stringify({ type: 'beacon', from: myPk, did: myDid });

    // Publicera till eget inbox — egna enheter på andra flikar/browsrar får veta vi finns
    MqttSignaling.client.publish(`mycel/inbox/${myPk}`, beaconPayload);

    const peers = await Peers.getAll();
    for (const peer of peers) {
      const ch = Peers.connFor(peer.pubkey)?.channel;
      if (ch?.readyState === 'open' || ch?.readyState === 'connecting') continue;
      MqttSignaling.client.publish(`mycel/inbox/${peer.pubkey}`, beaconPayload);
      if ((myPk + ':' + myDid) < (peer.pubkey + ':')) {
        MqttSignaling._sendOfferTo(peer.pubkey, null, false);
      }
    }
  },

  subscribeToPeer(_peerPubkey) {
    // Inget behov — vi prenumererar bara på vår egen inbox.
    // Beacon skickas automatiskt vid nästa intervall.
  },

  async _sendOfferTo(peerPk, peerDid = null, allowSameIdentity = false) {
    if (!MqttSignaling.client?.connected || !Identity.current) return;
    const myPk = Identity.current.pubkey;
    const myDid = Identity.current.deviceId;

    // Kontrollera om just denna enhet redan är ansluten
    const connKey = Peers.connKey(peerPk, peerDid);
    if (Peers.connections.get(connKey)?.channel?.readyState === 'open') return;
    // För olika identiteter: hoppa över om vi har någon öppen kanal till dem
    if (!allowSameIdentity && Peers.connFor(peerPk)?.channel?.readyState === 'open') return;

    // Undvik offer-spam: max en gång per 30 s per peer (normaliserad nyckel utan deviceId)
    const throttleKey = peerPk;
    const last = MqttSignaling._lastOfferTo.get(throttleKey) || 0;
    if (Date.now() - last < 30000) return;
    MqttSignaling._lastOfferTo.set(throttleKey, Date.now());

    try {
      console.log('[MQTT] Skapar offer till %s…', peerPk.slice(0, 12));
      const { code } = await ManualSignaling.createOffer();
      // Rikta offer till specifik enhet om vi känner till deviceId, annars broadcast
      const target = peerDid
        ? `mycel/inbox/${peerPk}/${peerDid}`
        : `mycel/inbox/${peerPk}`;
      MqttSignaling.client.publish(target, JSON.stringify({
        type: 'offer', from: myPk, did: myDid, code
      }));
      console.log('[MQTT] → offer till %s', peerPk.slice(0, 12));
      const peers = await Peers.getAll();
      const peer = peers.find(p => p.pubkey === peerPk);
      if (peer) ManualSignaling._rcCodes.set(peerPk, { name: peer.name, code });
      UI.renderPeers();
    } catch (err) {
      console.warn('[MQTT] Offer-skapningsfel:', err.message);
    }
  },

  sendOffer(toPubkey, code) {
    if (!MqttSignaling.client?.connected || !Identity.current) return false;
    try {
      MqttSignaling.client.publish(`mycel/inbox/${toPubkey}`, JSON.stringify({
        type: 'offer', from: Identity.current.pubkey, did: Identity.current.deviceId, code
      }));
      return true;
    } catch { return false; }
  }
};

// ══════════════════════════════════════════════════════════
// HJÄLPFUNKTIONER
// ══════════════════════════════════════════════════════════
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return 'just nu';
  if (s < 3600) return `${Math.floor(s / 60)} min sedan`;
  if (s < 86400) return `${Math.floor(s / 3600)} h sedan`;
  return `${Math.floor(s / 86400)} d sedan`;
}

// ══════════════════════════════════════════════════════════
// BOOTSTRAP — Huvudinitialisering
// ══════════════════════════════════════════════════════════
async function saveCredential(username, password) {
  if (!window.PasswordCredential) return;
  try {
    const cred = new PasswordCredential({ id: username, password });
    await navigator.credentials.store(cred);
  } catch {}
}

async function init() {
  // Kontrollera app-version och tvinga uppdatering om ny version finns
  const savedVersion = localStorage.getItem('mycel-app-version');
  if (savedVersion && savedVersion !== APP_VERSION) {
    console.log(`[App] Ny version tillgänglig (${savedVersion} → ${APP_VERSION}) — uppdaterar…`);
    localStorage.setItem('mycel-app-version', APP_VERSION);
    // Tvinga en reload så att ny kod hämtas från nätverket
    location.reload();
    return;
  }
  if (!savedVersion) {
    localStorage.setItem('mycel-app-version', APP_VERSION);
  }

  const loggedOut = sessionStorage.getItem('loggedOut');
  let currentDb = sessionStorage.getItem('currentDb');

  // ── Migration: if no accounts registry yet, check the old single DB ──
  const accounts = JSON.parse(localStorage.getItem('mycel-accounts') || '[]');
  const skipMigration = localStorage.getItem('mycel-skip-migration');
  localStorage.removeItem('mycel-skip-migration');
  if (accounts.length === 0 && !loggedOut && !currentDb && !skipMigration) {
    DB.DB_NAME = 'mycel-v1';
    await DB.open();
    const oldId = await DB.get('identity', 'self');
    if (oldId) {
      accounts.push({ name: oldId.name, dbName: 'mycel-v1' });
      localStorage.setItem('mycel-accounts', JSON.stringify(accounts));
      currentDb = 'mycel-v1';
      sessionStorage.setItem('currentDb', 'mycel-v1');
    }
  }

  let loggedIn = false;
  if (!loggedOut && currentDb) {
    try {
    DB.DB_NAME = currentDb;
    if (!DB.db) await DB.open();
    const pendingImport = sessionStorage.getItem('pendingImport');
    if (pendingImport) {
      sessionStorage.removeItem('pendingImport');
      try {
        const importedId = JSON.parse(pendingImport);
        const existingId = await DB.get('identity', 'self');
        const mergedId = { ...importedId };
        if (existingId && existingId.profileImage) mergedId.profileImage = existingId.profileImage;
        await DB.put('identity', mergedId);
      } catch (e) { console.warn('[init] DB.put fel:', e.message); }
    }
    const id = await Identity.load();
    if (id) {
      loggedIn = true;
      // Store pubkey in accounts registry so future imports can find this DB
      const accts = JSON.parse(localStorage.getItem('mycel-accounts') || '[]');
      const acctEntry = accts.find(a => a.dbName === DB.DB_NAME);
      if (acctEntry && !acctEntry.pubkey && id.pubkey) {
        acctEntry.pubkey = id.pubkey;
        localStorage.setItem('mycel-accounts', JSON.stringify(accts));
      }
      await Peers.loadImageCache();
      UI.updateHeaderCompose();
      UI.updateNotificationBadge();
      UI.showMainApp();
      if (sessionStorage.getItem('showWelcome')) {
        sessionStorage.removeItem('showWelcome');
        setTimeout(() => UI.toast('🎉 Välkommen till Skrivpunkten!', 'success'), 400);
      }
      Gossip.init();
      Network.init();
      SW.register();

      try {
        const lsContacts = JSON.parse(localStorage.getItem('mycel-contacts') || '[]');
        for (const c of lsContacts) {
          await Peers.add({ pubkey: c.pubkey, name: c.name, lastSeen: c.lastConnected });
        }
      } catch { }

      Peers.getAll().then(savedPeers => ManualSignaling.autoReconnect(savedPeers));
      MqttSignaling.connect();

      const url = new URL(location.href);
      if (url.searchParams.has('peer')) {
        history.replaceState({}, '', location.pathname);
      }

      setInterval(() => {
        UI.updateConnectionStatus(navigator.onLine || Peers.onlineCount() > 0);
      }, 3000);
      UI.updateConnectionStatus(navigator.onLine);
    }
    } catch (err) {
      console.warn('[init] Kunde inte ladda session:', err.message);
      sessionStorage.removeItem('currentDb');
    }
  }

  if (!loggedIn) {
    // Pre-fill if a single account exists (most common case for returning user)
    const savedAccounts = JSON.parse(localStorage.getItem('mycel-accounts') || '[]');
    if (savedAccounts.length === 1) {
      document.getElementById('onboard-name').value = savedAccounts[0].name;
      document.getElementById('btn-create-identity').textContent = '🔑 Logga in';
    }
    document.getElementById('screen-onboard').classList.add('active');
  }

  // ── Event Listeners ──

  // Onboarding
  document.getElementById('btn-create-identity').addEventListener('click', async () => {
    const name = document.getElementById('onboard-name').value.trim();
    if (!name) { UI.toast('Fyll i ditt namn', 'error'); return; }
    const bio = document.getElementById('onboard-bio').value.trim();
    const btn = document.getElementById('btn-create-identity');
    btn.disabled = true;
    try {
      const accounts = JSON.parse(localStorage.getItem('mycel-accounts') || '[]');
      const existing = accounts.find(a => a.name === name);

      if (existing) {
        // Returning user — open their own DB
        DB.DB_NAME = existing.dbName;
        DB.db = null;
        await DB.open();
        sessionStorage.setItem('currentDb', existing.dbName);
        sessionStorage.removeItem('loggedOut');
        await Identity.load();
        UI.updateHeaderCompose();
        UI.updateNotificationBadge();
        UI.showMainApp();
        Gossip.init();
        Network.init();
        SW.register();
        MqttSignaling.connect();
        UI.renderFeed();
        UI.toast('✓ Välkommen tillbaka, ' + name + '!', 'success');
      } else {
        // New user — create a fresh isolated DB
        const slug = name.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 12) || 'user';
        const rand = Math.random().toString(36).slice(2, 6);
        const dbName = `mycel-u-${slug}-${rand}`;
        DB.DB_NAME = dbName;
        DB.db = null;
        await DB.open();
        sessionStorage.setItem('currentDb', dbName);
        sessionStorage.removeItem('loggedOut');
        await Identity.create(name, bio);
        accounts.push({ name, dbName, pubkey: Identity.current.pubkey });
        localStorage.setItem('mycel-accounts', JSON.stringify(accounts));

        // Show identity code — user must save it before proceeding
        const payload = { name: Identity.current.name, bio: Identity.current.bio, pubkey: Identity.current.pubkey, privkeyJwk: Identity.current.privkeyJwk, createdAt: Identity.current.createdAt };
        const code = btoa(JSON.stringify(payload));
        document.getElementById('onboard-new-identity-code').value = code;
        document.getElementById('save-identity-username').value = Identity.current.name;
        document.getElementById('save-identity-password').value = code;
        document.getElementById('onboard-create-section').style.display = 'none';
        document.getElementById('onboard-import-section').style.display = 'none';
        document.getElementById('btn-onboard-show-create').style.display = 'none';
        document.getElementById('onboard-save-code-section').style.display = 'block';
        btn.disabled = false;
      }
    } catch (err) {
      UI.toast('Fel: ' + err.message, 'error');
      btn.disabled = false;
    }
  });

  // Onboarding — importera identitet från textkod
  document.getElementById('btn-onboard-show-create')?.addEventListener('click', () => {
    const section = document.getElementById('onboard-create-section');
    const visible = section.style.display !== 'none';
    section.style.display = visible ? 'none' : 'block';
    document.getElementById('btn-onboard-show-create').textContent = visible ? '+ Skapa en ny identitet' : '− Skapa en ny identitet';
    if (!visible) document.getElementById('onboard-name')?.focus();
  });

  document.getElementById('onboard-import-code')?.addEventListener('input', (e) => {
    try {
      const data = JSON.parse(atob(e.target.value.trim()));
      if (data.name) document.getElementById('import-identity-username').value = data.name;
    } catch {}
  });

  document.getElementById('form-login-identity')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const raw = document.getElementById('onboard-import-code')?.value?.trim();
    if (!raw) { UI.toast('Klistra in en identitetskod först', 'error'); return; }
    try {
      const data = JSON.parse(atob(raw));
      if (!data.pubkey || !data.privkeyJwk || !data.name) throw new Error('Ogiltig identitetskod');
      const newId = {
        id: 'self',
        name: data.name,
        bio: data.bio || '',
        pubkey: data.pubkey,
        privkeyJwk: data.privkeyJwk,
        deviceId: Crypto.uuid(),
        createdAt: data.createdAt || Date.now()
      };
      const accounts = JSON.parse(localStorage.getItem('mycel-accounts') || '[]');

      // Scan all known databases to find one that belongs to this pubkey
      let matchedDbName = null;
      for (const account of accounts) {
        try {
          const tempDb = await new Promise(res => {
            const req = indexedDB.open(account.dbName);
            req.onsuccess = e => res(e.target.result);
            req.onerror = () => res(null);
          });
          if (!tempDb) continue;
          const storedId = await new Promise(res => {
            try {
              const tx = tempDb.transaction('identity', 'readonly');
              tx.objectStore('identity').get('self').onsuccess = e => res(e.target.result);
              tx.onerror = () => res(null);
            } catch { res(null); }
          });
          tempDb.close();
          if (storedId?.pubkey === data.pubkey) {
            matchedDbName = account.dbName;
            if (!account.pubkey) { account.pubkey = data.pubkey; localStorage.setItem('mycel-accounts', JSON.stringify(accounts)); }
            break;
          }
        } catch { /* DB unreadable, skip */ }
      }

      let dbName;
      if (matchedDbName) {
        dbName = matchedDbName;
      } else {
        dbName = 'mycel-' + newId.pubkey.slice(0, 16) + '-' + Date.now();
        accounts.push({ name: newId.name, dbName, pubkey: data.pubkey });
        localStorage.setItem('mycel-accounts', JSON.stringify(accounts));
      }

      sessionStorage.setItem('pendingImport', JSON.stringify(newId));
      sessionStorage.removeItem('loggedOut');
      sessionStorage.setItem('currentDb', dbName);
      await saveCredential(data.name, raw);
      location.reload();
    } catch (err) {
      UI.toast('Fel: ' + err.message, 'error');
    }
  });

  document.getElementById('btn-copy-new-identity-code')?.addEventListener('click', () => {
    const code = document.getElementById('onboard-new-identity-code')?.value;
    if (code) navigator.clipboard?.writeText(code)
      .then(() => UI.toast('📋 Identitetskod kopierad — förvara den säkert!', 'success'))
      .catch(() => UI.toast('Markera och kopiera koden manuellt', 'info'));
  });

  document.getElementById('form-save-identity')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('save-identity-username').value;
    const password = document.getElementById('save-identity-password').value;
    await saveCredential(username, password);
    sessionStorage.setItem('showWelcome', '1');
    location.reload();
  });

  // Compose
  const composeText = document.getElementById('compose-text');
  composeText?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      document.getElementById('btn-post')?.click();
    }
  });

  composeText?.addEventListener('input', () => {
    const len = composeText.value.length;
    const cc = document.getElementById('char-count');
    if (cc) {
      cc.textContent = `${len} / 500`;
      cc.className = `char-count ${len > 450 ? 'warn' : ''}`;
    }
  });

  document.getElementById('btn-post')?.addEventListener('click', async () => {
    const text = composeText.value.trim();
    if (!text) { UI.toast('Skriv något först', 'error'); return; }
    if (!Identity.current) { UI.toast('Inte inloggad', 'error'); return; }
    const btn = document.getElementById('btn-post');
    btn.disabled = true;
    try {
      const post = await Posts.create(text);
      composeText.value = '';
      document.getElementById('char-count').textContent = '0 / 500';
      UI.renderFeed();
      // Gossip till peers
      Gossip.broadcast({ type: 'post', post });
      UI.toast('✓ Inlägg publicerat och gossipat', 'success');
      UI.updateStats();
    } catch (err) {
      UI.toast('Fel: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });


  // Nav
  document.querySelectorAll('.nav-btn[data-screen]').forEach(btn => {
    btn.addEventListener('click', () => UI.showScreen(btn.dataset.screen));
  });

  // Peers
  // Peers — Skapa inbjudan
  document.getElementById('btn-create-offer')?.addEventListener('click', async () => {
    const btn = document.getElementById('btn-create-offer');
    btn.disabled = true;
    try {
      UI.toast('⏳ Samlar nätverksvägar…', 'info');
      const { code } = await ManualSignaling.createOffer();
      const box = document.getElementById('offer-output-box');
      const pre = document.getElementById('offer-output-code');
      if (pre) pre.textContent = code;
      if (box) box.style.display = 'block';
      UI.toast('✔ Inbjudningskod skapad — kopiera och skicka!', 'success');
    } catch (err) {
      UI.toast('Fel: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById('btn-copy-offer')?.addEventListener('click', () => {
    const code = document.getElementById('offer-output-code')?.textContent;
    if (code) navigator.clipboard?.writeText(code).then(() => UI.toast('📋 Kopierat!', 'success'));
  });

  // Peers — Klistra in kod (inbjudan eller svar)
  document.getElementById('btn-handle-code')?.addEventListener('click', async () => {
    const input = document.getElementById('peer-code-input');
    const code = input?.value.trim();
    if (!code) return;
    const btn = document.getElementById('btn-handle-code');
    btn.disabled = true;
    try {
      const result = await ManualSignaling.handlePastedCode(code);
      if (result.action === 'answered') {
        // Försök leverera svaret automatiskt via MQTT
        const mqttTarget = result.toDid
          ? `mycel/inbox/${result.toPk}/${result.toDid}`
          : `mycel/inbox/${result.toPk}`;
        const autoSent = MqttSignaling.client?.connected
          ? (MqttSignaling.client.publish(mqttTarget, JSON.stringify({
              type: 'answer',
              from: Identity.current.pubkey,
              did: Identity.current.deviceId,
              code: result.code
            })), true)
          : false;
        const box = document.getElementById('answer-output-box');
        const pre = document.getElementById('answer-output-code');
        if (pre) pre.textContent = result.code;
        if (box) box.style.display = 'block';
        input.value = '';
        UI.toast(autoSent
          ? '✔ Svar skickat automatiskt till din vän!'
          : '✔ Svarskod skapad — skicka tillbaka till din vän!',
          'success');
      } else if (result.action === 'connected') {
        input.value = '';
        document.getElementById('answer-output-box').style.display = 'none';
        document.getElementById('offer-output-box').style.display = 'none';
        UI.toast('⏳ Upprättar direkt P2P-koppling…', 'info');
      }
    } catch (err) {
      UI.toast('⚠ ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById('btn-copy-answer')?.addEventListener('click', () => {
    const code = document.getElementById('answer-output-code')?.textContent;
    if (code) navigator.clipboard?.writeText(code).then(() => UI.toast('📋 Kopierat!', 'success'));
  });


  document.getElementById('avatar-file-input')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file || !Identity.current) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const img = new Image();
      img.onload = async () => {
        const size = 128;
        const canvas = document.createElement('canvas');
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');
        const ratio = Math.max(size / img.width, size / img.height);
        const w = img.width * ratio;
        const h = img.height * ratio;
        ctx.drawImage(img, (size - w) / 2, (size - h) / 2, w, h);
        Identity.current.profileImage = canvas.toDataURL('image/jpeg', 0.85);
        await DB.put('identity', Identity.current);
        UI.renderIdentity();
        UI.updateHeaderCompose();
        UI.toast('✓ Profilbild uppdaterad', 'success');
      };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
    e.target.value = '';
  });

  document.getElementById('btn-edit-profile')?.addEventListener('click', () => {
    const name = prompt('Nytt visningsnamn:', Identity.current?.name);
    if (!name?.trim()) return;
    const bio = prompt('Ny biografi:', Identity.current?.bio || '');
    Identity.current.name = name.trim();
    Identity.current.bio = bio?.trim() || '';
    DB.put('identity', Identity.current);
    UI.renderIdentity();
    UI.updateHeaderCompose();
    UI.toast('✓ Profil uppdaterad', 'success');
  });

  document.getElementById('btn-toggle-recovery')?.addEventListener('click', () => {
    const section = document.getElementById('recovery-section');
    const icon = document.getElementById('recovery-toggle-icon');
    const open = section.style.display === 'none';
    section.style.display = open ? 'block' : 'none';
    icon.textContent = open ? '▾' : '▸';
  });

  document.getElementById('btn-setup-recovery')?.addEventListener('click', async () => {
    UI.toast('🛡 Genererar 3 återställningsfragment...', 'info');
    const shards = await Identity.createRecoveryShards(3);
    localStorage.setItem('mycel-recovery-shards', JSON.stringify(shards));
    UI.renderIdentity();
    UI.toast('✓ 3 fragment skapade — dela med betrodda vänner', 'success');
  });

  function doLogout() {
    sessionStorage.setItem('loggedOut', '1');
    sessionStorage.removeItem('currentDb');
    location.reload();
  }

  document.getElementById('btn-nav-logout')?.addEventListener('click', () => {
    doLogout();
  });

  document.getElementById('btn-reset-identity')?.addEventListener('click', async () => {
    if (!confirm('⚠ Detta raderar din identitet och ALL data. Kan inte ångras. Fortsätta?')) return;
    const currentDb = sessionStorage.getItem('currentDb');
    // Remove this user from the accounts registry
    const accounts = JSON.parse(localStorage.getItem('mycel-accounts') || '[]');
    localStorage.setItem('mycel-accounts', JSON.stringify(accounts.filter(a => a.dbName !== currentDb)));
    // Remove user-specific localStorage data
    localStorage.removeItem('mycel-contacts');
    localStorage.removeItem('mycel-recovery-shards');
    localStorage.setItem('mycel-skip-migration', '1');
    // Remove stale signaling keys
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && k.startsWith('mycel-sig-')) localStorage.removeItem(k);
    }
    // Töm alla stores via öppen anslutning (garanterat — fungerar även om SW blockerar deleteDatabase)
    await DB.clear('identity');
    await DB.clear('posts');
    await DB.clear('peers');
    await DB.clear('seen');
    await DB.clear('likes');
    await DB.clear('comments');
    await DB.clear('comment_likes');
    // Stäng anslutningen och försök radera hela databasen
    if (DB.db) { DB.db.close(); DB.db = null; }
    if (currentDb) {
      indexedDB.deleteDatabase(currentDb); // bästa försök — blockeras ibland av SW
    }
    // Avregistrera SW så den inte håller gamla DB-anslutningar vid nästa laddning
    if ('serviceWorker' in navigator) {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map(r => r.unregister()));
    }
    sessionStorage.clear();
    location.reload();
  });

  // PWA install
  let deferredInstall = null;
  window.addEventListener('beforeinstallprompt', e => {
    e.preventDefault();
    deferredInstall = e;
    document.getElementById('install-banner')?.classList.add('show');
  });
  document.getElementById('btn-install')?.addEventListener('click', () => {
    deferredInstall?.prompt();
  });
  document.getElementById('btn-install-dismiss')?.addEventListener('click', () => {
    document.getElementById('install-banner')?.classList.remove('show');
  });

}

// App version för cache-invalidering
const APP_VERSION = '1.0.5';

// Start
// Tema-toggle (samma mönster som ../blogg)
document.addEventListener('DOMContentLoaded', () => {
  const checkbox = document.getElementById('theme-checkbox');
  if (!checkbox) return;
  const saved = localStorage.getItem('theme');
  if (saved === 'light-mode') {
    document.body.classList.add('light-mode');
    checkbox.checked = true;
  }
  checkbox.addEventListener('change', function () {
    if (this.checked) {
      document.body.classList.add('light-mode');
      localStorage.setItem('theme', 'light-mode');
    } else {
      document.body.classList.remove('light-mode');
      localStorage.setItem('theme', 'dark-mode');
    }
  });
});

document.addEventListener('DOMContentLoaded', init);

window.addEventListener('beforeunload', () => {
  const closing = JSON.stringify({ type: 'closing', from: Identity.current?.pubkey });
  for (const [, conn] of Peers.connections) {
    if (conn.channel?.readyState === 'open') {
      try { conn.channel.send(closing); } catch { }
    }
  }
});
