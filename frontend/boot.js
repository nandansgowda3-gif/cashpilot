/* Checks you are signed in, loads your saved data from the Python backend, then starts the app.
   Opened straight from disk (file://) it skips the backend and uses the browser's storage (no sign-in). */
(function () {
  var KEYS = ['cp2', 'cpo', 'cpl', 'cph', 'cpm', 'cpf', 'cpn'];
  var online = /^https?:$/.test(location.protocol);
  var timers = {};
  var HDR = { 'Content-Type': 'application/json', 'X-Requested-With': 'cashpilot' };

  function start() {
    var s = document.createElement('script');
    s.src = 'app.js';
    document.body.appendChild(s);
  }
  if (!online) { start(); return; }

  function toLogin() { location.replace('/login'); }
  function wipeLocal() {
    KEYS.forEach(function (k) { try { window.localStorage.removeItem(k); } catch (e) {} });
    try { window.localStorage.removeItem('cp_user'); } catch (e) {}
  }

  var orig = Storage.prototype.setItem;
  function push(k, v) {
    clearTimeout(timers[k]);
    timers[k] = setTimeout(function () {
      fetch('/api/state/' + k, {
        method: 'PUT', credentials: 'same-origin', headers: HDR,
        body: JSON.stringify({ value: v })
      }).then(function (r) { if (r.status === 401) toLogin(); }).catch(function () {});
    }, 400);
  }
  Storage.prototype.setItem = function (k, v) {
    orig.call(this, k, v);
    if (this === window.localStorage && KEYS.indexOf(k) >= 0) push(k, String(v));
  };

  function showUser(name) {
    var who = document.getElementById('who');
    if (!who) return;
    document.getElementById('wn').textContent = name;
    who.hidden = false;
    document.getElementById('lo').addEventListener('click', function () {
      fetch('/api/logout', { method: 'POST', credentials: 'same-origin', headers: HDR })
        .catch(function () {})
        .then(function () { wipeLocal(); toLogin(); });
    });
  }

  fetch('/api/me', { credentials: 'same-origin' })
    .then(function (r) { if (r.status === 401) { toLogin(); throw 'auth'; } if (!r.ok) throw 'down'; return r.json(); })
    .then(function (me) {
      // Never let one person's cached data leak into another person's session on a shared browser.
      var prev = null;
      try { prev = window.localStorage.getItem('cp_user'); } catch (e) {}
      if (prev !== me.username) { wipeLocal(); orig.call(window.localStorage, 'cp_user', me.username); }
      showUser(me.username);
      return fetch('/api/state', { credentials: 'same-origin' });
    })
    .then(function (r) { if (r.status === 401) { toLogin(); throw 'auth'; } if (!r.ok) throw new Error('no backend'); return r.json(); })
    .then(function (st) {
      KEYS.forEach(function (k) {
        if (typeof st[k] === 'string') {
          orig.call(window.localStorage, k, st[k]);          // server copy wins
        } else if (window.localStorage.getItem(k) !== null) {
          push(k, window.localStorage.getItem(k));             // first run: upload what this account has locally
        }
      });
      start();
    })
    .catch(function (e) { if (e !== 'auth') start(); });
})();
