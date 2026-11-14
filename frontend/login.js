(function () {
  var $ = function (id) { return document.getElementById(id); };
  var mode = 'in', busy = false, cfg = { signup: true, demo: null };

  function note(text, ok) { var m = $('msg'); m.textContent = text || ''; m.className = ok ? 'ok' : ''; }

  function setMode(m) {
    mode = m;
    var up = m === 'up';
    $('t-in').className = up ? '' : 'on'; $('t-up').className = up ? 'on' : '';
    $('t-in').setAttribute('aria-selected', String(!up)); $('t-up').setAttribute('aria-selected', String(up));
    $('c-wrap').hidden = !up;
    $('go').textContent = up ? 'Create account' : 'Sign in';
    $('p').setAttribute('autocomplete', up ? 'new-password' : 'current-password');
    note('');
  }

  function post(path, body) {
    return fetch(path, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'cashpilot' },
      body: JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, data: j }; });
    });
  }

  function submit(user, pass) {
    if (busy) return;
    if (!user || !pass) { note('Enter your username and password.'); return; }
    if (mode === 'up' && pass !== $('c').value) { note('The two passwords do not match.'); return; }
    busy = true; $('go').disabled = true; $('d-go').disabled = true;
    note(mode === 'up' ? 'Creating your account…' : 'Signing in…', true);
    post(mode === 'up' ? '/api/register' : '/api/login', { username: user, password: pass })
      .then(function (res) {
        if (res.ok) { note('Welcome! Loading your dashboard…', true); location.replace('/'); return; }
        note(res.data.error || 'Something went wrong. Please try again.');
        busy = false; $('go').disabled = false; $('d-go').disabled = false;
      })
      .catch(function () {
        note('Cannot reach the server. Is it running?');
        busy = false; $('go').disabled = false; $('d-go').disabled = false;
      });
  }

  $('f').addEventListener('submit', function (e) {
    e.preventDefault();
    submit($('u').value.trim(), $('p').value);
  });
  $('t-in').addEventListener('click', function () { setMode('in'); });
  $('t-up').addEventListener('click', function () { setMode('up'); });
  $('eye').addEventListener('click', function () {
    var show = $('p').type === 'password';
    $('p').type = show ? 'text' : 'password'; $('c').type = show ? 'text' : 'password';
    $('eye').textContent = show ? 'Hide' : 'Show';
    $('eye').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });
  $('d-go').addEventListener('click', function () {
    if (!cfg.demo) return;
    setMode('in');
    $('u').value = cfg.demo.username; $('p').value = cfg.demo.password;
    submit(cfg.demo.username, cfg.demo.password);
  });

  fetch('/api/config', { credentials: 'same-origin' })
    .then(function (r) { return r.json(); })
    .then(function (c) {
      cfg = c;
      if (!c.signup) $('tabs').hidden = true;
      if (c.demo) {
        $('d-u').textContent = c.demo.username; $('d-p').textContent = c.demo.password;
        $('demo').hidden = false;
      }
    })
    .catch(function () {});
  $('u').focus();
})();
