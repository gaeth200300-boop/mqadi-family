/* =============================================================================
   api.js — network + session layer for Family Groceries
   -----------------------------------------------------------------------------
   The app renders from a single in-memory `state` object exactly as before.
   This module owns everything that crosses the network boundary:

     • session tokens (access token in memory, refresh token in a cookie)
     • sign-up / sign-in / sign-out / account deletion
     • pulling household state from the server
     • pushing local changes, with an offline outbox that drains on reconnect

   Two integration seams are exposed for index.html:
     API.ready()   -> Promise, resolves once a session is restored (or fails)
     API.commit()  -> called by the app's existing commit() to persist changes

   API_BASE is resolved at runtime so the same bundle works in the browser,
   in the packaged iOS app, and in tests.
============================================================================= */
(function (global) {
  'use strict';

  /* ---------------------------------------------------------------- config */

  var API_BASE =
    (global.FG_API_BASE ||
      (global.localStorage && global.localStorage.getItem('fg_api_base')) ||
      '').replace(/\/+$/, '');

  var REFRESH_PATH = '/api/auth/refresh';
  var LS_SESSION = 'fg_session';

  /* ------------------------------------------------------- session handling */

  var accessToken = null;      // never persisted; short-lived
  var session = null;          // { user, household } — safe to persist for display
  var outbox = [];             // queued mutations while offline
  var online = true;
  var listeners = [];
  var syncing = false;

  function emit(evt) {
    listeners.forEach(function (fn) {
      try { fn(evt); } catch (e) { /* a bad listener must not break sync */ }
    });
  }

  function onChange(fn) { listeners.push(fn); }

  function persistSession() {
    try {
      if (session) localStorage.setItem(LS_SESSION, JSON.stringify(session));
      else localStorage.removeItem(LS_SESSION);
    } catch (e) { /* private mode */ }
  }

  function restoreSession() {
    try { session = JSON.parse(localStorage.getItem(LS_SESSION) || 'null'); }
    catch (e) { session = null; }
  }

  /* ------------------------------------------------------------------ fetch */

  function describe(payload, status) {
    return (payload && payload.message) || ('Request failed (' + status + ')');
  }

  function request(method, path, body, opts) {
    opts = opts || {};
    if (!API_BASE) return Promise.reject(new Error('No API server configured'));

    var headers = { accept: 'application/json' };
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (accessToken) headers.authorization = 'Bearer ' + accessToken;

    var init = {
      method: method,
      headers: headers,
      // Send the refresh cookie so the session survives an app restart.
      credentials: 'include',
      body: body === undefined ? undefined : JSON.stringify(body),
    };

    return fetch(API_BASE + path, init).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { /* non-JSON */ }

        if (res.status === 401 && !opts._retried && !opts._noRetry) {
          // Try exactly one silent refresh, then replay the original request once.
          return refresh().then(function (ok) {
            if (!ok) { clearSession(); throw mkError(data, 401); }
            return request(method, path, body, Object.assign({}, opts, { _retried: true }));
          });
        }
        if (!res.ok) throw mkError(data, res.status);
        return data;
      });
    });
  }

  function mkError(data, status) {
    var e = new Error(describe(data, status));
    e.code = (data && data.error) || 'http_' + status;
    e.status = status;
    return e;
  }

  /**
   * Single-flight refresh.
   *
   * The refresh token is single-use, so two concurrent refreshes race: one wins
   * and the other is rejected, which would sign the user out spuriously. That
   * happens in practice whenever two requests both hit a 401 at the same moment
   * — e.g. syncFromServer fires fetchState() and listMembers() in parallel on a
   * cold start with an expired access token. Callers share one in-flight
   * promise rather than each starting their own.
   */
  var refreshInFlight = null;

  function refresh() {
    if (!API_BASE) return Promise.resolve(false);
    if (refreshInFlight) return refreshInFlight;

    refreshInFlight = fetch(API_BASE + REFRESH_PATH, { method: 'POST', credentials: 'include' })
      .then(function (res) {
        if (!res.ok) return false;
        return res.json().then(function (d) {
          accessToken = d.accessToken;
          session = { user: d.user, household: (session && session.household) || null };
          persistSession();
          return true;
        });
      })
      .catch(function () { return false; })
      .then(function (ok) {
        refreshInFlight = null;  // always clear, so a later attempt can retry
        return ok;
      });

    return refreshInFlight;
  }

  function clearSession() {
    accessToken = null;
    session = null;
    persistSession();
    outbox = [];
    emit({ type: 'signed-out' });
  }

  /* ------------------------------------------------------------------- auth */

  function setConfig(base) {
    API_BASE = String(base || '').replace(/\/+$/, '');
    try { if (API_BASE) localStorage.setItem('fg_api_base', API_BASE); } catch (e) {}
  }

  function signIn(email, password) {
    return request('POST', '/api/auth/login', { email: email, password: password }, { _noRetry: true })
      .then(function (d) {
        accessToken = d.accessToken;
        session = { user: d.user, household: null };
        persistSession();
        emit({ type: 'signed-in', user: d.user });
        return d.user;
      });
  }

  function signUp(fields) {
    return request('POST', '/api/auth/register', fields, { _noRetry: true })
      .then(function (d) {
        accessToken = d.accessToken;
        session = { user: d.user, household: null };
        persistSession();
        emit({ type: 'signed-in', user: d.user });
        return d.user;
      });
  }

  function signOut() {
    var p = API_BASE
      ? request('POST', '/api/auth/logout', undefined, { _noRetry: true }).catch(function () {})
      : Promise.resolve();
    return p.then(function () { clearSession(); });
  }

  /* App Review guideline 5.1.1(v): account deletion must be possible in-app. */
  function deleteAccount() {
    return request('DELETE', '/api/auth/account', undefined, { _noRetry: true })
      .then(function () { clearSession(); });
  }

  function changePassword(currentPassword, newPassword) {
    return request('POST', '/api/auth/change-password', {
      currentPassword: currentPassword, newPassword: newPassword,
    }).then(function (d) {
      accessToken = d.accessToken;
      session = { user: d.user, household: (session && session.household) || null };
      persistSession();
      return d.user;
    });
  }

  function inviteMember(opts) {
    return request('POST', '/api/auth/household/invites', {
      email: opts.email || undefined,
      role: opts.role || 'member',
      expiresInDays: opts.expiresInDays || undefined,
    });
  }

  function listInvites() { return request('GET', '/api/auth/household/invites'); }
  function revokeInvite(id) { return request('DELETE', '/api/auth/household/invites/' + encodeURIComponent(id)); }
  function listMembers() { return request('GET', '/api/auth/household/members'); }
  function setMemberRole(id, role) {
    return request('POST', '/api/auth/household/members/' + encodeURIComponent(id) + '/role', { role: role });
  }
  function setMemberEnabled(id, enabled) {
    return request('POST', '/api/auth/household/members/' + encodeURIComponent(id) + '/' +
      (enabled ? 'enable' : 'disable'), {});
  }

  /* -------------------------------------------------------------- household */

  function fetchState() {
    return request('GET', '/api/lists/state').then(function (d) {
      if (d && d.user) { session = { user: d.user, household: d.household || null }; }
      else if (d) { session = { user: session.user, household: d.household || (session && session.household) || null }; }
      persistSession();
      return d;
    });
  }

  function createList(name, week, budget) {
    return request('POST', '/api/lists', { name: name, week: week, budget: budget });
  }
  /** Creates the opening week for a household that has none yet. */
  function bootstrapList(week, budget) {
    return request('POST', '/api/lists/bootstrap', { week: week, budget: budget });
  }
  function setBudget(budget) { return request('PATCH', '/api/household', { budget: budget }); }
  function finishList(payload) { return request('POST', '/api/lists/finish', payload); }
  function addItem(listId, item) { return request('POST', '/api/lists/' + encodeURIComponent(listId) + '/items', item); }
  function updateItem(id, patch) { return request('PATCH', '/api/items/' + encodeURIComponent(id), patch); }
  function deleteItem(id) { return request('DELETE', '/api/items/' + encodeURIComponent(id)); }
  function markNotificationsRead(ids) { return request('POST', '/api/notifications/read', { ids: ids || undefined }); }

  /* ------------------------------------------------- outbox / offline queue */

  function enqueue(job) {
    outbox.push(job);
    try { localStorage.setItem('fg_outbox', JSON.stringify(outbox)); } catch (e) {}
  }

  function loadOutbox() {
    try { outbox = JSON.parse(localStorage.getItem('fg_outbox') || '[]'); }
    catch (e) { outbox = []; }
  }

  function saveOutbox() {
    try { localStorage.setItem('fg_outbox', JSON.stringify(outbox)); } catch (e) {}
  }

  /**
   * Pushes a queued mutation. Resolves even when offline — the job stays in the
   * outbox and is retried by drain(). Never throws, so it can be called from the
   * app's existing fire-and-forget commit() without risk.
   */
  function push(job) {
    if (!session) return Promise.resolve();
    if (!API_BASE) return Promise.resolve();
    if (!navigator.onLine) { enqueue(job); online = false; return Promise.resolve(); }

    return request(job.method, job.path, job.body, { _noRetry: job.method === 'GET' })
      .catch(function (err) {
        // 4xx means the payload is bad; retrying will never help. Drop it.
        if (err.status >= 400 && err.status < 500 && err.code !== 'unauthorized') return;
        enqueue(job);
      });
  }

  function drain() {
    if (syncing || !session || !outbox.length) return Promise.resolve();
    syncing = true;
    var queue = outbox.slice();
    outbox = [];
    saveOutbox();

    var chain = Promise.resolve();
    queue.forEach(function (job) {
      chain = chain.then(function () {
        return request(job.method, job.path, job.body).catch(function () {
          outbox.push(job); // put it back for the next attempt
        });
      });
    });

    return chain.then(function () {
      syncing = false;
      saveOutbox();
      emit({ type: 'drained', remaining: outbox.length });
    });
  }

  global.addEventListener('online', function () { online = true; drain(); });
  global.addEventListener('offline', function () { online = false; });
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') drain();
  });

  /* ------------------------------------------------------------------ boot */

  /**
   * Restores a session if one exists. Resolves with
   * { signedIn, user, state } — state is null when signed out.
   */
  function ready() {
    restoreSession();
    loadOutbox();
    if (!API_BASE) return Promise.resolve({ signedIn: false, user: null, state: null, configured: false });

    return refresh()
      .then(function (ok) {
        if (!ok) {
          if (session) clearSession();
          return { signedIn: false, user: null, state: null, configured: true };
        }
        return fetchState().then(function (st) {
          drain();
          return { signedIn: true, user: st.user || (session && session.user), state: st, configured: true };
        });
      })
      .catch(function () {
        return { signedIn: false, user: null, state: null, configured: true, offline: true };
      });
  }

  global.FG_API = {
    ready: ready,
    getBase: function () { return API_BASE; },
    setConfig: setConfig,
    isSignedIn: function () { return !!session; },
    getUser: function () { return session && session.user; },
    onChange: onChange,

    signIn: signIn, signUp: signUp, signOut: signOut,
    deleteAccount: deleteAccount, changePassword: changePassword,
    inviteMember: inviteMember, listInvites: listInvites, revokeInvite: revokeInvite,
    listMembers: listMembers, setMemberRole: setMemberRole, setMemberEnabled: setMemberEnabled,

    fetchState: fetchState, createList: createList, bootstrapList: bootstrapList,
    setBudget: setBudget, finishList: finishList,
    addItem: addItem, updateItem: updateItem, deleteItem: deleteItem,
    markNotificationsRead: markNotificationsRead,

    push: push, drain: drain,
    pendingCount: function () { return outbox.length; },
  };
})(typeof window !== 'undefined' ? window : this);
