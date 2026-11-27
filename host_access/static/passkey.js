'use strict';

(() => {
  const status = document.getElementById('passkey-status');
  const login = document.querySelector('[data-passkey-login]');
  const approval = document.querySelector('form[data-passkey-approve]');
  const enrollment = document.querySelector('form[data-passkey-enroll]');
  let busy = false;

  function decode(value) {
    return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  }

  function encode(value) {
    return btoa(Array.from(new Uint8Array(value), n => String.fromCharCode(n)).join(''))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function options(data, create) {
    const parse = create ? 'parseCreationOptionsFromJSON' : 'parseRequestOptionsFromJSON';
    if (typeof PublicKeyCredential[parse] === 'function') return PublicKeyCredential[parse](data);
    data.challenge = decode(data.challenge);
    if (create) data.user.id = decode(data.user.id);
    const list = create ? data.excludeCredentials : data.allowCredentials;
    for (const item of list || []) item.id = decode(item.id);
    return data;
  }

  function serialize(credential) {
    const r = credential.response;
    const response = {clientDataJSON: encode(r.clientDataJSON)};
    for (const key of ['attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
      if (r[key] != null) response[key] = encode(r[key]);
    }
    if (typeof r.getTransports === 'function') response.transports = r.getTransports();
    return JSON.stringify({id: credential.id, rawId: encode(credential.rawId),
      type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults()});
  }

  async function post(path, data) {
    const result = await fetch(path, {method: 'POST', body: data, redirect: 'error', mode: 'same-origin'});
    if (!result.ok) throw new Error('server');
    return result.json();
  }

  async function run(control, start, finish, fields, create = false, onSuccess = null) {
    if (busy) return;
    if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
      status.textContent = 'Ouvrez cette page dans un navigateur compatible avec les clés d’accès.';
      return;
    }
    busy = true;
    control.disabled = true;
    status.textContent = 'En attente de votre clé d’accès…';
    try {
      const publicKey = options(await post(start, fields), create);
      fields.delete('code');
      const result = create ? await navigator.credentials.create({publicKey}) : await navigator.credentials.get({publicKey});
      if (!result) throw new DOMException('Canceled', 'NotAllowedError');
      fields.set('credential', serialize(result));
      const outcome = await post(finish, fields);
      if (onSuccess) onSuccess(outcome);
      else window.location.assign(outcome.location);
    } catch (error) {
      if (create) {
        status.textContent = 'Inscription non terminée. Déverrouillez votre coffre et générez un nouveau code dans la console PVE.';
      } else {
        status.textContent = error.name === 'NotAllowedError'
          ? 'Clé d’accès annulée ou indisponible. Vérifiez que votre coffre est déverrouillé.'
          : 'Action non confirmée. Actualisez la page avant de réessayer.';
      }
    } finally {
      busy = false;
      control.disabled = false;
    }
  }

  login?.addEventListener('click', () => {
    const csrf = document.querySelector('meta[name="passkey-csrf"]').content;
    run(login, '/passkeys/login/start', '/passkeys/login/finish',
      new URLSearchParams({csrf, request: login.dataset.request || ''}));
  });

  approval?.addEventListener('submit', event => {
    event.preventDefault();
    run(approval.querySelector('button[type=submit]'), `${approval.action}/start`, approval.action,
      new URLSearchParams(new FormData(approval)));
  });

  enrollment?.addEventListener('submit', event => {
    event.preventDefault();
    const fields = new URLSearchParams(new FormData(enrollment));
    enrollment.elements.code.value = '';
    run(enrollment.querySelector('button[type=submit]'), '/passkeys/enroll/start', '/passkeys/enroll/finish',
      fields, true, () => {
        status.textContent = 'Clé enregistrée. Testez-la dans un autre profil avant de désactiver le mot de passe.';
      });
  });
})();
