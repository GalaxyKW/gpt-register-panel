'use strict';

// Pure local-ledger matching. Email alone never establishes an account mapping.
// Keep this file byte-identical to the panel's registrationContinuationIdentity.js.
const TERMINAL = new Set(['account_deactivated', 'account_deleted', 'account_disabled', 'deactivated', 'deleted', 'disabled']);
function phone(value) {
    return typeof value === 'string' && value.length <= 64 && !/[^0-9 +().-]/.test(value) ? value.replace(/\D/g, '') : '';
}
function email(value) {
    return typeof value === 'string' && /^[^\s@/\\]+@[^\s@/\\]+\.[^\s@/\\]+$/.test(value.trim()) ? value.trim().toLowerCase() : '';
}
function password(value) { return typeof value === 'string' && value.trim() && !/[\x00\r\n]/.test(value); }
function isLocalAccountTerminal(row) {
    return !!row && (TERMINAL.has(String(row.status || '').trim().toLowerCase())
        || row.disabled === true || row.enabled === false || row.active === false
        || (typeof row.phase3Disposition === 'string' && row.phase3Disposition.trim().toLowerCase() === 'discard'));
}
function resolvePhase3LocalIdentity(accounts, usernames, index) {
    const reject = reason => ({ ok: false, reason });
    const account = accounts?.[index];
    if (!account || !Array.isArray(usernames) || !phone(account.phone) || !password(account.password)) return reject('LOCAL_CREDENTIALS_MISSING');
    if (isLocalAccountTerminal(account)) return reject('LOCAL_ACCOUNT_TERMINAL');
    const number = phone(account.phone);
    if (accounts.filter(item => phone(item?.phone) === number).length !== 1) return reject('LOCAL_PHONE_AMBIGUOUS');
    const matches = usernames.map((item, index) => ({ item, index })).filter(({ item }) => phone(item?.phone) === number);
    if (matches.length !== 1) return reject(matches.length ? 'LOCAL_USERNAME_AMBIGUOUS' : 'LOCAL_USERNAME_MISSING');
    const { item: username, index: usernameIndex } = matches[0];
    if (!password(username.password) || username.password !== account.password) return reject('LOCAL_PASSWORD_MISMATCH');
    if (String(account.smsActivationId || '') !== String(username.smsActivationId || '')) return reject('LOCAL_ACTIVATION_MISMATCH');
    if (isLocalAccountTerminal(username)) return reject('LOCAL_ACCOUNT_TERMINAL');
    const address = email(username.email);
    if (!address) return reject('LOCAL_EMAIL_MISSING');
    if (usernames.filter(item => email(item?.email) === address).length !== 1) return reject('LOCAL_EMAIL_AMBIGUOUS');
    if (accounts.some((item, itemIndex) => itemIndex !== index && email(item?.email) === address)) return reject('LOCAL_EMAIL_AMBIGUOUS');
    for (const existing of [account.email, account.phase2Email]) {
        if (existing !== undefined && existing !== null && existing !== '' && email(existing) !== address) return reject('LOCAL_EMAIL_MISMATCH');
    }
    return { ok: true, email: address, usernameIndex, repairEmail: !email(account.email) };
}
module.exports = { resolvePhase3LocalIdentity, isLocalAccountTerminal };
