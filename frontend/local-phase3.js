'use strict';

// This inventory is deliberately separate from the token/Sub2API table. A
// remote email is not authority to select a local credential record.
const localPhase3State = {
  listing: null,
  selected: new Set(),
  loading: false,
  submitting: false,
  generation: 0,
  page: 0,
};
const localPhase3Elements = Object.fromEntries([
  'Button', 'ActionHint', 'Dialog', 'Form', 'Summary', 'SelectAll', 'Reload',
  'Rows', 'Error', 'Cancel', 'Confirm',
  'Previous', 'Next', 'Page',
].map((name) => [name, document.querySelector('#localPhase3' + name)]));

function localPhase3Email(value) {
  return typeof value === 'string' && value.length <= 320
    && value === value.trim().toLowerCase()
    && !/[\p{Cc}\p{Cs}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}]/u.test(value)
    && /^[^\s@]+@[^\s@]+$/.test(value)
    && !reconciliationDisplayLooksLikeCredential(value)
    ? value : '';
}

function localPhase3Reason(reason) {
  const labels = {
    phase3_account_invalid: '本地登录记录格式无效',
    phase3_account_terminal: '账号已删除、停用或禁用',
    phase3_account_ambiguous: '本地邮箱或手机存在重复记录',
    phase3_password_missing: '本地记录缺少密码',
    phase3_source_present: '已有活动 token，请从账号表发起 Phase 3',
    username_missing: '本地账号不存在',
    username_email_invalid: '本地邮箱格式无效',
    username_ambiguous: '本地邮箱或手机存在重复记录',
    username_phone_invalid: '本地手机号格式无效',
    username_password_missing: '本地记录缺少密码',
    username_terminal: '账号已删除、停用或禁用',
    phase3_target_invalid: '本地记录无法生成安全快照凭证',
  };
  return Object.hasOwn(labels, reason) ? labels[reason] : '本地记录未通过安全核验';
}

function localPhase3ListingProblem(listing) {
  const invalid = '本地账号清单不完整或格式无效，已禁止提交；请重新读取';
  if (!listing || typeof listing.readOnly !== 'boolean'
      || typeof listing.capabilities?.phase3Enabled !== 'boolean'
      || !Array.isArray(listing.accounts) || listing.accounts.length > 100_000
      || listing.summary?.total !== listing.accounts.length
      || !Number.isSafeInteger(listing.summary?.eligible)
      || !Number.isSafeInteger(listing.summary?.ineligible)
      || listing.summary.eligible < 0 || listing.summary.ineligible < 0
      || listing.summary.eligible + listing.summary.ineligible !== listing.accounts.length) return invalid;
  const keys = new Set();
  const eligibleEmails = new Set();
  const eligiblePhones = new Set();
  for (const account of listing.accounts) {
    if (!account || typeof account !== 'object' || Array.isArray(account)
        || typeof account.selectedKey !== 'string'
        || !/^username:(?:0|[1-9]\d*)$/.test(account.selectedKey)
        || !Number.isSafeInteger(Number(account.selectedKey.slice(9)))
        || keys.has(account.selectedKey) || typeof account.eligible !== 'boolean'
        || (account.email !== null && (typeof account.email !== 'string' || account.email.length > 320))
        || (account.phone !== null && (typeof account.phone !== 'string' || account.phone.length > 80))
        || typeof account.status !== 'string' || account.status.length > 128
        || (account.reason !== null && (typeof account.reason !== 'string' || account.reason.length > 128))) return invalid;
    keys.add(account.selectedKey);
    if (!account.eligible) continue;
    if (!localPhase3Email(account.email)
        || (account.phone && !/^\d{1,80}$/.test(account.phone))
        || !/^phase3-local-v1\.[A-Za-z0-9_-]{43}$/.test(String(account.phase3TargetRevision || ''))
        || eligibleEmails.has(account.email)
        || (account.phone && eligiblePhones.has(account.phone))) return invalid;
    eligibleEmails.add(account.email);
    if (account.phone) eligiblePhones.add(account.phone);
  }
  return listing.accounts.filter((account) => account.eligible).length === listing.summary.eligible
    ? '' : invalid;
}

function localPhase3Selection() {
  const listing = localPhase3State.listing;
  if (!listing) return { targets: [], problem: '请先读取本地账号' };
  const listingProblem = localPhase3ListingProblem(listing);
  if (listingProblem) return { targets: [], problem: listingProblem };
  if (listing.readOnly || !listing.capabilities.phase3Enabled) {
    return { targets: [], problem: '本地清单未确认可写且 Phase 3 已启用，请重新读取' };
  }
  const selected = localPhase3State.selected;
  if (selected.size === 0) return { targets: [], problem: '请选择符合条件的本地记录' };
  if (selected.size > 100) return { targets: [], problem: '本地 Phase 3 每批最多 100 个，请减少选择；不会自动跳过超出项' };
  const accounts = listing.accounts.filter((account) => selected.has(account.selectedKey));
  if (accounts.length !== selected.size || accounts.some((account) => !account.eligible)) {
    return { targets: [], problem: '所选记录已不在当前可执行清单中，请重新读取' };
  }
  return {
    targets: accounts.map(({ selectedKey, email, phone, phase3TargetRevision }) => ({
      selectedKey, email, phone: phone || '', phase3TargetRevision,
    })),
    problem: '',
  };
}

function localPhase3ActionProblem() {
  if (state.jobInventoryVerified !== true) return '正在确认后台任务和待对账项';
  if (reconciliationWriteBlocked()) return '存在待人工对账任务，当前全部写操作已阻止';
  if (actionsLocked()) return '另一个任务、清单读取或快照刷新正在执行';
  if (state.snapshot?.readOnly !== false) return '当前面板未确认可写';
  if (!phase3CapabilityAvailable()) return '服务端未启用本地 Phase 3';
  return '';
}

function updateLocalPhase3ActionState() {
  const problem = localPhase3ActionProblem();
  if (localPhase3Elements.Button) {
    localPhase3Elements.Button.disabled = Boolean(problem);
    localPhase3Elements.Button.title = problem || '独立读取 username.json 中的本地登录账号；不使用远程表格的选择';
  }
  if (localPhase3Elements.ActionHint) {
    localPhase3Elements.ActionHint.hidden = !problem;
    localPhase3Elements.ActionHint.textContent = problem ? '本地账号获取 token：' + problem : '';
  }
  if (!localPhase3Elements.Dialog?.open) return;
  const selection = localPhase3Selection();
  const busy = localPhase3State.loading || localPhase3State.submitting;
  localPhase3Elements.Confirm.disabled = busy || Boolean(problem) || Boolean(selection.problem);
  localPhase3Elements.Reload.disabled = busy || Boolean(problem);
  localPhase3Elements.Cancel.disabled = localPhase3State.submitting;
  localPhase3Elements.SelectAll.disabled = busy || Boolean(problem) || !localPhase3State.listing;
  const accountCount = localPhase3State.listing?.accounts.length || 0;
  localPhase3Elements.Previous.disabled = busy || localPhase3State.page === 0;
  localPhase3Elements.Next.disabled = busy || (localPhase3State.page + 1) * 100 >= accountCount;
  for (const input of localPhase3Elements.Rows.querySelectorAll('input[data-local-phase3-key]')) {
    input.disabled = busy || Boolean(problem) || input.dataset.eligible !== 'true';
  }
  if (localPhase3State.listing && !localPhase3State.submitting) {
    const summary = localPhase3State.listing.summary;
    localPhase3Elements.Summary.textContent = '本地记录 ' + summary.total + ' · 可选 ' + summary.eligible
      + ' · 不可选 ' + summary.ineligible + ' · 已选 ' + localPhase3State.selected.size
      + (problem || selection.problem ? '；' + (problem || selection.problem) : '；可提交');
  }
}

function renderLocalPhase3Rows() {
  const accounts = localPhase3State.listing?.accounts || [];
  const pageCount = Math.max(1, Math.ceil(accounts.length / 100));
  localPhase3State.page = Math.max(0, Math.min(pageCount - 1, localPhase3State.page));
  const visibleAccounts = accounts.slice(localPhase3State.page * 100, (localPhase3State.page + 1) * 100);
  localPhase3Elements.Page.textContent = '第 ' + (localPhase3State.page + 1) + '/' + pageCount + ' 页，每页最多 100 条';
  localPhase3Elements.Rows.innerHTML = visibleAccounts.map((account) => {
    const checked = localPhase3State.selected.has(account.selectedKey) ? ' checked' : '';
    const index = account.selectedKey.slice(9);
    const email = localPhase3Email(account.email) || '邮箱未通过核验';
    const phone = /^\d{1,80}$/.test(account.phone) ? account.phone : '';
    const status = ['active', 'inactive', 'disabled', 'error', 'account_deleted', 'discard', 'pending']
      .includes(account.status) ? account.status : '未标注或未知';
    return '<tr><td><input type="checkbox" data-local-phase3-key="' + escapeHtml(account.selectedKey)
      + '" data-eligible="' + account.eligible + '" aria-label="选择本地记录 ' + index + '"'
      + checked + (account.eligible ? '' : ' disabled') + '></td><td>username.json #'
      + index + '<small>0 基记录索引</small></td><td>' + escapeHtml(email)
      + (phone ? '<small>' + escapeHtml(phone) + '</small>' : '') + '</td><td>' + escapeHtml(status)
      + '<small>' + escapeHtml(account.eligible ? '可获取 token' : localPhase3Reason(account.reason))
      + '</small></td></tr>';
  }).join('');
  const eligible = visibleAccounts.filter((account) => account.eligible);
  localPhase3Elements.SelectAll.checked = eligible.length > 0
    && eligible.every((account) => localPhase3State.selected.has(account.selectedKey));
  localPhase3Elements.SelectAll.indeterminate = eligible.some((account) => localPhase3State.selected.has(account.selectedKey))
    && !localPhase3Elements.SelectAll.checked;
  updateLocalPhase3ActionState();
}

function showLocalPhase3Error(message) {
  localPhase3Elements.Error.hidden = !message;
  localPhase3Elements.Error.textContent = message || '';
}

async function loadLocalPhase3Accounts() {
  if (localPhase3State.loading || localPhase3State.submitting || localPhase3ActionProblem()) return false;
  const generation = ++localPhase3State.generation;
  localPhase3State.listing = null;
  localPhase3State.selected = new Set();
  localPhase3State.page = 0;
  localPhase3State.loading = true;
  state.localPhase3ListingPending = true;
  showLocalPhase3Error('');
  localPhase3Elements.Summary.textContent = '正在读取本地账号…';
  renderLocalPhase3Rows();
  updateActionState();
  try {
    const response = await apiFetch('/api/phase3/local-accounts');
    const listing = await response.json();
    if (generation !== localPhase3State.generation || !localPhase3Elements.Dialog.open) return false;
    if (!response.ok) throw new Error('本地账号读取失败，请检查服务与日志后重新读取');
    const problem = localPhase3ListingProblem(listing);
    if (problem) throw new Error(problem);
    localPhase3State.listing = listing;
    return true;
  } catch (error) {
    if (generation === localPhase3State.generation) {
      showLocalPhase3Error('本地账号读取失败或清单无法核验，未提交任何任务；请重新读取。');
      localPhase3Elements.Summary.textContent = '本地账号尚未核验';
    }
    return false;
  } finally {
    if (generation === localPhase3State.generation) {
      localPhase3State.loading = false;
      state.localPhase3ListingPending = false;
      renderLocalPhase3Rows();
      updateActionState();
    }
  }
}

async function openLocalPhase3Dialog() {
  if (localPhase3ActionProblem()) return;
  const dialog = localPhase3Elements.Dialog;
  if (!dialog || typeof dialog.showModal !== 'function') {
    showNotice('浏览器无法打开本地账号确认框，未提交任何任务。', 'notice-warning');
    return;
  }
  dialog.returnValue = '';
  dialog.showModal();
  await loadLocalPhase3Accounts();
}

async function submitLocalPhase3(event) {
  event.preventDefault();
  if (localPhase3State.submitting) return;
  if (event.submitter?.value !== 'confirm') {
    localPhase3Elements.Dialog.close('cancel');
    return;
  }
  const selection = localPhase3Selection();
  const problem = localPhase3ActionProblem() || selection.problem;
  if (problem) { showLocalPhase3Error(problem); return; }
  const targets = selection.targets;
  if (!window.confirm('确认对 ' + targets.length + ' 个已勾选的 username.json 本地记录获取 token？'
      + '\n不使用远程账号邮箱关联，任务串行执行，不会自动导入 Sub2API。')) return;
  localPhase3State.submitting = true;
  state.phase3RequestPending = true;
  showLocalPhase3Error('');
  updateActionState();
  try {
    const { response, body } = await idempotentMutationFetch('phase3', '/api/phase3/local', {
      accounts: targets, selectedKeys: targets.map((target) => target.selectedKey),
    });
    if (!response.ok) {
      showLocalPhase3Error('本地 Phase 3 未获确认；'
        + (mutationRejectionSummary(body.rejected, 'phase3') || '请重新核验本地记录及任务状态'));
      // A non-2xx response does not prove admission had no durable effects.
      // Recheck complete inventory before considering any unlock or retry.
      await loadSnapshot({ resumeJobs: true });
      return;
    }
    const jobIds = body.jobIds;
    if (!Array.isArray(jobIds) || !jobIds.length || jobIds.length > targets.length
        || jobIds.some((id) => !/^job_[a-f0-9]{24}$/.test(String(id)))
        || new Set(jobIds).size !== jobIds.length) {
      throw new Error('LOCAL_PHASE3_RECEIPT_INVALID');
    }
    const rejected = mutationRejectionSummary(body.rejected, 'phase3');
    localPhase3State.submitting = false;
    localPhase3Elements.Dialog.close('submitted');
    showNotice('本地 Phase 3 已排队 ' + jobIds.length + ' 个任务'
      + (rejected ? '；' + rejected : '') + '。获取后请另行预览并确认导入。', 'notice-info');
    await watchJobs(jobIds);
  } catch {
    showLocalPhase3Error('提交结果暂时无法确认，后台仍可能执行；请先核实任务状态，不要更改目标重复提交。');
    await loadSnapshot({ resumeJobs: true });
  } finally {
    localPhase3State.submitting = false;
    if (!state.job || !['queued', 'running', 'unknown'].includes(state.job.status)) {
      state.phase3RequestPending = false;
    }
    updateActionState();
  }
}

localPhase3Elements.Button?.addEventListener('click', openLocalPhase3Dialog);
localPhase3Elements.Reload?.addEventListener('click', loadLocalPhase3Accounts);
localPhase3Elements.Form?.addEventListener('submit', submitLocalPhase3);
localPhase3Elements.SelectAll?.addEventListener('change', () => {
  if (localPhase3State.loading || localPhase3State.submitting || localPhase3ActionProblem()) return;
  const eligible = (localPhase3State.listing?.accounts || [])
    .slice(localPhase3State.page * 100, (localPhase3State.page + 1) * 100)
    .filter((account) => account.eligible);
  for (const account of eligible) {
    if (localPhase3Elements.SelectAll.checked) localPhase3State.selected.add(account.selectedKey);
    else localPhase3State.selected.delete(account.selectedKey);
  }
  renderLocalPhase3Rows();
});
for (const [control, step] of [['Previous', -1], ['Next', 1]]) {
  localPhase3Elements[control]?.addEventListener('click', () => {
    if (localPhase3State.loading || localPhase3State.submitting) return;
    localPhase3State.page += step;
    renderLocalPhase3Rows();
  });
}
localPhase3Elements.Rows?.addEventListener('change', (event) => {
  if (localPhase3State.loading || localPhase3State.submitting || localPhase3ActionProblem()) return;
  const key = event.target?.dataset?.localPhase3Key;
  const account = localPhase3State.listing?.accounts.find((item) => item.selectedKey === key);
  if (!account?.eligible) return;
  if (event.target.checked) localPhase3State.selected.add(key);
  else localPhase3State.selected.delete(key);
  renderLocalPhase3Rows();
});
localPhase3Elements.Dialog?.addEventListener('cancel', (event) => {
  if (localPhase3State.submitting) event.preventDefault();
});
localPhase3Elements.Dialog?.addEventListener('close', () => {
  if (localPhase3State.submitting) return;
  localPhase3State.generation += 1;
  localPhase3State.loading = false;
  state.localPhase3ListingPending = false;
  localPhase3State.listing = null;
  localPhase3State.selected = new Set();
  showLocalPhase3Error('');
  updateActionState();
});
updateLocalPhase3ActionState();
