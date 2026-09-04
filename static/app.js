"use strict";

const el = (id) => document.getElementById(id);
const BASE = document.querySelector('meta[name="app-base"]')?.content || "";
const AUTO_AUTH_KEY = "netease_mail_auto_auth_v1";
let csrfToken = "";

function show(id) { el(id).classList.remove("hidden"); }
function hide(id) { el(id).classList.add("hidden"); }
function exampleUrl(path) { return `${BASE}${path}`; }

async function jsonFetch(url, options = {}) {
  const response = await fetch(url, {credentials: "same-origin", cache: "no-store", ...options});
  const data = await response.json().catch(() => ({ok: false, message: "服务返回了无法识别的内容"}));
  if (!response.ok || data.ok === false) {
    const error = new Error(data.message || `请求失败（${response.status}）`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function applyIdentity(user) {
  el("name").textContent = user.name || "—";
  el("employeeNo").textContent = user.employeeNo || "—";
  el("workEmail").textContent = user.workEmail || "未填写";
  el("mobile").textContent = user.mobileMasked || "未填写";
  el("departmentPath").textContent = (user.departmentPath || []).join(" / ") || "未能读取";
  if (user.departmentWarning) {
    el("departmentWarning").textContent = user.departmentWarning;
    show("departmentWarning");
  } else {
    hide("departmentWarning");
  }
}

const mailStateLabels = {
  matched: "已开通", eligible: "可以开通", conflict: "信息冲突",
  blocked: "资料不完整", error: "查询失败", loading: "查询中"
};

function setMailState(state) {
  const badge = el("state");
  badge.dataset.state = state;
  badge.textContent = mailStateLabels[state] || state;
}

function renderChecks(checks = {}) {
  const rows = [...document.querySelectorAll("[data-check]")];
  let visible = 0;
  for (const row of rows) {
    const value = checks[row.dataset.check];
    if (value === undefined) { row.classList.add("hidden"); continue; }
    row.classList.remove("hidden");
    row.dataset.value = value ? "yes" : "no";
    row.querySelector("b").textContent = value ? "一致" : "不一致";
    visible += 1;
  }
  el("checks").classList.toggle("hidden", visible === 0);
}

function renderRecord(record) {
  if (!record) { hide("record"); return; }
  el("primaryEmail").textContent = record.primaryEmail || "—";
  el("aliases").textContent = (record.aliases || []).join("、") || "无";
  el("neteaseMobile").textContent = record.mobileMasked || "未登记";
  el("unitPath").textContent = (record.unitPath || []).map((item) => item.unitName).join(" / ") || "未归属目标组织";
  show("record");
}

function renderMailStatus(data) {
  const state = data.state || "error";
  const actions = data.actions || {};
  setMailState(state);
  el("message").textContent = data.message || "查询完成";
  el("message").dataset.state = state;
  renderChecks(data.checks || {});
  renderRecord(data.record);
  el("provision").disabled = !actions.provision;
  el("mailPassword").disabled = !actions.password;
  if (data.readOnly) {
    el("provisionHint").textContent = "服务当前为只读模式，开通与改密已停用。";
  } else if (actions.provision) {
    el("provisionHint").textContent = "点击开通后，系统按你的飞书工作邮箱创建账号，初始密码通过飞书发送给你。";
  } else if (actions.password) {
    el("provisionHint").textContent = "邮箱已开通。重置密码前需要重新完成飞书授权，新密码通过飞书发送给你。";
  } else if (state === "matched") {
    el("provisionHint").textContent = "员工信息与现有网易账号匹配，不支持重复开通。";
  } else {
    el("provisionHint").textContent = "存在资料缺失或冲突，禁止自动创建账号，请联系管理员。";
  }
}

function mailMessage(text, kind = "info") {
  el("mailMessage").textContent = text;
  el("mailMessage").dataset.state = kind === "success" ? "matched" : kind === "error" ? "error" : "loading";
  show("mailMessage");
}

async function mailAction(name) {
  const label = name === "provision" ? "开通企业邮箱" : "重置邮箱密码";
  if (!window.confirm(`确认${label}？新密码会通过飞书私聊发送给你本人。`)) return;
  ["provision", "mailPassword", "refresh"].forEach((id) => { el(id).disabled = true; });
  mailMessage("正在处理，请勿重复点击…");
  try {
    const result = await jsonFetch(exampleUrl(`/api/action/${name}`), {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrfToken},
      body: "{}"
    });
    mailMessage((result.data && result.data.message) || "操作成功", "success");
    renderMailStatus(result.data || {});
  } catch (error) {
    mailMessage(error.message, "error");
    if (error.status === 401) beginLogin();
  } finally {
    el("refresh").disabled = false;
  }
}

async function loadMailStatus(refresh = false) {
  setMailState("loading");
  el("message").textContent = refresh ? "正在绕过缓存重新核对…" : "正在读取网易企业邮箱信息…";
  el("refresh").disabled = true;
  el("provision").disabled = true;
  el("mailPassword").disabled = true;
  try {
    const result = await jsonFetch(exampleUrl(refresh ? "/api/refresh" : "/api/status"), refresh ? {
      method: "POST",
      headers: {"X-CSRF-Token": csrfToken, "Content-Type": "application/json"},
      body: "{}"
    } : {});
    renderMailStatus(result.data || {});
  } catch (error) {
    setMailState("error");
    el("message").textContent = error.message;
    el("message").dataset.state = "error";
    renderChecks({});
    renderRecord(null);
    if (error.status === 401) beginLogin();
  } finally {
    el("refresh").disabled = false;
  }
}

function showLogin() {
  hide("loading");
  hide("workspace");
  show("login");
}

async function initializeSession() {
  const result = await jsonFetch(exampleUrl("/api/me"));
  sessionStorage.removeItem(AUTO_AUTH_KEY);
  csrfToken = result.csrfToken;
  applyIdentity(result.user || {});
  hide("login");
  hide("loading");
  show("workspace");
  await loadMailStatus(false);
}

function beginLogin() {
  sessionStorage.setItem(AUTO_AUTH_KEY, "1");
  window.location.assign(exampleUrl("/auth/feishu/start"));
}

async function init() {
  try {
    await initializeSession();
  } catch (error) {
    if (error.status === 401) {
      const loggedOut = new URLSearchParams(window.location.search).get("logged_out") === "1";
      const attempted = sessionStorage.getItem(AUTO_AUTH_KEY) === "1";
      if (!loggedOut && !attempted) {
        beginLogin();
        return;
      }
      if (loggedOut) sessionStorage.removeItem(AUTO_AUTH_KEY);
      showLogin();
      return;
    }
    showLogin();
    el("login").querySelector("p").textContent = error.message;
  }
}

el("loginButton").addEventListener("click", beginLogin);
el("refresh").addEventListener("click", () => loadMailStatus(true));
el("provision").addEventListener("click", () => mailAction("provision"));
el("mailPassword").addEventListener("click", () => mailAction("password"));
init();
