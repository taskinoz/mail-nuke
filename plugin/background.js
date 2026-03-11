const DEFAULT_SETTINGS = {
  automaticEnabled: true,
  manualEnabled: true,
  serviceUrl: "http://127.0.0.1:8765/score",
  requestTimeoutMs: 15000,
  spamLabelValue: "spam",
  spamScoreThreshold: 0.9,
  moveEnabled: true,
  moveDestinationMode: "junk", // junk | custom
  customFolderId: "",
  markJunkEnabled: true,
  markReadEnabled: false,
  tagEnabled: false,
  monitorAllFolders: false,
  dryRun: false,
  autoOnlyInboxLike: true,
  includeRawHeaders: false
};

const state = {
  settings: { ...DEFAULT_SETTINGS },
  processing: new Set()
};

async function loadSettings() {
  const stored = await messenger.storage.local.get(Object.keys(DEFAULT_SETTINGS));
  state.settings = { ...DEFAULT_SETTINGS, ...stored };
  return state.settings;
}

async function saveSettings(patch) {
  await messenger.storage.local.set(patch);
  await loadSettings();
}

function normalizeSpecialUse(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map((v) => String(v).toLowerCase());
  }
  return [String(value).toLowerCase()];
}

function isFolderPathLikeInbox(folder) {
  const specialUse = normalizeSpecialUse(folder?.specialUse);
  if (specialUse.includes("inbox")) return true;

  const path = String(folder?.path || "").toLowerCase();
  return path.endsWith("/inbox") || path === "/inbox" || path === "inbox";
}

async function iterateMessageList(messageList) {
  const items = [...(messageList?.messages || [])];
  let listId = messageList?.id || null;

  while (listId) {
    const nextPage = await messenger.messages.continueList(listId);
    items.push(...(nextPage?.messages || []));
    listId = nextPage?.id || null;
  }

  return items;
}

function stripTags(html) {
  return String(html || "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function collectTextParts(part, out) {
  if (!part || typeof part !== "object") return;

  const contentType = String(part.contentType || "").toLowerCase();

  if (part.body && contentType.startsWith("text/")) {
    if (contentType.startsWith("text/plain")) {
      out.plain.push(part.body);
    } else if (contentType.startsWith("text/html")) {
      out.html.push(part.body);
    }
  }

  for (const child of part.parts || []) {
    collectTextParts(child, out);
  }
}

async function buildScorePayload(messageHeader) {
  const full = await messenger.messages.getFull(messageHeader.id, {
    decodeContent: true
  });

  const parts = { plain: [], html: [] };
  collectTextParts(full, parts);

  const bodyText = parts.plain.length
    ? parts.plain.join("\n\n")
    : stripTags(parts.html.join("\n\n"));

  let raw = "";
  if (state.settings.includeRawHeaders) {
    try {
      const rawFile = await messenger.messages.getRaw(messageHeader.id);
      raw = await rawFile.text();
    } catch (error) {
      console.warn("Failed to read raw message", error);
    }
  }

  return {
    messageId: messageHeader.id,
    from_header: messageHeader.author || "",
    subject: messageHeader.subject || "",
    body: bodyText || "",
    date: messageHeader.date ? new Date(messageHeader.date).toISOString() : null,
    folder: messageHeader.folder
      ? {
          id: messageHeader.folder.id,
          accountId: messageHeader.folder.accountId,
          name: messageHeader.folder.name,
          path: messageHeader.folder.path,
          specialUse: messageHeader.folder.specialUse || null
        }
      : null,
    raw: raw || undefined
  };
}

async function callScoringService(payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), state.settings.requestTimeoutMs);

  try {
    const res = await fetch(state.settings.serviceUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    if (!res.ok) {
      throw new Error(`Scoring service returned ${res.status}`);
    }

    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

function isSpamResult(result) {
  if (!result || typeof result !== "object") return false;

  if (
    String(result.label || "").toLowerCase() ===
    String(state.settings.spamLabelValue).toLowerCase()
  ) {
    return true;
  }

  const score = Number(result.spamScore);
  return Number.isFinite(score) && score >= Number(state.settings.spamScoreThreshold);
}

function walkFolders(folder, predicate) {
  if (!folder) return null;
  if (predicate(folder)) return folder;

  for (const child of folder.subFolders || []) {
    const found = walkFolders(child, predicate);
    if (found) return found;
  }

  return null;
}

async function findFolderById(folderId) {
  if (!folderId) return null;

  const accounts = await messenger.accounts.list(true);
  for (const account of accounts) {
    const found = walkFolders(account.rootFolder, (folder) => folder.id === folderId);
    if (found) return found;
  }

  return null;
}

async function findJunkFolderForMessage(messageHeader) {
  const targetAccountId = messageHeader?.folder?.accountId || null;
  const accounts = await messenger.accounts.list(true);

  const preferredAccounts = targetAccountId
    ? [
        ...accounts.filter((a) => a.id === targetAccountId),
        ...accounts.filter((a) => a.id !== targetAccountId)
      ]
    : accounts;

  for (const account of preferredAccounts) {
    const found = walkFolders(account.rootFolder, (folder) =>
      normalizeSpecialUse(folder.specialUse).includes("junk")
    );
    if (found) return found;
  }

  return null;
}

async function getDestinationFolder(messageHeader) {
  if (state.settings.moveDestinationMode === "custom") {
    const custom = await findFolderById(state.settings.customFolderId);
    if (custom) return custom;
  }

  return await findJunkFolderForMessage(messageHeader);
}

async function applyActions(messageHeader, result, reason) {
  if (state.settings.dryRun) {
    return { moved: false, markedJunk: false, dryRun: true };
  }

  let markedJunk = false;
  let moved = false;

  if (state.settings.markJunkEnabled) {
    await messenger.messages.update(messageHeader.id, { junk: true });
    markedJunk = true;
  }

  if (state.settings.markReadEnabled) {
    await messenger.messages.update(messageHeader.id, { read: true });
  }

  if (state.settings.moveEnabled) {
    const destination = await getDestinationFolder(messageHeader);

    if (destination?.id) {
      await messenger.messages.move(
        [messageHeader.id],
        destination.id,
        { isUserAction: reason === "manual" }
      );
      moved = true;
    } else {
      console.warn("No destination folder found for spam message", messageHeader.id);
    }
  }

  return { moved, markedJunk, dryRun: false };
}

async function scoreAndMaybeProcess(messageHeader, reason = "manual") {
  const dedupeKey = `${messageHeader.id}:${reason}`;
  if (state.processing.has(dedupeKey)) return null;

  state.processing.add(dedupeKey);

  try {
    const payload = await buildScorePayload(messageHeader);
    const result = await callScoringService(payload);
    const spam = isSpamResult(result);

    let actions = null;
    if (spam) {
      actions = await applyActions(messageHeader, result, reason);
    }

    return { payload, result, spam, actions };
  } finally {
    state.processing.delete(dedupeKey);
  }
}

async function scoreDisplayedMessages(tabId) {
  const displayed = await messenger.messageDisplay.getDisplayedMessages(tabId);
  const messages = await iterateMessageList(displayed);
  const results = [];

  for (const message of messages) {
    const processed = await scoreAndMaybeProcess(message, "manual");
    results.push({
      messageId: message.id,
      ...processed
    });
  }

  return results;
}

async function updateActionForTab(tabId) {
  if (state.settings.manualEnabled) {
    await messenger.messageDisplayAction.enable(tabId);
    await messenger.messageDisplayAction.setTitle({
      tabId,
      title: "Score this message"
    });
  } else {
    await messenger.messageDisplayAction.disable(tabId);
    await messenger.messageDisplayAction.setTitle({
      tabId,
      title: "Manual scoring disabled in Local Spam Filter settings"
    });
  }
}

async function maybeHandleNewMail(folder, messageList) {
  if (!state.settings.automaticEnabled) return;
  if (state.settings.autoOnlyInboxLike && !isFolderPathLikeInbox(folder)) return;

  const messages = await iterateMessageList(messageList);

  for (const message of messages) {
    try {
      await scoreAndMaybeProcess(message, "automatic");
    } catch (error) {
      console.error("Automatic scoring failed", error, message);
    }
  }
}

messenger.runtime.onInstalled.addListener(async () => {
  await loadSettings();
});

messenger.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local") return;

  const patch = {};
  for (const [key, value] of Object.entries(changes)) {
    patch[key] = value.newValue;
  }

  Object.assign(state.settings, patch);
});

messenger.messages.onNewMailReceived.addListener(
  (folder, messages) => {
    maybeHandleNewMail(folder, messages);
  },
  true
);

messenger.messageDisplayAction.onClicked.addListener(async (tab) => {
  try {
    const results = await scoreDisplayedMessages(tab.id);
    const spamCount = results.filter((r) => r?.spam).length;

    await messenger.messageDisplayAction.setBadgeText({
      tabId: tab.id,
      text: spamCount ? String(spamCount) : ""
    });

    await messenger.messageDisplayAction.setTitle({
      tabId: tab.id,
      title: spamCount
        ? `Scored ${results.length} message(s), ${spamCount} marked as spam`
        : `Scored ${results.length} message(s), no spam detected`
    });
  } catch (error) {
    console.error("Manual scoring failed", error);

    await messenger.messageDisplayAction.setBadgeText({
      tabId: tab.id,
      text: "!"
    });

    await messenger.messageDisplayAction.setTitle({
      tabId: tab.id,
      title: `Manual scoring failed: ${error?.message || error}`
    });
  }
});

messenger.messageDisplay.onMessagesDisplayed.addListener(async (tab) => {
  try {
    await updateActionForTab(tab.id);
    await messenger.messageDisplayAction.setBadgeText({ tabId: tab.id, text: "" });
  } catch (error) {
    console.error("Failed to update action state", error);
  }
});

messenger.runtime.onMessage.addListener(async (message) => {
  if (!message || typeof message !== "object") return undefined;

  switch (message.type) {
    case "get-settings":
      await loadSettings();
      return state.settings;

    case "save-settings":
      await saveSettings(message.payload || {});
      return { ok: true, settings: state.settings };

    case "list-folders":
      return await listFoldersForOptions();

    case "test-service":
      return await testService();

    default:
      return undefined;
  }
});

async function listFoldersForOptions() {
  const accounts = await messenger.accounts.list(true);

  return accounts.map((account) => ({
    id: account.id,
    name: account.name,
    folders: flattenFolders(account.rootFolder, account.name)
  }));
}

function flattenFolders(folder, accountName, result = []) {
  if (!folder) return result;

  if (folder.path) {
    result.push({
      id: folder.id,
      name: folder.name,
      path: folder.path,
      accountId: folder.accountId,
      accountName,
      specialUse: normalizeSpecialUse(folder.specialUse)
    });
  }

  for (const child of folder.subFolders || []) {
    flattenFolders(child, accountName, result);
  }

  return result;
}

async function testService() {
  const sample = {
    from_header: "Test Sender <test@example.com>",
    subject: "Test subject",
    body: "Test body"
  };

  try {
    const result = await callScoringService(sample);
    return { ok: true, result };
  } catch (error) {
    return { ok: false, error: String(error?.message || error) };
  }
}

loadSettings().catch(console.error);