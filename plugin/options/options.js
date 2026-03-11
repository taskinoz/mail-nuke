const ids = [
  "automaticEnabled",
  "autoOnlyInboxLike",
  "manualEnabled",
  "dryRun",
  "serviceUrl",
  "requestTimeoutMs",
  "spamLabelValue",
  "spamScoreThreshold",
  "includeRawHeaders",
  "markJunkEnabled",
  "markReadEnabled",
  "moveEnabled",
  "moveDestinationMode",
  "customFolderId",
  "tagEnabled",
  "tagName",
  "tagColor"
];

const els = Object.fromEntries(ids.map((id) => [id, document.getElementById(id)]));
const statusEl = document.getElementById("status");
const customFolderWrap = document.getElementById("customFolderWrap");
const testServiceResult = document.getElementById("testServiceResult");

function setStatus(text) {
  statusEl.textContent = text;
  if (text) {
    setTimeout(() => {
      if (statusEl.textContent === text) statusEl.textContent = "";
    }, 2500);
  }
}

function readForm() {
  return {
    automaticEnabled: els.automaticEnabled.checked,
    autoOnlyInboxLike: els.autoOnlyInboxLike.checked,
    manualEnabled: els.manualEnabled.checked,
    dryRun: els.dryRun.checked,
    serviceUrl: els.serviceUrl.value.trim(),
    requestTimeoutMs: Number(els.requestTimeoutMs.value || 15000),
    spamLabelValue: els.spamLabelValue.value.trim() || "spam",
    spamScoreThreshold: Number(els.spamScoreThreshold.value || 0.9),
    includeRawHeaders: els.includeRawHeaders.checked,
    markJunkEnabled: els.markJunkEnabled.checked,
    markReadEnabled: els.markReadEnabled.checked,
    moveEnabled: els.moveEnabled.checked,
    moveDestinationMode: els.moveDestinationMode.value,
    customFolderId: els.customFolderId.value,
    tagEnabled: els.tagEnabled.checked,
    tagName: els.tagName.value.trim() || "SpamFilter",
    tagColor: els.tagColor.value || "#d9480f"
  };
}

function applyForm(settings) {
  els.automaticEnabled.checked = !!settings.automaticEnabled;
  els.autoOnlyInboxLike.checked = !!settings.autoOnlyInboxLike;
  els.manualEnabled.checked = !!settings.manualEnabled;
  els.dryRun.checked = !!settings.dryRun;
  els.serviceUrl.value = settings.serviceUrl || "";
  els.requestTimeoutMs.value = settings.requestTimeoutMs ?? 15000;
  els.spamLabelValue.value = settings.spamLabelValue || "spam";
  els.spamScoreThreshold.value = settings.spamScoreThreshold ?? 0.9;
  els.includeRawHeaders.checked = !!settings.includeRawHeaders;
  els.markJunkEnabled.checked = !!settings.markJunkEnabled;
  els.markReadEnabled.checked = !!settings.markReadEnabled;
  els.moveEnabled.checked = !!settings.moveEnabled;
  els.moveDestinationMode.value = settings.moveDestinationMode || "junk";
  els.tagEnabled.checked = !!settings.tagEnabled;
  els.tagName.value = settings.tagName || "SpamFilter";
  els.tagColor.value = settings.tagColor || "#d9480f";
  updateFolderVisibility();
}

function updateFolderVisibility() {
  customFolderWrap.classList.toggle("hidden", els.moveDestinationMode.value !== "custom");
}

async function loadFolders(selectedFolderId = "") {
  const accounts = await messenger.runtime.sendMessage({ type: "list-folders" });
  els.customFolderId.innerHTML = "";

  for (const account of accounts) {
    const group = document.createElement("optgroup");
    group.label = account.name;
    for (const folder of account.folders) {
      const option = document.createElement("option");
      option.value = folder.id;
      const special = folder.specialUse.length ? ` [${folder.specialUse.join(", ")}]` : "";
      option.textContent = `${folder.path}${special}`;
      if (folder.id === selectedFolderId) {
        option.selected = true;
      }
      group.appendChild(option);
    }
    els.customFolderId.appendChild(group);
  }
}

async function init() {
  const settings = await messenger.runtime.sendMessage({ type: "get-settings" });
  applyForm(settings);
  await loadFolders(settings.customFolderId || "");
}

document.getElementById("save").addEventListener("click", async () => {
  const payload = readForm();
  await messenger.runtime.sendMessage({ type: "save-settings", payload });
  setStatus("Settings saved.");
});

document.getElementById("testService").addEventListener("click", async () => {
  testServiceResult.textContent = "Testing...";
  const result = await messenger.runtime.sendMessage({ type: "test-service" });
  if (result.ok) {
    testServiceResult.textContent = `OK: ${JSON.stringify(result.result)}`;
  } else {
    testServiceResult.textContent = `Failed: ${result.error}`;
  }
});

els.moveDestinationMode.addEventListener("change", updateFolderVisibility);

init().catch((error) => {
  console.error(error);
  setStatus(`Failed to load settings: ${error.message || error}`);
});
