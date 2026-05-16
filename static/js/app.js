const cipherSelect = document.getElementById("cipher");
const actionSelect = document.getElementById("action");
const keyFields = document.getElementById("keyFields");
const form = document.getElementById("cipherForm");
const resultOutput = document.getElementById("resultOutput");
const stepsList = document.getElementById("stepsList");
const workingTable = document.getElementById("workingTable");
const metaOutput = document.getElementById("metaOutput");
const aiExplanation = document.getElementById("aiExplanation");
const alertBox = document.getElementById("alertBox");
const runBtn = document.getElementById("runBtn");
const copyResult = document.getElementById("copyResult");
const fillDemo = document.getElementById("fillDemo");
const resetKeys = document.getElementById("resetKeys");
const modePill = document.getElementById("modePill");
const textInput = document.getElementById("text");
const textHint = document.getElementById("textHint");

const fields = {
  caesar: [
    { id: "shift", label: "Shift Value", type: "number", value: "3", help: "Example: 3" },
  ],
  affine: [
    { id: "a", label: "a Value", type: "number", value: "5", help: "Must be coprime with 26" },
    { id: "b", label: "b Value", type: "number", value: "8", help: "Addition key" },
  ],
  vigenere: [
    { id: "key", label: "Keyword", type: "text", value: "KEY", help: "Letters only, e.g. SECURITY", wide: true },
  ],
  substitution: [
    {
      id: "substitution_key",
      label: "26-Letter Substitution Key",
      type: "text",
      value: "QWERTYUIOPASDFGHJKLZXCVBNM",
      help: "Must contain every A-Z letter exactly once",
      wide: true,
    },
  ],
  rsa: [
    { id: "p", label: "Prime p", type: "number", value: "61", help: "Prime number" },
    { id: "q", label: "Prime q", type: "number", value: "53", help: "Prime number" },
    { id: "e", label: "Public exponent e", type: "number", value: "17", help: "gcd(e, φ(n)) must be 1", wide: true },
  ],
  dsa: [
    { id: "dsa_p", label: "p", type: "number", value: "59", help: "Prime p" },
    { id: "dsa_q", label: "q", type: "number", value: "29", help: "Prime q divides p-1" },
    { id: "dsa_g", label: "g", type: "number", value: "4", help: "Generator" },
    { id: "dsa_x", label: "Private key x", type: "number", value: "5", help: "Used for signing" },
    { id: "dsa_k", label: "Random k", type: "number", value: "7", help: "Used for signing" },
    { id: "dsa_y", label: "Public key y", type: "number", value: "", help: "Optional for verify. Default calculated from x." },
    { id: "dsa_r", label: "Signature r", type: "number", value: "", help: "Required for verify" },
    { id: "dsa_s", label: "Signature s", type: "number", value: "", help: "Required for verify" },
  ],
  asa: [
    { id: "aes_key", label: "Secret Key", type: "text", value: "information-security-key", help: "Same key is required for decrypt", wide: true },
  ],
};

const demos = {
  caesar: "HELLO INFORMATION SECURITY",
  affine: "HELLO AFFINE CIPHER",
  vigenere: "ATTACK AT DAWN",
  substitution: "SUBSTITUTION CIPHER DEMO",
  rsa: "HELLO",
  dsa: "This message is authentic",
  asa: "Confidential semester project text",
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setActions() {
  const cipher = cipherSelect.value;
  actionSelect.innerHTML = "";
  const actions = cipher === "dsa"
    ? [
        { value: "sign", label: "Sign" },
        { value: "verify", label: "Verify" },
      ]
    : [
        { value: "encrypt", label: "Encrypt" },
        { value: "decrypt", label: "Decrypt" },
      ];
  for (const action of actions) {
    const option = document.createElement("option");
    option.value = action.value;
    option.textContent = action.label;
    actionSelect.appendChild(option);
  }
  updateModePill();
}

function updateModePill() {
  const label = actionSelect.options[actionSelect.selectedIndex]?.textContent || "Mode";
  modePill.textContent = `${label} Mode`;
  if (cipherSelect.value === "rsa" && actionSelect.value === "decrypt") {
    textHint.textContent = "For RSA decryption, paste encrypted numbers separated by spaces or commas.";
  } else if (cipherSelect.value === "asa" && actionSelect.value === "decrypt") {
    textHint.textContent = "For ASA/AES decryption, paste Base64 output from encryption and use the same secret key.";
  } else if (cipherSelect.value === "dsa") {
    textHint.textContent = "DSA signs/verifies message authenticity. It does not encrypt text.";
  } else {
    textHint.textContent = "Enter plain text for encryption or ciphertext for decryption.";
  }
}

function renderFields(resetValues = false) {
  const cipher = cipherSelect.value;
  keyFields.innerHTML = "";
  const selectedFields = fields[cipher] || [];
  for (const field of selectedFields) {
    const wrapper = document.createElement("div");
    wrapper.className = `field-group ${field.wide ? "wide" : ""}`;
    wrapper.innerHTML = `
      <label for="${field.id}">${field.label}</label>
      <input id="${field.id}" name="${field.id}" type="${field.type}" value="${resetValues ? field.value : field.value}" />
      <small>${field.help}</small>
    `;
    keyFields.appendChild(wrapper);
  }
}

function collectKeys() {
  const keys = {};
  const inputs = keyFields.querySelectorAll("input");
  inputs.forEach((input) => {
    keys[input.name] = input.value;
  });
  return keys;
}

function showAlert(message, type = "error") {
  alertBox.textContent = message;
  alertBox.classList.remove("hidden", "success");
  if (type === "success") alertBox.classList.add("success");
}

function clearAlert() {
  alertBox.classList.add("hidden");
  alertBox.textContent = "";
  alertBox.classList.remove("success");
}

function renderOutput(data) {
  resultOutput.value = data.result || "";
  aiExplanation.textContent = data.ai_explanation || "No explanation returned.";
  stepsList.innerHTML = "";
  workingTable.innerHTML = "";
  metaOutput.textContent = JSON.stringify(data.meta || {}, null, 2);

  const warnings = data.warnings || [];
  if (warnings.length) {
    showAlert(warnings.join(" "), "success");
  } else {
    showAlert("Done. Result generated successfully.", "success");
  }

  (data.steps || []).forEach((step) => {
    const li = document.createElement("li");
    li.textContent = step;
    stepsList.appendChild(li);
  });

  (data.table || []).forEach((row) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(row.char ?? "")}</td>
      <td>${escapeHtml(row.value_before ?? "")}</td>
      <td>${escapeHtml(row.formula ?? "")}</td>
      <td>${escapeHtml(row.value_after ?? "")}</td>
      <td>${escapeHtml(row.output ?? "")}</td>
    `;
    workingTable.appendChild(tr);
  });
}

async function submitForm(event) {
  event.preventDefault();
  clearAlert();
  runBtn.disabled = true;
  runBtn.textContent = "Processing...";

  const payload = {
    cipher: cipherSelect.value,
    action: actionSelect.value,
    text: textInput.value,
    keys: collectKeys(),
  };

  try {
    const response = await fetch("/api/process", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok || !data.ok) {
      throw new Error(data.error || "Something went wrong.");
    }
    renderOutput(data);
  } catch (error) {
    showAlert(error.message);
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Run Cipher";
  }
}

function initTabs() {
  const tabs = document.querySelectorAll(".tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((item) => item.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.remove("active"));
      tab.classList.add("active");
      const tabName = tab.dataset.tab;
      document.getElementById(`${tabName}Panel`).classList.add("active");
    });
  });
}

cipherSelect.addEventListener("change", () => {
  setActions();
  renderFields(true);
  textInput.value = demos[cipherSelect.value] || "";
  clearAlert();
  updateModePill();
});

actionSelect.addEventListener("change", updateModePill);
form.addEventListener("submit", submitForm);
resetKeys.addEventListener("click", () => renderFields(true));

fillDemo.addEventListener("click", () => {
  textInput.value = demos[cipherSelect.value] || "HELLO";
  renderFields(true);
  clearAlert();
});

copyResult.addEventListener("click", async () => {
  if (!resultOutput.value) {
    showAlert("No result to copy yet.");
    return;
  }
  try {
    await navigator.clipboard.writeText(resultOutput.value);
    showAlert("Result copied to clipboard.", "success");
  } catch {
    resultOutput.select();
    document.execCommand("copy");
    showAlert("Result copied.", "success");
  }
});

setActions();
renderFields(true);
textInput.value = demos.caesar;
initTabs();
