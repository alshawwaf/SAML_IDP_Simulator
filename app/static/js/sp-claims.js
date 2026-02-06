document.addEventListener("DOMContentLoaded", () => {
  bindRemoveHandlers();
  document.getElementById("add-claim-btn")?.addEventListener("click", () =>
    addRow("#claims-body")
  );
  document.getElementById("edit-add-claim-btn")?.addEventListener("click", () =>
    addRow("#edit-claims-body")
  );
});

function bindRemoveHandlers() {
  document.querySelectorAll(".remove-claim").forEach(button => {
    button.removeEventListener("click", handleRemove);
    button.addEventListener("click", handleRemove);
  });
}

function handleRemove(event) {
  const row = this.closest("tr");
  if (row) {
    row.remove();
    reindexRows("#claims-body");
    reindexRows("#edit-claims-body");
  }
}

function addRow(tbodySelector) {
  const tbody = document.querySelector(tbodySelector);
  const index = tbody.querySelectorAll("tr").length;

  const optionsHtml = USER_FIELDS.map(field =>
    `<option value="${field}">${field}</option>`
  ).join("");

  const row = document.createElement("tr");
  row.innerHTML = `
    <td><input name="claim_name_${index}" class="form-control" required></td>
    <td>
      <select name="claim_value_{{ loop.index0 }}" class="form-select" required>

        ${optionsHtml}
      </select>
    </td>
    <td class="text-center">
      <button type="button" class="btn btn-sm btn-outline-danger remove-claim">
        <i class="bi bi-trash"></i>
      </button>
    </td>
  `;
  tbody.appendChild(row);
  bindRemoveHandlers();
  reindexRows(tbodySelector);
}

function reindexRows(tbodySelector) {
  const rows = document.querySelectorAll(`${tbodySelector} tr`);
  rows.forEach((row, index) => {
    const claimInput = row.querySelector("input[name^='claim_name_']");
    const valueSelect = row.querySelector("select[name^='claim_value_']");
    if (claimInput) claimInput.name = `claim_name_${index}`;
    if (valueSelect) valueSelect.name = `claim_value_${index}`;
  });
}
