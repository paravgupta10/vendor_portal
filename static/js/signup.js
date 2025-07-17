/**
 * Displays a custom styled alert message.
 * @param {string} message The message to display.
 * @param {string} type The type of alert ('error', 'success'). Defaults to 'error'.
 * @param {number} duration The duration in milliseconds before the alert fades out.
 */
function showAlert(message, type = 'error', duration = 4000) {
  const alertBox = document.createElement('div');
  alertBox.className = `custom-alert ${type}`;
  alertBox.textContent = message;

  const closeButton = document.createElement('span');
  closeButton.className = 'close-btn';
  closeButton.innerHTML = '&times;';
  closeButton.onclick = () => {
    alertBox.classList.add('hide');
    alertBox.addEventListener('transitionend', () => alertBox.remove());
  };
  alertBox.appendChild(closeButton);

  document.body.appendChild(alertBox);

  setTimeout(() => alertBox.classList.add('show'), 10);

  setTimeout(() => {
    alertBox.classList.add('hide');
    alertBox.addEventListener('transitionend', () => alertBox.remove());
  }, duration);
}

// --- Initialize Counters and Event Listeners ---
document.addEventListener('DOMContentLoaded', () => {
  // Check for success messages flashed from the server
  const flashedMessage = document.querySelector('.flashed-message');
  if (flashedMessage) {
    const message = flashedMessage.dataset.message;
    const category = flashedMessage.dataset.category;
    showAlert(message, category, 6000);
  }
  
  showOwnershipFields();
  
  partnerCount = document.querySelectorAll('#partner-container .partner-block').length + 1;
  LLPCount = document.querySelectorAll('#llp-container .partner-block').length + 1;
  pvtDirectorCount = document.querySelectorAll('#pvtltd-container .director-block').length + 1;
  directorCount = document.querySelectorAll('#publicltd-container .director-block').length + 1;
  branchAddressCount = document.querySelectorAll('#branch-addresses .branch-group').length;
});

document.getElementById('ownership').addEventListener('change', showOwnershipFields);

// --- Core Form Logic ---
function showOwnershipFields() {
  const groups = document.querySelectorAll('.ownership-group');
  groups.forEach(group => {
    group.hidden = true;
    group.querySelectorAll('input, textarea, select').forEach(el => {
      el.disabled = true;
      el.value = '';
    });
  });

  const ownership = document.getElementById('ownership').value;
  if (ownership) {
    const activeGroup = document.getElementById(`${ownership}-fields`);
    if (activeGroup) {
      activeGroup.hidden = false;
      activeGroup.querySelectorAll('input, textarea, select').forEach(el => {
        el.disabled = false;
      });
    }
  }
}

/**
 * Checks if the last block in a container has all its inputs filled.
 * @param {string} containerSelector - The CSS selector for the main container.
 * @param {string} blockSelector - The CSS selector for the repeatable blocks within the container.
 * @param {string} inputSelector - The CSS selector for inputs to check within a block.
 */
function isLastSectionFilled(containerSelector, blockSelector, inputSelector = 'input') {
    const container = document.querySelector(containerSelector);
    if (!container) return true;

    const blocks = container.querySelectorAll(blockSelector);
    if (blocks.length === 0) return true;

    const lastBlock = blocks[blocks.length - 1];
    const inputs = lastBlock.querySelectorAll(inputSelector);
    if (inputs.length === 0) return true;

    return Array.from(inputs).every(el => el.value.trim() !== '');
}

/**
 * Generic function to remove the last added element from a container.
 */
function removeLastField(containerSelector, itemSelector, minItems) {
  const container = document.querySelector(containerSelector);
  if (!container) return false;

  const items = container.querySelectorAll(itemSelector);
  if (items.length > minItems) {
    container.removeChild(items[items.length - 1]);
    return true;
  } else {
    showAlert(`Cannot remove. A minimum of ${minItems} item(s) is required.`, 'error');
    return false;
  }
}

// --- Branch Address Functions ---
function addBranchAddress() {
  if (!isLastSectionFilled('#branch-addresses', '.branch-group', 'textarea, input')) {
    showAlert("Please fill the last branch address before adding a new one.");
    return;
  }
  branchAddressCount++;
  const container = document.getElementById('branch-addresses');
  const groupWrapper = document.createElement('div');
  groupWrapper.className = 'branch-group';
  groupWrapper.innerHTML = `
    <div class="input-group">
      <label for="baddress_${branchAddressCount}">Address of Branch Office ${branchAddressCount}</label>
      <textarea id="baddress_${branchAddressCount}" name="baddress[]" maxlength="100" placeholder="Enter your branch address"></textarea>
    </div>
    <div class="input-group">
      <label for="bcity_${branchAddressCount}">City</label>
      <input type="text" id="bcity_${branchAddressCount}" name="bcity[]" maxlength="30" placeholder="Enter your branch city"/>
    </div>
    <div class="input-group">
      <label for="bstate_${branchAddressCount}">State</label>
      <input type="text" id="bstate_${branchAddressCount}" name="bstate[]" maxlength="30" placeholder="Enter your branch state"/>
    </div>
    <div class="input-group">
      <label for="bcountry_${branchAddressCount}">Country</label>
      <input type="text" id="bcountry_${branchAddressCount}" name="bcountry[]" maxlength="30" placeholder="Enter your branch country"/>
    </div>`;
  container.appendChild(groupWrapper);
}

function removeBranchAddress() {
  if (removeLastField('#branch-addresses', '.branch-group', 1)) {
    branchAddressCount--;
  }
}

// --- Entity (Partner/Director) Functions ---
function addEntity(containerId, countVarName, label, namePrefix) {
  const blockSelector = containerId.includes("director") ? '.director-block' : '.partner-block';
  if (!isLastSectionFilled(`#${containerId}`, blockSelector)) {
    showAlert(`Please complete the last ${label.toLowerCase()} details before adding a new one.`);
    return;
  }
  const container = document.getElementById(containerId);
  if (!container) return;
  const count = window[countVarName];
  const wrapper = document.createElement('div');
  wrapper.className = blockSelector.substring(1);
  wrapper.innerHTML = `
    <h4>${label} ${count} Details</h4>
    <div class="input-group"><label>Name</label><input type="text" name="${namePrefix}${count}_name" maxlength="100"></div>
    <div class="input-group"><label>Email</label><input type="email" name="${namePrefix}${count}_email" maxlength="100"></div>
    <div class="input-group"><label>Phone</label><input type="tel" name="${namePrefix}${count}_phone" maxlength="10" pattern="\\d{10}" title="Please enter exactly 10 digits"></div>
    <div class="input-group"><label>PAN Number</label><input type="text" name="${namePrefix}${count}_pan" maxlength="10"></div>`;
  container.appendChild(wrapper);
  window[countVarName]++;
}

function removeEntity(containerId, countVarName, minItems) {
  const itemSelector = containerId.includes("director") ? '.director-block' : '.partner-block';
  if (removeLastField(`#${containerId}`, itemSelector, minItems)) {
    window[countVarName]--;
  }
}

// CORRECTED: Prefixes now match the backend Python code
function addPartner()     { addEntity('partner-container', 'partnerCount', 'Partner', 'partner'); }
function removePartner()  { removeEntity('partner-container', 'partnerCount', 2); }

function addLLP()         { addEntity('llp-container', 'LLPCount', 'Partner', 'partner'); }
function removeLLP()      { removeEntity('llp-container', 'LLPCount', 2); }

function addPvtDirector() { addEntity('pvtltd-container', 'pvtDirectorCount', 'Director', 'director'); }
function removePvtDirector(){ removeEntity('pvtltd-container', 'pvtDirectorCount', 2); }

function addPubDirector() { addEntity('publicltd-container', 'directorCount', 'Director', 'dir'); }
function removePubDirector(){ removeEntity('publicltd-container', 'directorCount', 3); }


// --- Product/Service Functions ---
function addProductField() {
  if (!isLastSectionFilled('#product-services-container', '.input-group')) {
    showAlert("Please complete the last product/service field before adding a new one.");
    return;
  }
  const container = document.getElementById('product-services-container');
  const count = container.querySelectorAll('.input-group').length + 1;
  const inputGroup = document.createElement('div');
  inputGroup.className = 'input-group';
  inputGroup.innerHTML = `
    <label for="product_${count}">Product/Service ${count}</label>
    <input type="text" name="products[]" id="product_${count}" placeholder="Enter product or service" required maxlength="100">`;
  container.appendChild(inputGroup);
}

function removeProductField() {
  removeLastField('#product-services-container', '.input-group', 3);
}

// --- Form Validation ---
function validateFormat(id, pattern, message) {
  const input = document.getElementById(id);
  if (input && input.value && !new RegExp(pattern).test(input.value)) {
    showAlert(message);
    input.focus();
    return false;
  }
  return true;
}

function validateFileInput(id, errorId) {
  const fileInput = document.getElementById(id);
  const errorMsg = document.getElementById(errorId);
  if (!fileInput.files.length) {
    return true; 
  }
  const file = fileInput.files[0];
  const validTypes = ['application/pdf', 'image/jpeg'];
  if (!validTypes.includes(file.type)) {
    showAlert(`Invalid file type for ${id}. Please upload PDF or JPEG.`, 'error');
    fileInput.value = "";
    fileInput.focus();
    return false;
  }
  if (file.size > 2 * 1024 * 1024) { // 2MB limit
    showAlert(`File for ${id} is too large. Maximum size is 2MB.`, 'error');
    errorMsg.style.display = "inline";
    fileInput.value = "";
    fileInput.focus();
    return false;
  } else {
    errorMsg.style.display = "none";
  }
  return true;
}

const fileValidations = [
  { id: "tan_proof", errorId: "tan_proof_error" },
  { id: "gst_proof", errorId: "gst_proof_error" },
  { id: "bs_year1", errorId: "bs1_proof_error" },
  { id: "bs_year2", errorId: "bs2_proof_error" },
  { id: "bs_year3", errorId: "bs3_proof_error" }
];

fileValidations.forEach(({ id, errorId }) => {
  const el = document.getElementById(id);
  if (el) {
    el.addEventListener("change", () => validateFileInput(id, errorId));
  }
});

document.querySelector('form').addEventListener('submit', function (e) {
  const ownership = document.getElementById('ownership').value;
  if (!ownership) {
    e.preventDefault();
    showAlert('Please select an ownership type.');
    return;
  }
  const runValidations = (...validations) => {
    for (const validation of validations) {
      if (!validation.check()) {
        e.preventDefault();
        return false;
      }
    }
    return true;
  };
  runValidations(
    { check: () => validateFormat('tan_number', '^[A-Z]{4}[0-9]{5}[A-Z]$', 'Invalid TAN format') },
    { check: () => validateFormat('gst_number', '^\\d{2}[A-Z]{5}\\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$', 'Invalid GST format') },
    { check: () => validateFormat('phone', '^[6-9][0-9]{9}$', 'Invalid phone number format') },
    ...fileValidations.map(fv => ({
      check: () => {
        const input = document.getElementById(fv.id);
        if (input.required && !input.files.length) {
          showAlert(`Please upload the required file for ${fv.id}.`, 'error');
          input.focus();
          return false;
        }
        return validateFileInput(fv.id, fv.errorId);
      }
    }))
  );
});