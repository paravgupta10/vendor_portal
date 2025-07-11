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

document.addEventListener('DOMContentLoaded', () => {
  showOwnershipFields(); // already called

  // Initialize counts from DOM
  partnerCount = document.querySelectorAll('#partner-container .partner-block').length + 1;
  LLPCount = document.querySelectorAll('#llp-container .partner-block').length + 1;
  pvtDirectorCount = document.querySelectorAll('#pvtltd-container .director-block').length + 1;
  directorCount = document.querySelectorAll('#publicltd-container .director-block').length + 1;

});
document.getElementById('ownership').addEventListener('change', showOwnershipFields);

function isLastSectionFilled(containerSelector, inputSelector = 'input, textarea') {
  const groups = document.querySelectorAll(containerSelector);
  if (!groups.length) return true;
  const lastGroup = groups[groups.length - 1];
  return Array.from(lastGroup.querySelectorAll(inputSelector)).every(el => el.value.trim() !== '');
}

let branchAddressCount = 1;
function addBranchAddress() {
  if (!isLastSectionFilled('#branch-addresses .branch-group')) {
    alert("Please fill the last branch address fields before adding a new one.");
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
    </div>
  `;
  container.appendChild(groupWrapper);
}

function addEntity(containerId, countVarName, label, namePrefix) {
  if (!isLastSectionFilled(`#${containerId} .input-group`)) {
    alert(`Please complete the last ${label.toLowerCase()} details before adding a new one.`);
    return;
  }

  const container = document.getElementById(containerId);
  if (!container) return;

  // Ensure counter is initialized
  window[countVarName] = window[countVarName] || 1;

  const count = window[countVarName]; // Use current count for labeling

  const wrapper = document.createElement('div');
  wrapper.classList.add(containerId.includes("director") ? 'director-block' : 'partner-block');
  wrapper.innerHTML = `
    <h4>${label} ${count} Details</h4>
    <div class="input-group"><label>Name</label><input type="text" name="${namePrefix}${count}_name" maxlength="100"></div>
    <div class="input-group"><label>Email</label><input type="email" name="${namePrefix}${count}_email" maxlength="100"></div>
    <div class="input-group"><label>Phone</label><input type="tel" name="${namePrefix}${count}_phone" maxlength="10" pattern="\\d{10}" title="Please enter exactly 10 digits"></div>
    <div class="input-group"><label>PAN Number</label><input type="text" name="${namePrefix}${count}_pan" maxlength="10"></div>
  `;
  container.appendChild(wrapper);

  window[countVarName]++; // Increment after using
}



function addPartner()       { addEntity('partner-container', 'partnerCount', 'Partner', 'partner'); }
function addLLP()           { addEntity('llp-container', 'LLPCount', 'Partner', 'partner'); }
function addPvtDirector()   { addEntity('pvtltd-container', 'pvtDirectorCount', 'Director', 'director'); }
function addPubDirector()   { addEntity('publicltd-container', 'directorCount', 'Director', 'dir'); }

function addProductField() {
  if (!isLastSectionFilled('#product-services-container .input-group')) {
    alert("Please complete the last product/service field before adding a new one.");
    return;
  }

  const container = document.getElementById('product-services-container');
  const count = container.querySelectorAll('input').length + 1;

  const inputGroup = document.createElement('div');
  inputGroup.className = 'input-group';

  const label = document.createElement('label');
  label.setAttribute('for', `product_${count}`);
  label.innerText = `Product/Service ${count}`;

  const input = document.createElement('input');
  input.type = 'text';
  input.name = 'products[]';
  input.id = `product_${count}`;
  input.placeholder = 'Enter product or service';
  input.required = true;
  input.maxLength = 100;

  inputGroup.appendChild(label);
  inputGroup.appendChild(input);
  container.appendChild(inputGroup);
}

function validateFormat(id, pattern, message) {
  const input = document.getElementById(id);
  if (input && !new RegExp(pattern).test(input.value)) {
    alert(message);
    input.focus();
    return false;
  }
  return true;
}

function validateFileInput(id, errorId) {
  const fileInput = document.getElementById(id);
  const errorMsg = document.getElementById(errorId);

  if (!fileInput.files.length) {
    alert(`Please upload a file for ${id}.`);
    fileInput.focus();
    return false;
  }

  const file = fileInput.files[0];
  const validTypes = ['application/pdf', 'image/jpeg'];

  if (!validTypes.includes(file.type)) {
    alert(`Invalid file type for ${id}. Please upload PDF or JPEG.`);
    fileInput.focus();
    return false;
  }

  if (file.size > 2 * 1024 * 1024) {
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
    alert('Please select an ownership type.');
    e.preventDefault();
    return;
  }

  const isValidTAN = validateFormat('tan_number', '^[A-Z]{4}[0-9]{5}[A-Z]$', 'Invalid TAN format');
  const isValidGST = validateFormat('gst_number', '^\\d{2}[A-Z]{5}\\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$', 'Invalid GST format');
  const isValidPhone = validateFormat('phone', '^[6-9][0-9]{9}$', 'Invalid phone number format');
  const areFilesValid = fileValidations.every(({ id, errorId }) => validateFileInput(id, errorId));

  if (!(isValidTAN && isValidGST && isValidPhone && areFilesValid)) {
    e.preventDefault();
  }
});
