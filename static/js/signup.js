// signup.js

function showOwnershipFields() {
  const groups = document.querySelectorAll('.ownership-group');
  groups.forEach(group => {
    group.hidden = true;
    group.querySelectorAll('input').forEach(input => {
      input.disabled = true;
      input.value = '';
    });
  });

  const ownership = document.getElementById('ownership').value;
  if (ownership) {
    const activeGroup = document.getElementById(`${ownership}-fields`);
    if (activeGroup) {
      activeGroup.hidden = false;
      activeGroup.querySelectorAll('input').forEach(input => {
        input.disabled = false;
      });
    }
  }
}

document.addEventListener('DOMContentLoaded', showOwnershipFields);

document.getElementById('ownership').addEventListener('change', showOwnershipFields);

let branchAddressCount = 1;
function addBranchAddress() {
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

let partnerCount = 2;
function addPartner() {
  partnerCount++;
  const container = document.getElementById('partnership-fields');
  if (!container) return;

  const wrapper = document.createElement('div');
  wrapper.innerHTML = `
    <h4>Partner ${partnerCount} Details</h4>
    <div class="input-group"><label>Name</label><input type="text" name="partner${partnerCount}_name" maxlength="100"></div>
    <div class="input-group"><label>Email</label><input type="email" name="partner${partnerCount}_email" maxlength="100"></div>
    <div class="input-group"><label>Phone</label><input type="tel" name="partner${partnerCount}_phone" maxlength="10" pattern="\\d{10}" title="Please enter exactly 10 digits"></div>
    <div class="input-group"><label>PAN Number</label><input type="text" name="partner${partnerCount}_pan" maxlength="10"></div>
  `;
  container.appendChild(wrapper);
}

let LLPCount = 2;
function addLLP() {
  LLPCount++;
  const container = document.getElementById('llp-fields');
  if (!container) return;

  const wrapper = document.createElement('div');
  wrapper.innerHTML = `
    <h4>Partner ${LLPCount} Details</h4>
    <div class="input-group"><label>Name</label><input type="text" name="partner${LLPCount}_name" maxlength="100"></div>
    <div class="input-group"><label>Email</label><input type="email" name="partner${LLPCount}_email" maxlength="100"></div>
    <div class="input-group"><label>Phone</label><input type="tel" name="partner${LLPCount}_phone" maxlength="10" pattern="\\d{10}" title="Please enter exactly 10 digits"></div>
    <div class="input-group"><label>PAN Number</label><input type="text" name="partner${LLPCount}_pan" maxlength="10"></div>
  `;
  container.appendChild(wrapper);
}

let pvtDirectorCount = 2;
function addPvtDirector() {
  pvtDirectorCount++;
  const container = document.getElementById('pvtltd-fields');
  if (!container) return;

  const wrapper = document.createElement('div');
  wrapper.innerHTML = `
    <h4>Director ${pvtDirectorCount} Details</h4>
    <div class="input-group"><label>Name</label><input type="text" name="director${pvtDirectorCount}_name" maxlength="100"></div>
    <div class="input-group"><label>Email</label><input type="email" name="director${pvtDirectorCount}_email" maxlength="100"></div>
    <div class="input-group"><label>Phone</label><input type="tel" name="director${pvtDirectorCount}_phone" maxlength="10" pattern="\\d{10}" title="Please enter exactly 10 digits"></div>
    <div class="input-group"><label>PAN Number</label><input type="text" name="director${pvtDirectorCount}_pan" maxlength="10"></div>
  `;
  container.appendChild(wrapper);
}

let directorCount = 3;
function addPubDirector() {
  directorCount++;
  const container =document.getElementById('publicltd-fields');
  if (!container) return;

  const wrapper = document.createElement('div');
  wrapper.innerHTML = `
    <h4>Director ${directorCount} Details</h4>
    <div class="input-group"><label>Name</label><input type="text" name="director${directorCount}_name" maxlength="100"></div>
    <div class="input-group"><label>Email</label><input type="email" name="director${directorCount}_email" maxlength="100"></div>
    <div class="input-group"><label>Phone</label><input type="tel" name="director${directorCount}_phone" maxlength="10" pattern="\\d{10}" title="Please enter exactly 10 digits"></div>
    <div class="input-group"><label>PAN Number</label><input type="text" name="director${directorCount}_pan" maxlength="10"></div>
  `;
  container.appendChild(wrapper);
}

function addProductField() {
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
  if (!fileInput.files.length) {
    alert(`Please upload a file for ${id}.`);
    fileInput.focus();
    return false;
  }

  const file = fileInput.files[0];
  const validTypes = ['application/pdf', 'image/jpeg'];
  const errorMsg = document.getElementById(errorId);

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
  document.getElementById(id).addEventListener("change", function () {
    validateFileInput(id, errorId);
  });
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
