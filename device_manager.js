document.addEventListener('DOMContentLoaded', function() {
  const registerForm = document.getElementById('registerForm');
  const deviceTableBody = document.querySelector('#deviceTable tbody');
  const totalCountSpan = document.getElementById('totalCount');

  let devices = [];

  // Function to display devices in the table
  function displayDevices() {
    deviceTableBody.innerHTML = '';
    devices.forEach((device, index) => {
      const row = deviceTableBody.insertRow();
      row.insertCell().textContent = index + 1;
      row.insertCell().textContent = device.devId;
      row.insertCell().textContent = device.devType;
      row.insertCell().textContent = device.devDesc || '-';
      row.insertCell().innerHTML = '<span class="status-online">Online</span> <span class="heartbeat">❤️</span>';
      row.insertCell().textContent = 'Just now';
      row.insertCell().innerHTML = '<button class="btn btn-danger btn-sm delete-btn" data-index="' + index + '">Delete</button>';
    });
    totalCountSpan.textContent = devices.length;

    // Add event listeners to delete buttons
    const deleteButtons = document.querySelectorAll('.delete-btn');
    deleteButtons.forEach(button => {
      button.addEventListener('click', function() {
        const index = parseInt(this.dataset.index);
        deleteDevice(index);
      });
    });
  }

  // Function to delete a device
  function deleteDevice(index) {
    devices.splice(index, 1);
    displayDevices();
  }

  // Form submission event listener
  registerForm.addEventListener('submit', function(event) {
    event.preventDefault();

    const devId = document.getElementById('devId').value;
    const devType = document.getElementById('devType').value;
    const devDesc = document.getElementById('devDesc').value;

    const newDevice = {
      devId: devId,
      devType: devType,
      devDesc: devDesc
    };

    devices.push(newDevice);
    displayDevices();

    // Clear the form
    document.getElementById('devId').value = '';
    document.getElementById('devType').value = '';
    document.getElementById('devDesc').value = '';
  });

  // Initial display of devices
  displayDevices();
});
