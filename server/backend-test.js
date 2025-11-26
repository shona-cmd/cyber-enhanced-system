import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:3001/api';

async function testApi() {
  try {
    console.log('Testing API status...');
    const statusRes = await fetch(BASE_URL + '/status');
    console.log('Status response:', await statusRes.text());

    console.log('Testing login...');
    const loginRes = await fetch(BASE_URL + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'mtac-admin', password: 'Mtac2025!' })
    });
    const loginData = await loginRes.json();
    console.log('Login response:', loginData);

    if (!loginData.token) {
      console.error('Login failed. Cannot proceed with protected API tests.');
      return;
    }

    console.log('Testing protected /devices API...');
    const devicesRes = await fetch(BASE_URL + '/devices', {
      headers: { Authorization: 'Bearer ' + loginData.token }
    });
    const devicesData = await devicesRes.json();
    console.log('Devices response:', devicesData);

    console.log('Testing protected /audit API...');
    const auditRes = await fetch(BASE_URL + '/audit', {
      headers: { Authorization: 'Bearer ' + loginData.token }
    });
    const auditData = await auditRes.json();
    console.log('Audit response:', auditData);

  } catch (error) {
    console.error('API test error:', error);
  }
}

testApi();
