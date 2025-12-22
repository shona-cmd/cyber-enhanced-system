# Naashon Secure IoT - Demonstration Instructions

To demonstrate this software locally on all devices, follow these steps:

## Using the Provided Startup Script (Recommended)

1. Run the PowerShell script `start-local.ps1` located in the project root directory.
2. This script will start both the backend server and frontend development server concurrently in separate windows.
3. Wait for both servers to fully start.
4. Note the frontend server IP displayed in the terminal.

## Backend Server

Alternatively, to start servers manually:

1. Open a terminal in the `server` directory.
2. Run the commands:
   ```
   npm install
   npm run start
   ```
3. This will start the backend API server on `https://localhost:3000`.

## Frontend Application

1. Open a terminal in the root project directory (`d:/cyber-enhanced-system-1/mtac-cyber-security`).
2. Run the commands:
   ```
   npm install
   npm run dev
   ```
3. Vite will start the development server on port 5173 (default).
4. Take note of the IP address that Vite displays in the terminal (e.g., `192.168.1.100`).

## Accessing the Application

- On any device connected to the same local network, open a web browser.
- Navigate to:
  ```
  http://[IP address]:5173
  ```
  replacing `[IP address]` with the IP noted from the Vite server terminal output.
- The frontend will proxy API requests to the backend server automatically.

## Testing and Validation

- Use the manual frontend and backend testing checklists provided to thoroughly verify all features.
- Confirm network access from other devices on the local LAN works and the software functions correctly.

## Notes

- Ensure your devices are connected to the same local network.
- The frontend Vite dev server listens on host `0.0.0.0` to enable access from other devices.
- The backend server runs with a self-signed SSL certificate; the frontend proxy in vite.config.js accepts this configuration.

