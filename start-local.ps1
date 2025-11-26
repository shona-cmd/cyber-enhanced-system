# PowerShell script to start backend and frontend servers concurrently

Write-Host "Starting backend server..."
Start-Process powershell -ArgumentList '-NoExit', '-Command', 'cd server; npm install; npm run start'

Write-Host "Starting frontend dev server..."
Start-Process powershell -ArgumentList '-NoExit', '-Command', 'npm install; npm run dev'

Write-Host "Both backend and frontend servers started in separate windows."
