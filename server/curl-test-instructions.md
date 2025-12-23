# Manual Backend API Testing with curl

Use the following curl commands to manually test backend APIs over the HTTP endpoint (port 3001) for easier local testing without SSL:

## 1. Check API status (replace `/status` if a specific health endpoint exists)
```
curl http://localhost:3001/api/status
```

## 2. Login API
Test login with valid credentials:
```
curl -X POST http://localhost:3001/api/login -H "Content-Type: application/json" -d "{\"username\":\"mtac-admin\",\"password\":\"Mtac2025!\"}"
```

## 3. Using Token for Protected APIs

The login response includes a JWT token. Use this token to test protected endpoints by including it in the `Authorization` header:

Example (replace `<TOKEN>` with the actual token string received on login):
```
curl -H "Authorization: Bearer <TOKEN>" http://localhost:3001/api/devices
curl -H "Authorization: Bearer <TOKEN>" http://localhost:3001/api/audit
```

## Troubleshooting and Verifying Responses

- Status codes 200-299 indicate success.
- 401 indicates unauthorized (missing or invalid token).
- 403 indicates forbidden (token verification failed).
- Response bodies may have error messages detailing issues.

## Next Steps

- Run these commands in a terminal to verify backend API functionality.
- If errors occur, note error messages and status codes.
- I can assist you in interpreting responses or troubleshooting any issues encountered.
