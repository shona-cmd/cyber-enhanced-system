# API Response Interpretation and Troubleshooting Guide

## Common HTTP Status Codes

- **200 OK**: Request succeeded. Response body contains requested data.
- **201 Created**: Resource created successfully.
- **400 Bad Request**: Client sent invalid data. Check request payload format.
- **401 Unauthorized**: Authentication required or failed (missing/invalid token).
- **403 Forbidden**: Credentials valid but no permission for requested resource.
- **404 Not Found**: Requested endpoint or resource does not exist.
- **500 Internal Server Error**: Server encountered an unexpected error.

## Typical Error Responses and Causes

- **Invalid Credentials**
  - API returns 401 Unauthorized with message "Invalid credentials".
  - Ensure username and password are correct.
  - Check password hashing mechanism matches stored value.

- **Missing or Invalid Token**
  - API returns 401 or 403 with messages "No token" or "Invalid token".
  - Confirm `Authorization` header is present and formatted as `Bearer <token>`.
  - Ensure token has not expired (expiresIn set to 8 hours in this setup).

- **Rate Limiting**
  - API may return 429 Too Many Requests if too many calls within 15 min window.
  - Wait for cooldown or adjust rate limiting config if needed.

## Debugging Tips

- Verify backend server is running on expected port (HTTP 3001 for test).
- Use manual curl or automated backend-test.js script and review response bodies.
- On SSL errors (with HTTPS), use HTTP port 3001 or configure trusted cert locally.
- Check console logs of backend server for detailed error trace.
- Use Postman or similar API clients for interactive testing.

## Next Steps

- Use this guide in combination with `curl-test-instructions.md` for effective backend testing.
- Record any error codes or messages and share for assistance in debugging.
- For frontend testing, verify login flows, protected pages loading data, and logout behave as expected.
