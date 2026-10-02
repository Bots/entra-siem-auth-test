# Entra SIEM Authentication Flow Test

Authorized security-testing tools for developing SIEM detections against a Microsoft Entra ID tenant you own or are explicitly permitted to test.

The browser harness preserves one Playwright browser context across ten manually entered authentication attempts while rotating User-Agent and NordVPN location. Passwords must never be logged.

The FastAPI application is a separate local authentication test fixture. It is not the target of the Microsoft browser harness.

Do not use these tools against accounts or tenants without explicit authorization.
