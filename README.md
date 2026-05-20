# 🔐 Secure REST API — JWT Authentication

![CI](https://github.com/YOUR_USERNAME/secure-rest-api/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

Production-ready REST API with secure JWT authentication — featuring **access + refresh token rotation**, **token revocation**, and **bcrypt password hashing**. Deployed with Docker and tested with a full pytest suite.

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🔑 JWT Auth | Short-lived access tokens (30 min) + long-lived refresh tokens (7 days) |
| 🔄 Token rotation | Refresh tokens are revoked on use — prevents replay attacks |
| 🚪 Logout | Access tokens are blacklisted on logout |
| 🔒 Password hashing | bcrypt with automatic salt generation |
| 📄 Auto-docs | Swagger UI at `/docs`, ReDoc at `/redoc` |
| 🐳 Docker | Single-command deployment, non-root user |
| ✅ Tests | 10 pytest cases covering happy paths and edge cases |
| ⚡ CI/CD | GitHub Actions: test → build on every push |

---

## 🚀 Quick Start

### Option 1 — Docker (recommended)
```bash
docker build -t secure-api .
docker run -p 8000:8000 secure-api
```

### Option 2 — Local
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Visit **http://localhost:8000/docs** for the interactive Swagger UI.

---

## 📡 API Endpoints

```
POST /auth/register   — Create a new account
POST /auth/login      — Get access + refresh tokens
POST /auth/refresh    — Rotate refresh token → new token pair
POST /auth/logout     — Revoke current access token
GET  /users/me        — Get profile (requires Bearer token)
GET  /health          — Health check
```

---

## 🔐 Auth Flow

```
1. Register  →  POST /auth/register
2. Login     →  POST /auth/login  →  { access_token, refresh_token }
3. Request   →  GET /users/me  Header: Authorization: Bearer <access_token>
4. Refresh   →  POST /auth/refresh  →  new token pair (old refresh revoked)
5. Logout    →  POST /auth/logout  →  access token blacklisted
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

```
tests/test_auth.py::test_register               PASSED
tests/test_auth.py::test_register_duplicate     PASSED
tests/test_auth.py::test_login                  PASSED
tests/test_auth.py::test_login_wrong_password   PASSED
tests/test_auth.py::test_protected_route        PASSED
tests/test_auth.py::test_protected_no_token     PASSED
tests/test_auth.py::test_refresh_token          PASSED
tests/test_auth.py::test_refresh_token_rotation PASSED
tests/test_auth.py::test_logout                 PASSED
tests/test_auth.py::test_health                 PASSED
```

---

## 🏗 Project Structure

```
secure-rest-api/
├── app/
│   └── main.py              # FastAPI app, routes, JWT logic
├── tests/
│   └── test_auth.py         # Full test suite (pytest)
├── .github/
│   └── workflows/
│       └── ci.yml           # GitHub Actions CI
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## 🔧 Production Checklist

- [ ] Move `SECRET_KEY` to environment variable
- [ ] Replace in-memory DB with PostgreSQL (SQLAlchemy)
- [ ] Add rate limiting (slowapi)
- [ ] Add HTTPS (reverse proxy: nginx / Caddy)
- [ ] Store revoked tokens in Redis (not in-memory)

---

## 📚 What I Learned

- Stateless vs stateful authentication tradeoffs
- Why refresh token rotation prevents session hijacking
- bcrypt cost factor and why MD5/SHA is not enough for passwords
- Docker best practices (non-root user, layer caching)
- Writing tests that cover security edge cases, not just happy paths

---

## 📄 License

MIT — free to use, fork, and build on.
