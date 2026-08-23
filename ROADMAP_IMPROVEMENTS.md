# Windows Inventory Lite — Roadmap улучшений (на основе код-ревью)

> **Версия:** 1.0  
> **Дата:** 2026-08-23  
> **Статус:** Черновик для обсуждения  
> **Основа:** Полный код-ревью проекта (security, architecture, UI/UX, code quality)

---

## 📋 ОБЗОР ПРИОРИТЕТОВ

| Приоритет | Категория | Количество задач | Оценка трудоёмкости |
|-----------|-----------|------------------|---------------------|
| 🔴 **P0 — Critical** | Security (ИБ) | 8 | ~3-4 недели |
| 🟠 **P1 — High** | Architecture | 6 | ~2-3 недели |
| 🟡 **P2 — Medium** | Code Quality / Maintainability | 10 | ~2-3 недели |
| 🟢 **P3 — Low** | UI/UX / DX | 7 | ~1-2 недели |
| 🔵 **P4 — Nice to have** | Testing / Observability | 5 | ~1-2 недели |

**Итого:** ~36 задач | **~9-14 недель** (при 1 разработчике) | **~4-6 недель** (при 2-3 разработчиках)

---

## 🔴 P0 — CRITICAL: ИНФОРМАЦИОННАЯ БЕЗОПАСНОСТЬ

### SEC-001: Удаление хардкода мастер-ключа шифрования
**Файл:** `Src/Server/SecretProtector.cs` (строка 23)  
**Проблема:** Мастер-ключ `MasterKey` зашит в бинарник сервера. При компрометации одного сервера — компрометируются **все** инсталляции.  
**Решение:**
- [ ] Генерировать уникальный мастер-ключ при первом запуске (`Install-Server.ps1`)
- [ ] Хранить в DPAPI (Windows) / файл с `chmod 600` (Linux) / Azure Key Vault / HashiCorp Vault
- [ ] Добавить ротацию мастер-ключа (re-encrypt existing secrets)
- [ ] Документировать процедуру disaster recovery при потере ключа

**Оценка:** 3-5 дней  
**Зависимости:** SEC-002, SEC-003

---

### SEC-002: Замена AES-ECB на AES-GCM (аутентифицированное шифрование)
**Файл:** `Src/Server/SecretProtector.cs` (строки 45-70)  
**Проблема:** ECB режим — детерминированный, не обеспечивает целостность, уязвим к replay/bit-flipping атакам.  
**Решение:**
- [ ] Перейти на `AesGcm` (NET 6+) или `AesCcm` / `ChaCha20Poly1305`
- [ ] Формат ciphertext: `nonce(12) || ciphertext || tag(16)`
- [ ] Добавить AAD (additional authenticated data) — например, `purpose: "webhook-secret"` для контекстной привязки
- [ ] Миграция существующих секретов: расшифровать старым методом → зашифровать новым

**Оценка:** 2-3 дня  
**Риск:** Breaking change — нужна миграция

---

### SEC-003: Устранение timing-атак при сравнении токенов
**Файлы:** 
- `Src/Server/WindowsInventoryLiteServer.cs` — строки ~340, ~380 (сравнение `ingestionToken`)
- `Linux-client/token.go` — функция `ValidateToken`

**Проблема:** Использование `==` / `strings.EqualFold` утекает длину общего префикса через timing side-channel.  
**Решение:**
- [ ] .NET: `CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b))`
- [ ] Go: `subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1`
- [ ] Добавить unit-тесты на timing (statistical, flaky но полезные)

**Оценка:** 1 день

---

### SEC-004: Отсутствие rate limiting на ingestion endpoint
**Файл:** `Src/Server/WindowsInventoryLiteServer.cs` — метод `HandleIngestion`  
**Проблема:** Атакующий может DoS-ить сервер, флудя отчётами (CPU, диск, БД). Нет защиты от перебора токенов.  
**Решение:**
- [ ] Token bucket / sliding window per IP + per token
- [ ] Лимиты: например, 60 req/min per token, 200 req/min per IP
- [ ] Возврат `429 Too Many Requests` с `Retry-After`
- [ ] Метрики: `ingestion_rate_limited_total` (Prometheus)

**Оценка:** 2-3 дня

---

### SEC-005: Отсутствие валидации размера входящего отчёта
**Файл:** `Src/Server/WindowsInventoryLiteServer.cs` — `HandleIngestion`  
**Проблема:** Клиент может прислать 100+ MB JSON → OOM, забивание диска, парсинг-атаки.  
**Решение:**
- [ ] `Request.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024)` (5 MB лимит, настраиваемый)
- [ ] Жёсткий лимит в `json.Decoder.DisallowUnknownFields()` + `UseNumber()`
- [ ] Таймауты чтения: `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`

**Оценка:** 1 день

---

### SEC-006: CSP без `script-src 'self'` — inline скрипты в HTML
**Файл:** `Server/Dashboard/Index.html` — строка 12-15 (CSP meta tag)  
**Проблема:** CSP позволяет `'unsafe-inline'` для скриптов — обходит основную защиту от XSS.  
**Решение:**
- [ ] Вынести весь JS в `App.js` (уже сделано частично)
- [ ] Убрать `onclick="..."` атрибуты → `addEventListener`
- [ ] CSP: `script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`
- [ ] Добавить `nonce` или `hash` для остаточных inline (если неизбежны)

**Оценка:** 1-2 дня

---

### SEC-007: Отсутствие security headers на API endpoints
**Файл:** `Src/Server/WindowsInventoryLiteServer.cs` — настройка `HttpListener` / middleware  
**Проблема:** Нет `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`  
**Решение:**
- [ ] Middleware `AddSecurityHeaders` для всех ответов
- [ ] HSTS (если HTTPS): `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- [ ] `Cross-Origin-Resource-Policy: same-origin` для API

**Оценка:** 0.5 дня

---

### SEC-008: Логирование секретов в plaintext
**Файлы:** 
- `Src/Server/WindowsInventoryLiteServer.cs` — строки с `Log($"Token: {token}")`
- `Install-Server.ps1` — запись пароля в конфиг без маскирования

**Проблема:** Секреты попадают в логи, syslog, SIEM, файлы — риск утечки.  
**Решение:**
- [ ] Structured logging с полями: `token_hash: sha256(token)[:8]` вместо самого токена
- [ ] В конфигах: `WebPassword: "***REDACTED***"` при логировании
- [ ] Добавить `.gitignore` проверки на секреты (gitleaks pre-commit)

**Оценка:** 1 день

---

### SEC-009: Отсутствие подписи/верификации отчётов клиента
**Проблема:** Любой владелец токена может подделать данные инвентаризации. Нет гарантии авторства и целостности.  
**Решение:**
- [ ] Ed25519 подпись отчёта клиентским приватным ключом
- [ ] Сервер хранит публичные ключи клиентов (при регистрации — TOFU или CA)
- [ ] Формат: `payload || signature` или JWS (detached)
- [ ] Опционально: mTLS для клиентов (cert-based auth)

**Оценка:** 5-7 дней (крупная фича)  
**Примечание:** Можно отложить до P1, если threat model не требует non-repudiation

---

### SEC-010: Отсутствие HTTPS enforcement / HSTS / certificate pinning
**Проблема:** В дефолте HTTP. Токены и отчёты летят в открытом виде.  
**Решение:**
- [ ] `Install-Server.ps1`: генерация self-signed cert + настройка HTTPS binding
- [ ] Документация: как подсунуть реальный сертификат (Let's Encrypt, корп. CA)
- [ ] Клиенты: проверка сертификата (pinning SHA256 или CA trust)
- [ ] Редирект HTTP → HTTPS на уровне сервера

**Оценка:** 2-3 дня

---

## 🟠 P1 — HIGH: АРХИТЕКТУРА

### ARCH-001: Монофункциональный God-object сервер
**Файл:** `Src/Server/WindowsInventoryLiteServer.cs` — 2000+ строк, 1 класс  
**Проблема:** Нарушение SRP: HTTP routing, auth, storage, AD lookup, scheduling, UI serving — всё в одном.  
**Решение:**
- [ ] Разбить на модули:
  - `HttpServer` — только transport
  - `IngestionHandler` — приём и валидация отчётов
  - `AuthService` — токены, rate limiting
  - `StorageService` — абстракция над JSON/DB
  - `AdLookupService` — отдельный (уже вынесен, но tightly coupled)
  - `DashboardService` — статические файлы
- [ ] DI контейнер (Microsoft.Extensions.DependencyInjection) или manual wiring
- [ ] Интерфейсы для каждого сервиса → тестируемость, моки

**Оценка:** 5-7 дней

---

### ARCH-002: JSON-файлы как "БД" — нет конкурентности, ACID, индексов
**Файлы:** `WindowsInventoryLiteServer.cs` — `SaveReport`, `LoadReports`, `GetClients`  
**Проблема:** 
- Race condition при параллельной записи (нет file locking)
- Полное чтение всех файлов в память при каждом запросе списка клиентов
- Нет индексов