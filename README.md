# mrv2

## Локальный запуск

```bash
npm install
npm start
```

Сервер поднимается на `http://localhost:3000`.

## Render (деплой)

В репозиторий добавлен `render.yaml`.

1. Создай **Web Service** на Render из этого репозитория.
2. Убедись, что команды такие:
   - `Build Command`: `npm install --omit=dev`
   - `Start Command`: `npm run start:render`
3. Обязательно задай переменную `ADMIN_PASSWORD`.
4. Для сохранения данных между рестартами используй persistent disk и путь в `DATA_FILE` (по умолчанию: `/var/data/mrv2-data.json`).

### Если видишь `MODULE_NOT_FOUND` в Render

Чаще всего это значит, что сервис стартует без установленного `node_modules` или используется старая команда запуска в UI.

Проверь в Render Dashboard:
- сервис типа **Web Service** (не Static Site);
- Start Command именно `npm run start:render`;
- после изменения нажми **Manual Deploy → Clear build cache & deploy**.

## Основные маршруты

- `/` → редирект на `/login`
- `/login` — страница входа мессенджера
- `/servers/:code` — роут входа в сервер по коду устройства
- `/invite/:code` — роут invite-ссылки
- `/admmrv` — админ-панель
- `/health` — healthcheck для хостинга

## Backend (`server.js`)

Реализованы:

- Node.js сервер (Express + Socket.IO)
- хранение данных в `data.json` или в пути из `DATA_FILE`
- поддержка reverse proxy (`trust proxy`) для корректного IP на Render
- сессии устройств (`/api/auth/device`)
- создание пустых серверов без дефолтных разделов/каналов (`POST /api/servers`)
- invite-коды с ротацией каждые 24 часа
- join по invite (`POST /api/invites/:code/join`)
- panic endpoint (`POST /api/panic`) с удалением сессий и данных пользователя
- realtime события по сокетам для серверов/сообщений/реакций
- админ-бан сервера по IP участников (`POST /api/admin/ban/server/:id`)
