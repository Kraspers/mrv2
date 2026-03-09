# mrv2

## Запуск

```bash
npm install
npm start
```

Сервер поднимается на `http://localhost:3000`.

## Основные маршруты

- `/login` — страница входа мессенджера
- `/servers/:code` — роут входа в сервер по коду устройства
- `/invite/:code` — роут invite-ссылки
- `/admmrv` — админ-панель

## Backend (`server.js`)

Реализованы:

- Node.js сервер (Express + Socket.IO)
- хранение данных в `data.json`
- сессии устройств (`/api/auth/device`)
- создание пустых серверов без дефолтных разделов/каналов (`POST /api/servers`)
- invite-коды с ротацией каждые 24 часа
- join по invite (`POST /api/invites/:code/join`)
- panic endpoint (`POST /api/panic`) с удалением сессий и данных пользователя
- realtime события по сокетам для серверов/сообщений/реакций
- админ-бан сервера по IP участников (`POST /api/admin/ban/server/:id`)
