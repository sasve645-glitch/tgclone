# TgClone — мессенджер (MVP)

Личные чаты, группы, каналы, real-time (Socket.IO), ответы, правка/удаление, файлы и фото до 25 МБ, "печатает…", онлайн-статус, непрочитанные, поиск, публичные каналы, тёмная тема, мобильная вёрстка.

**Защита от фейков:** регистрация только с подтверждением e-mail (код 6 цифр, 10 мин, 5 попыток), блок одноразовых почт, лимиты запросов, 1 аккаунт = 1 e-mail.

## Запуск
```
cd server && npm install && npm start     # http://localhost:3000
```
Без SMTP код подтверждения печатается в консоль (dev). Для продакшена: `cp .env.example .env`, заполнить, `docker compose up -d --build`.

## GitHub
```
git init && git add . && git commit -m "init"
git branch -M main && git remote add origin https://github.com/USER/REPO.git && git push -u origin main
```
CI (.github/workflows/ci.yml) проверит сборку. Деплой: Render / Railway / Fly.io / VPS (Dockerfile готов; подключите том на /data).

## Не реализовано
Голосовые/видеозвонки, E2E «секретные чаты», боты, стикеры, пуш-уведомления, нативные приложения, SMS/телефон-верификация.

## Android APK
APK — это оболочка (Capacitor), которая открывает ваш задеплоенный сервер.
1. Задеплойте сервер (Render и т.п.), получите https-ссылку.
2. GitHub → Settings → Secrets and variables → Actions → Variables → New: `SERVER_URL` = ваша ссылка.
3. Actions → Build APK → Run workflow. Через ~5 мин скачайте артефакт `tgclone-apk` и установите app-debug.apk.
