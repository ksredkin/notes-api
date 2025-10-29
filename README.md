# Notes API 📝

![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=JSON%20web%20tokens&logoColor=white)

Безопасное REST API для управления персональными заметками с аутентификацией JWT.

## 🛠 Технологии

- **FastAPI** - современный, быстрый веб-фреймворк
- **JWT** - JSON Web Tokens для безопасной аутентификации
- **SQLite** - легковесная база данных
- **bcrypt** - хеширование паролей
- **python-jose** - работа с JWT токенами
- **Uvicorn** - ASGI сервер
- **Pydantic** - валидация данных
- **Logging** - система логирования операций

## 📁 Структура проекта

```text
notes-api/
├── .gitignore          # Игнорирование файлов 
├── __main__.py         # Основной файл приложения
├── database.db         # База данных (создается автоматически)
├── database.sql        # SQL скрипт инициализации БД
├── logs/               # Папка с логами
│   └── __main__.log
└── README.md           # Документация
```

## 🚀 Установка и запуск

```bash
# Клонируй репозиторий
git clone https://github.com/ksredkin/notes-api.git
cd notes-api

# Создай виртуальное окружение (рекомендуется)
python -m venv venv
source venv/bin/activate  # Linux/MacOS
# или
venv\Scripts\activate     # Windows

# Установи зависимости
pip install fastapi uvicorn python-jose[cryptography] passlib[bcrypt] python-multipart

# Запусти сервер
python __main__.py
```

API будет доступно по адресу: http://127.0.0.1:8000

## 📚 Документация API

После запуска посети http://127.0.0.1:8000/docs для интерактивной документации Swagger.

## 🔐 Аутентификация

Все защищенные эндпоинты требуют JWT токен в заголовке:
```
Authorization: Bearer <ваш_jwt_токен>
```

### Эндпоинты аутентификации

**POST /register/**
Регистрация нового пользователя.

**Тело запроса:**
```json
{
  "username": "ваш_логин",
  "password": "ваш_пароль"
}
```

**POST /login/**
Вход в систему и получение JWT токена.

**Тело запроса:**
```json
{
  "username": "ваш_логин",
  "password": "ваш_пароль"
}
```

**Ответ:**
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer"
  }
}
```

## 📝 Эндпоинты заметок

Все эндпоинты заметок требуют аутентификации.

**POST /notes/{note_name}**
Создать новую заметку.

**Параметры:**
- `note_name` - название заметки
- `note_text` - текст заметки

**Ответы:**
- `201 Created` - заметка успешно создана
- `200 OK` - заметка уже существует
- `401 Unauthorized` - неверный токен

**GET /notes/{note_name}**
Получить конкретную заметку.

**Ответ:**
```json
{
  "status": "success",
  "data": {
    "note_name": "покупки",
    "text": "купить молоко и хлеб",
    "date": "2024-01-15 10:30:00"
  }
}
```

**PUT /notes/{note_name}**
Обновить существующую заметку.

**Параметры:**
- `note_name` - название заметки
- `note_text` - новый текст заметки

**Ответ:**
```json
{
  "status": "success",
  "message": "Note updated successfully",
  "data": {
    "note": {
      "note_name": "покупки",
      "text": "купить молоко, хлеб и яйца"
    }
  }
}
```

**DELETE /notes/{note_name}**
Удалить заметку.

**Ответ:**
```json
{
  "status": "success",
  "message": "Note deleted successfully",
  "data": {
    "note": {
      "note_name": "покупки",
      "text": "купить молоко, хлеб и яйца",
      "date": "2024-01-15 10:30:00"
    }
  }
}
```

**GET /my-notes/**
Получить все заметки текущего пользователя.

**Ответ:**
```json
{
  "status": "success",
  "data": {
    "notes": [
      {
        "name": "покупки",
        "text": "купить молоко и хлеб",
        "date": "2024-01-15 10:30:00"
      },
      {
        "name": "задачи",
        "text": "сделать домашку по математике",
        "date": "2024-01-14 15:45:00"
      }
    ]
  }
}
```

## 🔒 Безопасность

- Пароли хранятся в хешированном виде (`bcrypt`)
- JWT токены с ограниченным временем жизни
- Изоляция данных между пользователями
- Валидация всех входящих данных
- Подробное логирование операций

## 💡 Особенности

- Полностью асинхронное API
- Автоматическая генерация документации
- Подробное логирование в файл и консоль
- Простая установка и настройка
- Легковесная база данных SQLite

---

Если тебе понравился этот проект, не забудь поставить ⭐ на GitHub!