from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import FastAPI, status, HTTPException, Depends
from datetime import datetime, timedelta, timezone
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel
import uvicorn
import sqlite3
import logging
import os

SECRET_KEY = "lelele"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Logger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.setup_logger()

    def get_logger(self):
        return self.logger

    def setup_logger(self):
        if not os.path.exists("./logs/"):
            os.mkdir("./logs/")

        file_handler = logging.FileHandler(f"./logs/{self.logger.name}.log", "w")
        stream_handler = logging.StreamHandler()

        self.logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(stream_handler)

security = HTTPBearer()
app = FastAPI()
logger = Logger(__name__).get_logger()

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class User(BaseModel):
    id: int
    username: str

def error_response(status_code: int = status.HTTP_400_BAD_REQUEST, detail: str = "Bad request"):
    return HTTPException(
        status_code=status_code,
        detail=detail
    )

def succes_response(status_code: int = status.HTTP_200_OK, message: str = None, data: any = None):
    content = {
        "status": "success",
    }

    if message:
        content["message"] = message

    if data:
        content["data"] = data

    return JSONResponse(
        content=content,
        status_code=status_code
    )

def create_jwt_token(user_id: int):
    try:
        logger.info(f"Создание JWT токена для пользователя id: {user_id}")
        expiration = datetime.now(timezone.utc) + timedelta(hours=24)
        payload = {"sub": str(user_id), "exp": expiration}
        token = jwt.encode(payload, SECRET_KEY, ALGORITHM)
        logger.info(f"JWT токен для пользователя id: {user_id} успешно создан")
        return token

    except Exception as e:
        logger.exception(f"Произошла ошибка при создании JWT токена для пользователя id: {user_id}") 
        raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Token creation failed")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        if user_id is None:
            raise error_response(status.HTTP_401_UNAUTHORIZED, "Invalid token")

        user = execute_query("SELECT id, username FROM users WHERE id = ?", (int(user_id),))[0]
        if not user:
            raise error_response(status.HTTP_401_UNAUTHORIZED, "User not found")

        return User(id=user[0], username=user[1])

    except ValueError:
        raise error_response(status.HTTP_401_UNAUTHORIZED, "Invalid user ID in token")

    except JWTError as e:
        logger.exception(f"Ошибка JWT: {e}")
        raise error_response(status.HTTP_401_UNAUTHORIZED, "Invalid token")

@app.post("/register/")
def register(user: UserRegister):
    try:
        logger.info(f"Получен запрос о создании аккаунта для username: {user.username}")

        user_db = execute_query("SELECT id FROM users WHERE username = ?", (user.username,))

        if user_db:
            raise error_response(status.HTTP_400_BAD_REQUEST, "Username already exists")

        hashed_password = pwd_context.hash(user.password)

        user_id = execute_query("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed_password))

        if user_id:
            logger.info(f"Аккаунт для username: {user.username} успешно создан")
            return succes_response(status.HTTP_201_CREATED, "User registered successfully")
        else:
            raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Registration failed")

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Произошла ошибка при попытке пользователя username: {user.username} зарегистрироваться: {e}")
        raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")

@app.post("/login/")
def login(user: UserLogin):
    try:
        logger.info(f"Получен запрос о входе в аккаунт для username: {user.username}")

        user_db = execute_query("SELECT id, username, password FROM users WHERE username = ?", (user.username,))[0]

        if not user_db or not pwd_context.verify(user.password, user_db[2]):
            raise error_response(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

        token = create_jwt_token(user_db[0])
        logger.info(f"Успешно создан JWT токен и отправлен для пользователя username: {user.username}")
        return succes_response(data={"access_token": token, "token_type": "bearer"})

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Произошла ошибка при попытке пользователя username: {user.username} залогиниться: {e}")
        raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")

@app.post("/notes/{note_name}")
def create_note(note_name: str, note_text: str, current_user: User = Depends(get_current_user)):
    try:
        logger.info(f"Получен запрос о создании заметки name: {note_name} пользователем id: {current_user.id}")
        
        note_result = execute_query("""SELECT text, date FROM notes WHERE name = ? AND user_id = ?""", (note_name, current_user.id))

        if note_result:
            note = note_result[0]
            return succes_response(status.HTTP_200_OK, "Note already exists", {"note": {"note_name": note_name, "text": note[0], "date": note[1]}})

        execute_query("""INSERT INTO notes (user_id, name, text, date) VALUES (?, ?, ?, CURRENT_TIMESTAMP)""", (current_user.id, note_name, note_text))
        logger.info(f"Заметка name: {note_name} успешно создана пользователем id: {current_user.id} и отправлена")
        return succes_response(status.HTTP_201_CREATED, "Note added successfully", {"note": {"note_name": note_name, "text": note_text}})

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Произошла ошибка при создании заметки пользователем id: {current_user.id}: {e}")
        raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")
    
@app.put("/notes/{note_name}")
def update_note(note_name: str, note_text: str, current_user: User = Depends(get_current_user)):
    try:
        logger.info(f"Получен запрос обновления заметки name: {note_name} пользователем id: {current_user.id}")
        
        note_result = execute_query("""SELECT text, date FROM notes WHERE name = ? AND user_id = ?""", (note_name, current_user.id))

        if not note_result:
            logger.info(f"Не найдена заметка пользователя id: {current_user.id} с name: {note_name}")
            raise error_response(status.HTTP_404_NOT_FOUND, "No note found in database")
        
        execute_query("""UPDATE notes SET text = ?, date = CURRENT_TIMESTAMP WHERE user_id = ? AND name = ?""", (note_text, current_user.id, note_name))
        logger.info(f"Заметка name: {note_name} успешно обновлена пользователем id: {current_user.id}")
        return succes_response(status.HTTP_200_OK, "Note updated successfully", {"note": {"note_name": note_name, "text": note_text}})

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Произошла ошибка при обновлении заметки name: {note_name} пользователем id: {current_user.id}: {e}")
        raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")
    
@app.delete("/notes/{note_name}")
def delete_note(note_name: str, current_user: User = Depends(get_current_user)):
    try:
        logger.info(f"Получен запрос удаления заметки name: {note_name} пользователем id: {current_user.id}")
        
        note_result = execute_query("""SELECT text, date FROM notes WHERE name = ? AND user_id = ?""", (note_name, current_user.id))

        if not note_result:
            logger.info(f"Не найдена заметка пользователя id: {current_user.id} с name: {note_name}")
            raise error_response(status.HTTP_404_NOT_FOUND, "No note found in database")
        
        execute_query("""DELETE FROM notes WHERE user_id = ? AND name = ?""", (current_user.id, note_name))
        logger.info(f"Заметка name: {note_name} успешно удалена пользователем id: {current_user.id}")
        return succes_response(status.HTTP_200_OK, "Note deleted successfully", {"note": {"note_name": note_name, "text": note_result[0][0]}})

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Произошла ошибка при удалении заметки name: {note_name} пользователем id: {current_user.id}: {e}")
        raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")

@app.get("/notes/{note_name}")
def get_note(note_name: str, current_user: User = Depends(get_current_user)):
    try:
        logger.info(f"Получен запрос о получении заметки name: {note_name} пользователем id: {current_user.id}")
        
        note_result = execute_query("""SELECT text, date FROM notes WHERE name = ? AND user_id = ?""", (note_name, current_user.id))

        if not note_result:
            logger.info(f"Не найдена заметка пользователя id: {current_user.id} с name: {note_name}")
            raise error_response(status.HTTP_404_NOT_FOUND, "No note found in database")

        note = note_result[0]

        logger.info(f"Заметка name: {note_name} пользователя id: {current_user.id} успешно найдена и отправлена")
        return succes_response(data={"note_name": note_name, "text": note[0], "date": note[1]})

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Произошла ошибка при получении заметки пользователя id: {current_user.id}: {e}")
        raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")

@app.get("/my-notes/")
def get_my_notes(current_user: User = Depends(get_current_user)):
    try:
        logger.info(f"Получен запрос о получении всех заметок пользователя id: {current_user.id}")

        notes = execute_query("""SELECT name, text, date FROM notes WHERE user_id = ? ORDER BY date DESC""", (current_user.id,))

        notes_list = []
        if notes:
            for note in notes:
                notes_list.append({"name": note[0], "text": note[1], "date": note[2]})

        logger.info(f"Список заметок успешно получен и отправлен")
        return succes_response(data={"notes": notes_list})

    except HTTPException:
        raise

    except Exception as e:
        logger.exception(f"Ошибка при получении всех заметок пользователя id: {current_user.id}: {e}")
        raise error_response(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error")

def execute_query(query: str, params: tuple = ()):
    try:
        logger.info(f"Выполнение SQL запроса: {query[:100]}")
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)

            if query.upper().startswith("SELECT"):
                result = cursor.fetchall()
                logger.info(f"Результат выполнения SQL запроса: {result[:100]}")
                return result if result else None
            else:
                conn.commit()
                logger.info("SQL запрос успешно выполнен")
                if query.upper().startswith("INSERT"):
                    return cursor.lastrowid
                return cursor.rowcount
    
    except Exception as e:
        logger.exception(f"Ошибка при выполнении SQL запроса: {e}")
        return None

def check_database():
    try:
        logger.info("Проверка наличия базы данных")
        if not os.path.exists("database.db"):
            with open("database.sql") as f:
                script = f.read()

            with sqlite3.connect("database.db") as conn:
                cursor = conn.cursor()
                cursor.executescript(script)
                conn.commit()

            return logger.info("База данных успешно создана")

        logger.info("База данных уже существует")

    except Exception as e:
        logger.critical(f"Ошибка при проверке наличия или создании базы данных: {e}")
        raise

def main():
    try:
        logger.info("Запуск приложения Notes API")
        check_database()
        logger.info("Сервер запускается на 127.0.0.1:8000")
        uvicorn.run(app, host="127.0.0.1", port=8000)
    
    except Exception as e:
        logger.critical(f"Не удалось запустить: {e}")
        raise

if __name__ == "__main__":
    main()