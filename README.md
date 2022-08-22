# Beeline_test_task
Python autotests for auth methods (unittest)

---

## Тест test_auth_methods 
Проверяет последовательно методы **GET_STRING**, **GET_UUID** и **GET_MD5**. 
Для использования HTTP Basic Auth используются переменные окружения (логин и пароль).

## Тест test_token_method 
Проверяет метод **VALIDATE**. 
Проверяет на валидность JWT-токены с разным временем создания.
Для генерации токена используется файл **.pem** с приватным ключом.

---
## Установка
**Клонируем репозиторий**: 

`- https://github.com/AlexeyVikharev/Beeline_test_task.git` 

**Создаем виртуальное окружение**: 

`- $ python -m venv venv` 

**Устанавливаем зависимости**: 

`- $ pip install -r requirements.txt` 

**Примеры запуска тестов**: 

`- $ python test.py -v` 

`- $ python -m unittest -v` 

---