import json
import jwt
import os.path
import requests
import time
import unittest

from dotenv import load_dotenv

URL_GET_STRING = 'http://v1021401.hosted-by-vdsina.ru:13890/string'  # URL-адрес для метода Get string
URL_GET_UUID = 'http://v1021401.hosted-by-vdsina.ru:13890/uuid'  # URL-адрес для метода Get Uuid
URL_GET_MD5 = 'http://v1021401.hosted-by-vdsina.ru:13890/md5'  # URL-адрес для метода Get Md5
URL_VALIDATE = 'http://v1021401.hosted-by-vdsina.ru:13890/validate'  # URL-адрес для метода Validate

TEST_STRING = 'teststring'  # Тестовая строка для метода Get string

load_dotenv()

TEST_USER_LOGIN = os.getenv('TEST_USER_LOGIN')  # Логин для HTTP Basic Auth
TEST_USER_PASSWORD = os.getenv('TEST_USER_PASSWORD')  # Пароль для HTTP Basic Auth

TEST_PATH_PRIVATE_KEY = 'private.pem'  # Путь к файлу с приватным ключом для токена


class TestAuthentication(unittest.TestCase):
    def test_auth_methods(self):
        """
        Проверка методов GET_STRING, GET_UUID и GET_MD5.
        """

        # Задаем сессию для работы через HTTP Basic Auth
        with requests.Session() as session:
            session.auth = (TEST_USER_LOGIN, TEST_USER_PASSWORD)

            # Тестируем метод GET_STRING
            response_get_string = session.get(
                URL_GET_STRING,
                params={'string': TEST_STRING}
            )
            self.assertEqual(response_get_string.status_code, 201,
                             f'UUID did not created. Response status_code expected "201",'
                             f'Response actual "{response_get_string.status_code}"')
            self.assertIn('uuid', response_get_string.json(),
                          f'Response does not contain "uuid",'
                          f'actual json of response: {response_get_string.json()}')

            # Если метод GET_STRING прошел тест, то используем полученный UUID
            uuid = response_get_string.json().get('uuid')

            # Тестируем метод GET_UUID
            response_get_uuid = session.post(
                URL_GET_UUID,
                data=json.dumps({'uuid': uuid})
            )
            self.assertEqual(response_get_uuid.status_code, 200,
                             f'MD5 did not created. Response status_code expected "200",'
                             f'Response actual "{response_get_uuid.status_code}"')
            self.assertIn('md5', response_get_uuid.json(),
                          f'Response does not contain "md5",'
                          f'actual json of response: {response_get_uuid.json()}')

            # Если метод GET_UUID прошел тест, то используем полученный MD5
            md5 = response_get_uuid.json().get('md5')

            # Тестируем метод GET_MD5
            session.headers.update({'uuid': uuid})
            response_get_md5 = session.put(
                URL_GET_MD5,
                params={'md5': md5},
            )
            self.assertEqual(response_get_md5.status_code, 200,
                             f'Response status_code expected "200",'
                             f'Response actual "{response_get_md5.status_code}"')
            self.assertIn('message', response_get_md5.json(),
                          f'Response does not contain "message",'
                          f'actual json of response: {response_get_md5.json()}')
            self.assertEqual(response_get_md5.json().get('message'), TEST_STRING,
                             f'Expected message is "{TEST_STRING}",'
                             f'actual message: {response_get_md5.json().get("message")}')

    def test_token_method(self):
        """
        Тестируем валидность JWT-токена через метод VALIDATE.
        """
        valid_delta_iat_for_tests = [
            0,
            110,
        ]
        invalid_delta_iat_for_tests = [
            120,
            -10,
        ]
        headers = {
            'alg': 'RS256',
            'typ': 'JWT'
        }
        with open(TEST_PATH_PRIVATE_KEY, 'rb') as f:
            private_key = f.read()

        # Тесты для токенов с валидным сроком жизни
        for valid_delta_iat in valid_delta_iat_for_tests:
            with self.subTest(msg=f'test for delta iat:{valid_delta_iat}',
                              valid_iat=valid_delta_iat):
                payload = {
                    "iss": "Authlib",
                    "sub": "123",
                    "iat": int(time.time()) - valid_delta_iat,
                    "autotest": True
                }
                jwt_token = jwt.encode(
                    payload=payload,
                    key=private_key,
                    headers=headers,
                    algorithm='RS256'
                )

                response_validate = requests.post(
                    URL_VALIDATE,
                    data=json.dumps({'jwt': jwt_token}),
                )
                self.assertEqual(response_validate.status_code, 200,
                                 f'Response status_code expected "200",'
                                 f'Response actual "{response_validate.status_code}"')
                self.assertIn('status', response_validate.json(),
                              f'Response does not contain "status",'
                              f'actual json of response: {response_validate.json()}')
                self.assertEqual(response_validate.json().get('status'), 'valid',
                                 f'Expected status is "valid",'
                                 f'actual status: {response_validate.json().get("status")}')

        # Тесты для токенов с невалидным сроком жизни
        for invalid_delta_iat in invalid_delta_iat_for_tests:
            with self.subTest(msg=f'test for delta iat:{invalid_delta_iat}',
                              invalid_iat=invalid_delta_iat):
                payload = {
                    "iss": "Authlib",
                    "sub": "123",
                    "iat": int(time.time()) - invalid_delta_iat,
                    "autotest": True
                }
                jwt_token = jwt.encode(
                    payload=payload,
                    key=private_key,
                    headers=headers,
                    algorithm='RS256'
                )

                response_validate = requests.post(
                    URL_VALIDATE,
                    data=json.dumps({'jwt': jwt_token}),
                )
                self.assertEqual(response_validate.status_code, 400,
                                 f'Response status_code expected "400",'
                                 f'Response actual "{response_validate.status_code}"')
                self.assertIn('error', response_validate.json(),
                              f'Response does not contain "error",'
                              f'actual json of response: {response_validate.json()}')
                self.assertEqual(response_validate.json().get('error'), True,
                                 f'Expected error field is "true",'
                                 f'actual error field: {response_validate.json().get("error")}')
                self.assertEqual(response_validate.json().get('error_description'), 'invalid iaf',
                                 f'Expected error description is "invalid iaf",'
                                 f'actual error description: {response_validate.json().get("error_description")}')


if __name__ == '__main__':
    unittest.main()
