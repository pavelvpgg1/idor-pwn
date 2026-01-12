import requests

class Session:
    def __init__(self, base_url, token):
        self.base_url = base_url
        # Для victim API используем X-User-ID заголовок
        try:
            user_id = int(token) if token.isdigit() else 1
            self.headers = {
                "X-User-ID": str(user_id)
            }
        except:
            self.headers = {
                "X-User-ID": "1"  # По умолчанию пользователь 1
            }

    def get(self, path):
        url = self.base_url + path
        return requests.get(url, headers=self.headers)
