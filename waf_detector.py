import argparse
import requests  # type: ignore
import json
import re

# Загрузка сигнатур WAF из JSON
def load_waf_signatures(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

# Функция для проверки наличия WAF
def detect_waf(url, waf_signatures):
    try:
        # Отправляем GET-запрос на указанный URL
        response = requests.get(url, timeout=10)
        response_headers = response.headers
        response_text = response.text
        response_code = response.status_code

        print(f"Ответ от сервера: {response_code}")

        # Проверяем каждую сигнатуру WAF
        detected_wafs = []
        for waf_name, signature in waf_signatures.items():
            code = signature.get("code", "")
            page = signature.get("page", "")
            headers = signature.get("headers", "")

            # Проверка кода ответа
            if code and str(response_code) in code.split("|"):
                detected_wafs.append(waf_name)
                continue

            # Проверка текста страницы
            if page:
                if re.search(page, response_text, re.IGNORECASE):
                    detected_wafs.append(waf_name)
                    continue

            # Проверка заголовков
            if headers:
                if re.search(headers, str(response_headers), re.IGNORECASE):
                    detected_wafs.append(waf_name)
                    continue

        if detected_wafs:
            print("Обнаруженные WAF:")
            for waf in detected_wafs:
                print(f"- {waf}")
        else:
            print("WAF не обнаружен.")

    except requests.exceptions.RequestException as e:
        print(f"Ошибка при выполнении запроса: {e}")

# Основная функция
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="Скрипт для обработки serial.log файлов"
        )
    parser.add_argument(
            "--host", action="store_true", help="Example: https://example.com"
        )
    parser.add_argument(
            "--all",
            action="store_true",
            help="Массовое сканирование всех serial.log.* файлов",
        )
    args = parser.parse_args()

    # Путь к JSON-файлу с сигнатурами WAF
    signatures_file = "waf_signatures.json"  # Укажите путь к вашему JSON-файлу
    waf_signatures = load_waf_signatures(signatures_file)

    # Целевой URL для сканирования
    target_url = "https://cloudflare.com"  # Замените на URL вашего сайта

    # Запуск сканера
    detect_waf(target_url, waf_signatures)