import requests
import pandas as pd
import matplotlib.pyplot as plt
import json
import os

# Как работает мой скрипт?
# 1. Скрипт генерирует тестовый файл в формате json (имитация логов сетевой безопасности)
# 2. С помощью pandas загружает и анализирует логи, подсчитывая количество обращений к IP-адресам
# 3. Выбирает наиболее активные IP-адреса
# 4. Отправляет запрос к API VirusTotal для проверки этих IP (я создала свой API-ключ)
# 5. Имитирует реагирование
# 6. Сохраняет итоговый отчет в threat_report.json и строит график в threat_chart.png.

LOG_FILE = "suricata_logs.json"
REPORT_FILE = "threat_report.json"
CHART_FILE = "threat_chart.png"

def generate_mock_logs():
    """Создаем тестовый файл с логами, если он не существует"""
    if not os.path.exists(LOG_FILE):
        mock_data = [
            {"timestamp": "2026-03-10T10:00:01", "src_ip": "192.168.1.10", "dest_ip": "185.10.10.1", "event_type": "dns"},
            {"timestamp": "2026-03-10T10:00:02", "src_ip": "192.168.1.10", "dest_ip": "185.10.10.1", "event_type": "alert"},
            {"timestamp": "2026-03-10T10:00:03", "src_ip": "192.168.1.11", "dest_ip": "8.8.8.8", "event_type": "dns"},
            {"timestamp": "2026-03-10T10:00:04", "src_ip": "192.168.1.12", "dest_ip": "185.10.10.1", "event_type": "alert"},
            {"timestamp": "2026-03-10T10:00:05", "src_ip": "192.168.1.10", "dest_ip": "45.33.32.156", "event_type": "alert"}
        ]
        with open(LOG_FILE, "w") as f:
            json.dump(mock_data, f, indent=4)
        print(f"[i] Сгенерирован тестовый файл логов: {LOG_FILE}")

def analyze_logs():
    """Анализируем логи с помощью pandas и возвращаем топ подозрительных IP."""
    print("[i] Анализ логов...")
    df = pd.read_json(LOG_FILE)
    
    # Считаем количество обращений к каждому IP
    ip_counts = df['dest_ip'].value_counts()
    
    # Берем IP-адреса, к которым было больше 1 обращения
    suspicious_ips = ip_counts[ip_counts > 1].index.tolist()
    
    return ip_counts, suspicious_ips

def check_ip_virustotal(ip, api_key):
    """Проверяем IP-адрес через API VirusTotal"""
    if not api_key:
         
         return {"error": "API key not provided", "simulated_malicious": True}
        
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Ошибка API для IP {ip}: {e}")
        return {"error": str(e)}

def block_threat(ip):
    """Имитация реагирования на угрозу"""
    print(f"[!!!] ВНИМАНИЕ: Обнаружена угроза от IP {ip}!")
    print(f"[+] ДЕЙСТВИЕ: IP-адрес {ip} добавлен в черный список межсетевого экрана ")
    # Теперь сымитируем уведомление
    print(f"[✉️] УВЕДОМЛЕНИЕ: Сообщение об инциденте с IP {ip} отправлено администратору в Telegram.")

def generate_report_and_chart(ip_counts, report_data):
    """Сохраняем JSON-отчет и PNG-график."""
    # Сохранение JSON
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)
    print(f"[i] Отчет сохранен в файл: {REPORT_FILE}")

    # Теперь построим график
    plt.figure(figsize=(8, 5))
    ip_counts.plot(kind='bar', color='salmon', edgecolor='black')
    plt.title('Частота обращений к целевым IP-адресам (Анализ логов)')
    plt.xlabel('IP-адреса')
    plt.ylabel('Количество событий')
    plt.xticks(rotation=15)
    plt.tight_layout()
    
    # Сохраним наш график
    plt.savefig(CHART_FILE)
    print(f"[i] График сохранен в файл: {CHART_FILE}")

def main():
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("[!] Переменная окружения VT_API_KEY не задана. Будет использована имитация ответа от API.")

    # Этап 1: Сбор данных
    generate_mock_logs()

    # Этап 2: Анализ данных
    ip_counts, suspicious_ips = analyze_logs()
    
    report_data = {
        "analyzed_ips": ip_counts.to_dict(),
        "threat_responses": []
    }

    # Этап 3: Проверка через API и реагирование
    for ip in suspicious_ips:
        print(f"\n[i] Проверка подозрительного IP: {ip}")
        vt_result = check_ip_virustotal(ip, api_key)
        
        # Если API вернуло данные/ мы имитируем обнаружение
        if vt_result.get("simulated_malicious") or "data" in vt_result:
            block_threat(ip)
            report_data["threat_responses"].append({
                "ip": ip,
                "action_taken": "blocked",
                "api_response": vt_result
            })

    # Этап 4: Формирование отчета и визуализация
    print("\n[i] Формирование отчетности...")
    generate_report_and_chart(ip_counts, report_data)
    print("[+] Работа скрипта успешно завершена.")

if __name__ == "__main__":
    main()