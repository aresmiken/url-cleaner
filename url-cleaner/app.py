from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse, parse_qs, urlunparse
import re
import requests
from datetime import datetime

app = Flask(__name__)

# Списки подозрительных доменов (можно расширять)
SUSPICIOUS_DOMAINS = [
    'phishing.com', 'malware.ru', 'fake-bank.net',
    'loginto.xyz', 'secure-verify.com'
]

# Блокируемые параметры трекеров
TRACKER_PARAMS = [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'yclid', 'mc_cid', '_ga', 'hsCtaTracking',
    'clickid', 'mkt_tok', 'trk', 'sc_campaign'
]

def clean_url(url):
    """Очищает URL от трекеров"""
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Удаляем параметры трекеров
        cleaned_params = {
            k: v for k, v in query_params.items() 
            if k not in TRACKER_PARAMS
        }
        
        # Собираем URL обратно
        cleaned_query = '&'.join([f'{k}={v[0]}' for k, v in cleaned_params.items()])
        cleaned = parsed._replace(query=cleaned_query)
        
        return urlunparse(cleaned)
    except Exception as e:
        return url

def check_domain_safety(url):
    """Проверяет домен на подозрительность"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Удаляем www.
        if domain.startswith('www.'):
            domain = domain[4:]
        
        for suspicious in SUSPICIOUS_DOMAINS:
            if suspicious in domain or domain in suspicious:
                return {
                    'safe': False,
                    'reason': f'Домен {domain} найден в чёрном списке'
                }
        
        # Проверка на HTTPS
        is_https = parsed.scheme == 'https'
        
        return {
            'safe': True,
            'https': is_https,
            'domain': domain
        }
    except:
        return {'safe': False, 'reason': 'Не удалось проверить домен'}

def expand_short_url(url):
    """Раскрывает короткие ссылки (опционально)"""
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@app.route('/clean', methods=['POST'])
def process_url():
    """Обрабатывает URL: очищает и проверяет"""
    data = request.get_json()
    original_url = data.get('url', '')
    
    if not original_url:
        return jsonify({'error': 'URL не указан'}), 400
    
    # Раскрываем короткие ссылки
    expanded_url = expand_short_url(original_url)
    
    # Очищаем от трекеров
    cleaned_url = clean_url(expanded_url)
    
    # Проверяем безопасность
    safety = check_domain_safety(cleaned_url)
    
    # Формируем результат
    result = {
        'original': original_url,
        'cleaned': cleaned_url,
        'safe': safety.get('safe', False),
        'warning': safety.get('reason', None) if not safety.get('safe') else None,
        'https': safety.get('https', False),
        'domain': safety.get('domain', 'Неизвестно')
    }
    
    # Добавляем статистику удалённых трекеров
    original_params = set(re.findall(r'[?&]([^=]+)=', original_url))
    cleaned_params = set(re.findall(r'[?&]([^=]+)=', cleaned_url))
    removed_params = original_params - cleaned_params
    result['removed_trackers'] = list(removed_params)
    
    return jsonify(result)

@app.route('/api/check-bulk', methods=['POST'])
def check_bulk():
    """Проверка нескольких ссылок сразу"""
    data = request.get_json()
    urls = data.get('urls', [])
    
    results = []
    for url in urls:
        expanded = expand_short_url(url)
        cleaned = clean_url(expanded)
        safety = check_domain_safety(cleaned)
        results.append({
            'original': url,
            'cleaned': cleaned,
            'safe': safety.get('safe', False)
        })
    
    return jsonify({'results': results})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)