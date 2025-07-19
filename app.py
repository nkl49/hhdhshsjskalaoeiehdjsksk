from flask import Flask, request, render_template_string, abort
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from time import time

app = Flask(__name__)

HTML = '''
<!doctype html>
<title>أدوات كشف الثغرات المتكاملة</title>
<h2>فحص HTTP Headers، XSS بسيط، وفحص استجابة السيرفر</h2>
<form method="POST">
  <input name="url" placeholder="أدخل رابط الموقع" style="width:400px" required>
  <button type="submit">افحص</button>
</form>
{% if message %}
  <h3>النتائج:</h3>
  <pre>{{ message }}</pre>
{% endif %}
'''

# حماية سبام بسيطة
requests_log = {}
REQUEST_LIMIT = 5  # طلبات لكل IP
TIME_WINDOW = 60   # بالثواني

def is_rate_limited(ip):
    now = time()
    if ip not in requests_log:
        requests_log[ip] = []
    requests_log[ip] = [t for t in requests_log[ip] if now - t < TIME_WINDOW]
    if len(requests_log[ip]) >= REQUEST_LIMIT:
        return True
    requests_log[ip].append(now)
    return False

def test_xss(url):
    payload = '<script>alert("XSS")</script>'
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        return "الرابط لا يحتوي على متغيرات GET للفحص."
    results = []
    for param in query:
        original = query[param][0]
        query[param][0] = payload
        new_query = urlencode(query, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        try:
            res = requests.get(test_url, timeout=5)
            if payload in res.text:
                results.append(f"✅ ثغرة XSS مكتشفة في المعامل: {param}\nالرابط: {test_url}")
        except Exception:
            pass
        query[param][0] = original
    if results:
        return '\n'.join(results)
    else:
        return "لم يتم العثور على ثغرات XSS."

def fetch_headers(url):
    try:
        r = requests.get(url, timeout=5)
        headers = '\n'.join(f"{k}: {v}" for k, v in r.headers.items())
        return headers
    except Exception as e:
        return f"تعذر الاتصال بالموقع: {e}"

def test_server_status(url):
    try:
        r = requests.head(url, timeout=5)
        return f"حالة السيرفر: {r.status_code} {r.reason}"
    except Exception as e:
        return f"فشل فحص حالة السيرفر: {e}"

@app.route('/', methods=['GET', 'POST'])
def home():
    ip = request.remote_addr
    if is_rate_limited(ip):
        abort(429, description="كثرت الطلبات، حاول مرة بعد شوية.")
    message = None
    if request.method == 'POST':
        url = request.form['url'].strip()
        if not url.startswith('http'):
            url = 'http://' + url
        headers = fetch_headers(url)
        xss = test_xss(url)
        status = test_server_status(url)
        message = f"=== HTTP Headers ===\n{headers}\n\n=== XSS Scan ===\n{xss}\n\n=== Server Status ===\n{status}"
    return render_template_string(HTML, message=message)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
