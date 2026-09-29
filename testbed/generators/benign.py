import http.client
import random
import sys
import time

N = int(sys.argv[1]) if len(sys.argv) > 1 else 500

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
]

SEARCH_WORDS = ["shoes", "laptop", "red shirt", "phone case", "book",
                "headphones", "coffee mug", "backpack", "desk lamp", "watch"]

REFERERS = ["", "", "http://shop.local/", "http://shop.local/products",
            "https://www.google.com/"]


def pick_path():
    r = random.random()
    if r < 0.20:
        return "/"
    if r < 0.40:
        return "/products"
    if r < 0.70:
        return f"/product?id={random.randint(1, 25)}"
    if r < 0.88:
        q = random.choice(SEARCH_WORDS).replace(" ", "+")
        return f"/search?q={q}"
    return "/login"


def send(method, path, user_agent, referer, exp_id, body=None):
    conn = http.client.HTTPConnection("nginx", 80, timeout=5)
    headers = {"User-Agent": user_agent, "X-Exp-Id": exp_id}
    if referer:
        headers["Referer"] = referer
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=body, headers=headers)
    status = conn.getresponse().status
    conn.close()
    return status


for i in range(N):
    ua = random.choice(USER_AGENTS)
    if random.random() < 0.05:
        # 5% là gửi form đăng nhập
        status = send("POST", "/login", ua, "http://shop.local/login",
                      f"benign:{i}", body="user=alice&pass=secret")
    else:
        status = send("GET", pick_path(), ua, random.choice(REFERERS), f"benign:{i}")

    if i % 50 == 0:
        print(f"[benign] {i}/{N} last status {status}", flush=True)

    time.sleep(random.uniform(0.05, 0.4))   # nghỉ ngẫu nhiên như người thật

print(f"[benign] done, sent {N} requests", flush=True)