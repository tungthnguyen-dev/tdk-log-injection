from flask import Flask, request, abort
import sqlite3

app = Flask(__name__)

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE products(id INTEGER, name TEXT)")
db.executemany("INSERT INTO products VALUES(?,?)",
               [(i, f"item{i}") for i in range(1, 21)])

@app.get("/")
def index():
    return "home"

@app.get("/products")
def products():
    return "product list"

@app.get("/product")
def product():
    pid = request.args.get("id", "1")
    try:
        rows = db.execute(f"SELECT name FROM products WHERE id = {pid}").fetchall()
    except Exception as e:
        print("SQL error:", repr(e), "| query id =", repr(pid), flush=True)
        abort(500)
    if not rows:
        abort(404)
    return str(rows)

@app.get("/search")
def search():
    return f"results for {request.args.get('q', '')[:50]}"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return "ok", 302
    return "login form"

@app.get("/static/<path:f>")
def static_file(f):
    abort(404)