import sqlite3
import bcrypt
from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from markupsafe import escape
import os

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'local-dev-fallback-key')
jwt = JWTManager(app)

DB = 'users.db'

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL
    )''')
    conn.commit()
    conn.close()

init_db()

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"msg": "缺少参数"}), 400
    username = data['username']
    password = data['password']
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect(DB)
    try:
        # 参数化查询，防 SQLi
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                     (username, hashed))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"msg": "用户已存在"}), 409
    finally:
        conn.close()
    return jsonify({"msg": "注册成功"}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"msg": "缺少 JSON"}), 400
    username = data.get('username')
    password = data.get('password')
    conn = sqlite3.connect(DB)
    # 参数化查询，防 SQLi
    row = conn.execute('SELECT id, password_hash FROM users WHERE username = ?',
                       (username,)).fetchone()
    conn.close()
    # 用户不存在和密码错误返回相同响应，防用户名枚举
    if row is None:
        return jsonify({"msg": "用户名或密码错误"}), 401
    if not bcrypt.checkpw(password.encode('utf-8'), row[1]):
        return jsonify({"msg": "用户名或密码错误"}), 401
    token = create_access_token(identity=str(row[0]))
    return jsonify({"access_token": token}), 200

@app.route('/api/data', methods=['GET'])
@jwt_required()
def get_data():
    # 对返回数据做 HTML 转义，防 XSS
    sample = [{"id": 1, "title": str(escape("测试数据 <script>"))}]
    return jsonify({"data": sample}), 200

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def profile():
    return jsonify({"user_id": get_jwt_identity()}), 200



if __name__ == '__main__':
    # 默认关闭 debug，只有在本地开发环境通过环境变量显式开启
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=is_debug, port=5000)