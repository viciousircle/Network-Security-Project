from flask import Flask, request, jsonify

app = Flask(__name__)

# Dữ liệu người dùng (sử dụng cho ví dụ đơn giản này)
users = {
    "admin": "password"
}

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()  # Get JSON data from the request
    username = data.get("username")
    password = data.get("password")
    
    # Kiểm tra thông tin đăng nhập
    if users.get(username) == password:
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

if __name__ == "__main__":
    app.run(debug=True)
