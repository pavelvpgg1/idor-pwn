from flask import Flask, jsonify, request
import logging

app = Flask(__name__)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ФЕЙКОВАЯ БАЗА ДАННЫХ
ORDERS = {
    1: {"id": 1, "owner_id": 100, "item": "MacBook Pro", "price": 250000},
    2: {"id": 2, "owner_id": 101, "item": "iPhone 15", "price": 120000},
    3: {"id": 3, "owner_id": 100, "item": "AirPods", "price": 30000},
    4: {"id": 4, "owner_id": 102, "item": "RTX 4090", "price": 350000},
}

def get_current_user():
    # ❌ КРИТИЧЕСКАЯ ОШИБКА: доверяем заголовку
    user_id = int(request.headers.get("X-User-ID", 100))
    logger.info(f"Request from user {user_id} for order {request.view_args.get('order_id')}")
    return user_id

@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    current_user = get_current_user()
    order = ORDERS.get(order_id)
    
    logger.info(f"User {current_user} requesting order {order_id}")
    
    if not order:
        logger.warning(f"Order {order_id} not found")
        return jsonify({"error": "Not found"}), 404

    # ❌ IDOR: НЕТ ПРОВЕРКИ owner_id
    logger.info(f"IDOR VULNERABILITY: User {current_user} accessing order {order_id} owned by {order['owner_id']}")
    return jsonify(order)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
