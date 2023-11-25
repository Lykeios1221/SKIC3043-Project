from flask import get_flashed_messages

from app import app

if __name__ == "__main__":
    app.run(debug=True)
    with app.app_context():
        get_flashed_messages()
