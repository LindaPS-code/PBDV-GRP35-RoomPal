from app import app, initialize_app


if __name__ == '__main__':
    initialize_app()
    app.run(host='127.0.0.1', port=5001, debug=False)
