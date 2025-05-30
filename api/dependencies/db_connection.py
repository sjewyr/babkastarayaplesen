import fastapi


def get_db_connection(request: fastapi.Request):
    return request.app.state.db