def find_user_by_name(cursor, name):
    return cursor.execute("SELECT * FROM users WHERE name = %s", (name,))


def search(index, term):
    filter_expr = "status:active AND tag:" + term
    return index.execute(filter_expr)
