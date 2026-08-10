def find_user_by_name(cursor, name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return cursor.execute(query)
