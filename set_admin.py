import sys
from app import app, db, Users  # Импортируйте приложение, базу данных и модель Users


def set_admin(user_id, is_admin):
    with app.app_context():  # Создаем контекст приложения
        user = db.session.get(Users, user_id)  # Получаем пользователя по ID
        if user is None:
            print(f"Пользователь с ID {user_id} не найден.")
            return
        user.is_admin = is_admin  # Устанавливаем статус администратора
        db.session.commit()  # Сохраняем изменения
        print(f"Пользователь {user.nik} теперь {'администратор' if is_admin else 'не администратор'}.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python set_admin.py <user_id> <is_admin (True/False)>")
        sys.exit(1)

    user_id = int(sys.argv[1])  # ID пользователя
    is_admin = sys.argv[2].lower() == 'true'  # Преобразуем строку в булевое значение

    set_admin(user_id, is_admin)  # Вызываем функцию для установки статуса
