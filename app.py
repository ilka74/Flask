import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, flash, session
from datetime import datetime
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tpbuh.db'  # /// - корневой каталог проекта
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '1b17f9c8168e3045c0fd3f833985b7aefdb6e76e'

db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Инициализируем диспетчер входа в систему:
login_manager = LoginManager()
login_manager.init_app(app)

# Set the login_view to the name of the login route
login_manager.login_view = "index"  # Redirect to the index route if not logged in


# Загрузчик пользователей: функция загрузки пользователей, которую Flask-Login будет использовать
# для получения пользователя из сеанса
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    nik = db.Column(db.String(20), unique=True)
    psw = db.Column(db.String(500), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    # Определение отношений
    profiles = db.relationship('Profiles', backref='user', cascade='all, delete-orphan')  # Каскадное удаление профилей
    tasks = db.relationship('Tasks', backref='user', cascade='all, delete-orphan')  # Каскадное удаление задач

    def __repr__(self):
        return f"<users {self.id}>"


class Profiles(db.Model):
    __tablename__ = 'profiles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.Integer)
    name_organization = db.Column(db.String(100), nullable=False)
    inn_organization = db.Column(db.Integer)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Определение отношений
    tasks = db.relationship('Tasks', backref='profile', cascade='all, delete-orphan')  # Каскадное удаление задач

    def __repr__(self):
        return f"<profiles {self.id}>"


class Tasks(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    task_name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='new')

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    profile_id = db.Column(db.Integer, db.ForeignKey('profiles.id'))

    # Каскадные удаления
    assessments = db.relationship('Assessment', backref='task', cascade="all, delete-orphan")

    def __repr__(self):
        return f"<tasks {self.id}>"


class Assessment(db.Model):
    __tablename__ = 'assessment'
    id = db.Column(db.Integer, primary_key=True)
    evaluation = db.Column(db.Integer)  # оценка работы специалистов
    comm = db.Column(db.String(200))

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    profile_id = db.Column(db.Integer, db.ForeignKey('profiles.id'))
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'))

    def __repr__(self):
        return f"<assessment {self.id}>"


@app.route("/register", methods=("POST", "GET"))
def register():
    if request.method == "POST":
        # Проверка корректности введенных данных
        nik = request.form['nik']
        psw = request.form['psw']
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        name_organization = request.form['name_organization']
        inn_organization = request.form['inn_organization']

        # Validate 'nik' length
        if len(nik) < 5 or len(nik) > 20:
            flash("Ник должен содержать от 5 до 20 символов.", "error")
            return render_template('register.html', title='Регистрация')

        # Check if 'nik' already exists
        existing_user = Users.query.filter_by(nik=nik).first()
        if existing_user:
            flash("Этот ник уже занят. Пожалуйста, выберите другой.", "error")
            return render_template('register.html', title='Регистрация')

        # Validate 'psw' length
        if len(psw) < 8:
            flash('Длина пароля не может быть менее 8 символов', category='error')
            return render_template('register.html', title='Регистрация')

        telephone_pattern = r'^[0-9]{3}-[0-9]{3}-[0-9]{4}$'
        if not re.match(telephone_pattern, phone):
            flash('Неверный формат телефона. Используйте формат XXX-XXX-XXXX', category='error')
            return render_template('register.html', title='Регистрация')

        if len(inn_organization) not in (10, 12):
            flash('ИНН должен состоять из 10 (для юридического лица) или 12 (для ИП) цифр', category='error')
            return render_template('register.html', title='Регистрация')

        try:
            # Hash the password
            hashed_password = generate_password_hash(psw)
            # Create a new user
            u = Users(nik=nik, psw=hashed_password)
            db.session.add(u)
            db.session.flush()

            # Create a new profile
            p = Profiles(name=name, email=email, phone=phone, name_organization=name_organization,
                         inn_organization=inn_organization, user_id=u.id)
            db.session.add(p)
            db.session.commit()
            flash("Регистрация прошла успешно!", "success")
            return render_template('success.html')
        except Exception as e:
            db.session.rollback()
            print(f"Ошибка добавления в БД: {e}")
            flash("Произошла ошибка при регистрации. Пожалуйста, попробуйте еще раз.", "error")

    return render_template('register.html', title='Регистрация')


# Обработка для администратора (управление задачами)
@app.route("/admin/tasks", methods=("GET",))
def admin_tasks():
    # Проверяем, есть ли пользователь в сессии и является ли он администратором
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))

    # Получаем все задачи
    tasks_list = Tasks.query.all()

    return render_template('admin_tasks.html', title='Администрирование задач', tasks=tasks_list)


def is_admin(user_id):
    # Проверка, является ли пользователь администратором
    user = Users.query.get(user_id)
    return user.is_admin  # Предполагается, что у пользователя есть поле is_admin


# Обработчик для обновления статуса задачи

@app.route("/admin/tasks/update_status/<int:task_id>/<status>", methods=("POST",))
def update_task_status(task_id, status):
    # Проверяем, есть ли пользователь в сессии и является ли он администратором
    if 'user_id' not in session or not is_admin(session['user_id']):
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))

    task = Tasks.query.get(task_id)
    if task:
        task.status = status
        db.session.commit()
        flash("Статус задачи обновлен", "success")
    else:
        flash("Задача не найдена", "error")

    return redirect(url_for('admin_tasks'))


@app.route("/index",  methods=("POST", "GET"))
@app.route("/", methods=["POST", "GET"])
def index():
    if request.method == 'POST':
        nik = request.form['nik']
        psw = request.form['psw']

        # Находим пользователя по нику
        user = Users.query.filter_by(nik=nik).first()
        if user and check_password_hash(user.psw, psw):  # Проверка пароля
            session['user_id'] = user.id  # Сохраняем идентификатор пользователя в сеансе
            flash('Успешная авторизация', 'success')
            return redirect(url_for('index'))  # Перенаправление на ту же страницу
        else:
            flash('Неверный ник или пароль. Пожалуйста, попробуйте снова.', 'error')
    # Проверяем, авторизован ли пользователь
    user_id = session.get('user_id')
    user = Users.query.get(user_id) if user_id else None  # Получаем пользователя по user_id

    return render_template('index.html', title='Главная', user=user)


# Для выхода пользователя из системы
@app.route("/logout")
def logout():
    session.pop('user_id', None)  # Remove user ID from session
    flash("Вы успешно вышли из системы.", "success")
    return redirect(url_for('index'))  # Redirect to login page after logout


# Редактирование профиля пользователя
@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    # Check if user is logged in
    if 'user_id' not in session:
        flash('Пожалуйста, авторизуйтесь для доступа к редактированию профиля', 'error')
        return redirect(url_for('index'))

    user_id = session['user_id']
    user = Users.query.get(user_id)
    profile = Profiles.query.filter_by(user_id=user_id).first()

    if request.method == "POST":
        # Get updated data from the form
        user.nik = request.form['nik']
        profile.name = request.form['name']
        profile.email = request.form['email']
        profile.phone = request.form['phone']
        profile.name_organization = request.form['name_organization']
        profile.inn_organization = request.form['inn_organization']

        # Validate input as needed (e.g., check phone format)

        db.session.commit()  # Commit changes to database
        flash("Профиль успешно обновлен!", "success")
        return redirect(url_for('index'))  # Redirect to main page

    return render_template('edit_profile.html', user=user, profile=profile)


# обработчик удаления пользователя

@app.route("/delete_account", methods=["GET", "POST"])
def delete_account():
    # Логика удаления аккаунта
    if request.method == "POST":
        # проверяем, авторизован ли пользователь
        if 'user_id' not in session:
            flash('Пожалуйста, авторизуйтесь для удаления аккаунта', 'error')
            return redirect(url_for('index'))

        user_id = session['user_id']
        user = Users.query.get(user_id)

        if user:
            db.session.delete(user)
            db.session.commit()
            flash("Ваш аккаунт был удален", "success")
            session.pop('user_id', None)  # Удаляем пользователя из сессии
        else:
            flash("Пользователь не найден!", "error")

        return redirect(url_for('index'))

    # для метода GET отображаем страницу удаления
    user_id = session.get('user_id')
    user = Users.query.get(user_id) if user_id else None
    user_nik = user.nik if user else "Гость"  # Используем "Гость", если пользователь не найден

    return render_template('delete_account.html', user_nik=user_nik)


@app.route("/tasks", methods=("POST", "GET"))
def tasks():
    # Проверяем, есть ли пользователь в сессии
    if 'user_id' not in session:
        flash('Пожалуйста, авторизуйтесь для доступа к отправке сообщения', 'error')
        return redirect(url_for('index'))

    user_id = session['user_id']  # Получаем user_id из сессии
    user = Users.query.get(user_id)  # Получаем пользователя по user_id
    profile = Profiles.query.filter_by(user_id=user_id).first()  # Получаем профиль по user_id

    # Инициализация списка задач для передачи в шаблон
    tasks_list = Tasks.query.filter_by(user_id=user.id).all()

    if request.method == 'POST':
        # Получаем данные из формы
        task_name = request.form['task_name']
        description = request.form['description']

        # Создаем новую задачу, используя данные из пользователя и профиля
        new_task = Tasks(
            task_name=task_name,
            description=description,
            user_id=user.id,  # Связываем задачу с пользователем
            profile_id=profile.id  # Связываем задачу с профилем
        )
        db.session.add(new_task)
        db.session.commit()
        flash("Задача успешно создана!", "success")
        return redirect(url_for('tasks'))  # Перенаправление на ту же страницу для обновления списка задач

    # Передаем необходимые данные
    return render_template('tasks.html', title='Сообщения', user=user, profile=profile, tasks=tasks_list)


@app.route("/assessment", methods=("POST", "GET"))
def assessment():
    # Проверяем, есть ли пользователь в сессии
    if 'user_id' not in session:
        flash('Пожалуйста, авторизуйтесь для доступа к отправке сообщения', 'error')
        return redirect(url_for('index'))

    user_id = session['user_id']  # Получаем user_id из сессии
    user = Users.query.get(user_id)  # Получаем пользователя по user_id
    profile = Profiles.query.filter_by(user_id=user_id).first()  # Получаем профиль по user_id

    # Получаем все задачи пользователя
    tasks = Tasks.query.filter_by(user_id=user_id).all()

    if request.method == 'POST':
        # Обработка редактирования задачи
        if 'edit_task_id' in request.form:
            task_id = request.form['edit_task_id']
            task = Tasks.query.get(task_id)
            if task:  # Проверка, существует ли задача
                task.description = request.form['description']
                db.session.commit()
                flash("Задача успешно обновлена!", "success")
            else:
                flash("Задача не найдена!", "error")

        # Обработка закрытия задачи
        elif 'delete_task_id' in request.form:
            task_id = request.form['delete_task_id']
            task = Tasks.query.get(task_id)
            if task:  # Проверка, существует ли задача
                db.session.delete(task)
            db.session.commit()
            flash("Задача успешно закрыта!", "success")

        return redirect(url_for('assessment'))  # Перенаправление на ту же страницу для обновления списка задач

    return render_template('assessment.html', title='Мои задачи', tasks=tasks, user=user, profile=profile)


@app.route('/submit_ratings', methods=['POST'])
def submit_ratings():
    # Проверяем, есть ли пользователь в сессии
    if 'user_id' not in session:
        flash('Пожалуйста, авторизуйтесь для доступа к отправке оценок', 'error')
        return redirect(url_for('index'))

    user_id = session['user_id']
    profile = Profiles.query.filter_by(user_id=user_id).first()

    # Iterate over all tasks associated with the user
    for task in Tasks.query.filter_by(user_id=user_id).all():
        task_id = task.id
        rating_key = f'rating_{task_id}'
        comment_key = f'comm_{task_id}'
        rating_value = request.form.get(rating_key)
        comment_value = request.form.get(comment_key)

        # Only create a new Assessment entry if a rating is provided
        if rating_value:
            new_assessment = Assessment(
                evaluation=int(rating_value),
                comm=comment_value,  # Comment associated with the task
                user_id=user_id,
                profile_id=profile.id,  # Ensure profile_id is included
                task_id=task_id
            )
            db.session.add(new_assessment)  # Add the new assessment to the session

    try:
        db.session.commit()  # Commit the session to save changes to the database
        flash('Ваши изменения успешно отправлены в базу данных!', 'success')
    except Exception as e:
        print(f'Error occurred: {e} ')
        flash('Произошла ошибка при отправке данных!', 'error')
    return redirect(url_for('assessment'))  # Redirect back to assessment page


if __name__ == "__main__":
    app.run(debug=False)

