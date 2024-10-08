Это веб-приложение разарботано на основе фреймворка "Flask" предназначено для организации работы консультантов технической поддержки с клиентами, например Франчайзи 1С и бухгалтерии предприятия.
Клиент может самостоятельно зарегистрироваться на сайте, редактировать профиль своей организации (при необходимости), ставить задачи перед консультантами (отправить сообщение), редактировать текст ранее созданных задач, а также закрывать их.

В публичном доступе на сайте отображаются все пункты главного меню, но технически можно перейти только по ссылкам «Главная» (страница о фирме – владельце сайта),  «Регистрация», и «Вход» для уже зарегистрированных клиентов. Переход по ссылкам «Оставить сообщение», «Мои задачи», «Профиль» недоступен для незарегистрированных клиентов.

Форма регистрации клиента:
![image](https://github.com/user-attachments/assets/7195508e-6bb0-47f8-a27d-5ce474121a1c)

После регистрации клиенту предлагается создать сообщение (поставить перед консультантами задачу). При этом в данной форме отображается Ник клиента, наименование и ИНН его организации (эти поля только для чтения). А также можно поставить задачу и предоставить подробное ее описание:
![image](https://github.com/user-attachments/assets/41d6a990-5f5a-4ee4-b5e0-421f86f4613b)

Раздел "Мои задачи": после того, как консультанты выполнили поставленную задачу, клиент имеет возможность выставить консультанту оценку за работу (от 1 о 5), оставить комментарий и нажать кнопку «закрыть задачу», может удалить свою ранее поставленную задачу
![image](https://github.com/user-attachments/assets/60da4260-bad5-4398-8d76-50672619ceac)

Все эти действия для клиента являются необязательными – он может выполнить одно или два из этих действий, может все, а может ни одного.

Под разделом администрирования на сайте предполагается, в первую очередь, отслеживание всех задач всей фирмы в целях контроля их отработки. Этот раздел доступен только администраторам (руководителям у консультантов): 
![image](https://github.com/user-attachments/assets/6b8a3661-55bc-4e6b-8895-45da98dd2a1a)

Также реализован раздел "Профиль" для тех случаев, когда изменяются реквизиты клиентов. В данной форме можно изменить все поля, кроме логина пользователя (его Ника):
![image](https://github.com/user-attachments/assets/be9a7b31-bc38-4ac1-b875-5b3a52badab1)

Раздел "Вход админа" Если у пользователя есть права администратора, то страница будет доступна, и мы увидим все задачи всех клиентов. Это удобно для контроля консультантов.
![image](https://github.com/user-attachments/assets/55383b16-c01c-475d-95b7-ea2a2b3b0a87)

Если пользователь не является администратором, то он получит такое всплывающее сообщение об отсутствии прав доступа:
![image](https://github.com/user-attachments/assets/cb34d667-bd95-4939-afc3-de5e927a5d83)

При каждом сохранении в проекте появляются всплывающие сообщения, в которых содержится информация об успешном или неуспешном действии
![image](https://github.com/user-attachments/assets/0babca4b-b736-44e2-9a61-b80687bb1a05)

Проект разработан в соответствии с ORM (объектно-реляционным отображением) с подключением к реляционной базе аанных SQLite3, которая входит в стандартную библиотеку Python и не требует дополнительных установок.
![image](https://github.com/user-attachments/assets/a67e350e-319f-4c65-a8be-95cb04900b39)

В структуре проекта использованы 4 модели: Users (пользователи), Profiles (профили организаций), Tasks (поставленные задачи) и Assessment (оценка работы с задачами). Все они описаны в виде классов, наследованных от встроенного в Пайтон родительского класса Model. В базе данных эти модели содержатся в виде таблиц с соответствующими наименованиями. 
![image](https://github.com/user-attachments/assets/bfcfc481-0ffd-4319-b564-36b8ee3ed969)

Для взаимодействия с базой данных написаны роуты (маршруты) и функции представления, для корректного отображения на экране созданы html-шаблоны и описания стилей оформления.
Вся основная логика прописана в главном модуле проекта - app.py:
![image](https://github.com/user-attachments/assets/6fe45478-fb8b-4335-a80f-a084077b9c6d)

Шаблоны и таблицы стилей в отдельных папках и файлах, соответственно templetes и static/css
![image](https://github.com/user-attachments/assets/de020012-f547-48d7-b2ed-4c5af089bbca)

В заключение скажу, что данное приложение можно использовать для различного взаимодействия между разными субъектами, не только в сфере бухгалтерского учета.Это достаточно универсальное решение, и при необходимости легко может быть доработано и адаптировано под текущие условия заказчика.
