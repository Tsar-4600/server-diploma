// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');


const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;  // Порт, на котором будет запущен сервер






//check signature-tokken
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.error('FATAL ERROR: JWT_SECRET is not defined.');
  process.exit(1); // Завершаем приложение, если секретный ключ не установлен
}

app.use(cors());  // Разрешаем CORS
app.use(express.json());  // Для парсинга данных в JSON


//db_connection
const connection = mysql.createConnection({
  host: '185.207.0.190', // IP-адрес вашего MySQL сервера
  user: 'tsar',      // ваше имя пользователя
  password: 'tsar12345',  // ваш пароль
  database: 'test_DB',     // имя вашей базы данных
  charset: 'utf8mb4'
});

connection.connect((err) => {
  if (err) {
    console.error('Ошибка подключения: ' + err.stack);
    return;
  }
  console.log('Подключен к бд как id ' + connection.threadId);
});



// token validation with middleware function

app.get('/api/validate-token', (req, res)=> {
 
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (token == null) {
      // Токена нет - не авторизован
      return res.sendStatus(401);
    }
  
    jwt.verify(token, jwtSecret, (err) => {
      if (err) {
        // Токен недействителен
        console.error('Ошибка валидации токена:', err.message);
        return res.sendStatus(403); // Или 401
      }
  
      // Токен действителен
      res.status(200).json({ success: true, message: 'Токен действителен',});
    });
});



// выгрузка вопросов
app.get('/api/questions', (req, res) => {


  const query = `SELECT 
                    moodle_questions.id_question as id,
                    moodle_questions.title as name,
                    question_types.name AS type,
                    Category.name as category,
                    moodle_questions.xml
                  FROM moodle_questions
                  JOIN 
                    question_types ON  moodle_questions.id_question_type = question_types.id_question_type
                  JOIN 
                    Category ON moodle_questions.id_category = Category.id_category;
                  `;
  connection.execute(query, (err, results) => {
    if (err) {
      console.error('Ошибка при выполнении запроса к бд: ' + err.stack);
      return res.status(500).json({ message: 'Произошла ошибка при загрузке вопросов.' });
    }
    // results - это массив объектов, где каждый объект представляет строку из таблицы
    console.log(results);
    res.json(results);    // Возвращаем данные клиенту
  });

});




// Обработчик для авторизации
// ОБНОВЛЕННЫЙ ОБРАБОТЧИК ДЛЯ АВТОРИЗАЦИИ
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // 1. Находим пользователя по имени пользователя
  const findUserQuery = 'SELECT * FROM User WHERE username = ?';
  connection.execute(findUserQuery, [username], async (err, results) => {
    if (err) {
      console.error('Ошибка при поиске пользователя:', err.stack);
      return res.status(500).json({ success: false, message: 'Произошла ошибка.' });
    }

    // 2. Проверяем, найден ли пользователь
    if (results.length === 0) {
      // Пользователь не найден
      return res.status(401).json({ success: false, message: 'Неправильное имя пользователя или пароль.' });
    }

    // 3. Получаем хешированный пароль из базы данных
    const user = results[0];
    const storedHashedPassword = user.password;

    try {
      // 4. Сравниваем введенный пароль с хешированным паролем из БД
      const match = await bcrypt.compare(password, storedHashedPassword);

      if (match) {
        // Пароли совпадают - пользователь успешно авторизован

        // --- ГЕНЕРАЦИЯ JWT ---
        const payload = {
          // Включаем в токен информацию, которая может быть полезна на клиенте
          // и для проверки прав доступа на сервере.
          // НЕ включайте сюда чувствительные данные вроде пароля!
          userId: user.id_user, // id_user в таблице User
          username: user.username,
        };

        const token = jwt.sign(
          payload,
          jwtSecret,
        );
        // --- КОНЕЦ ГЕНЕРАЦИИ JWT ---

        res.status(200).json({ success: true, message: 'Вход выполнен успешно!', token});
        console.log('Авторизация прошла успешно');
      } else {
        // Пароли не совпадают
        res.status(401).json({ success: false, message: 'Неправильное имя пользователя или пароль.' });
      }
    } catch (error) {
      console.error('Ошибка при сравнении паролей:', error);
      res.status(500).json({ success: false, message: 'Произошла ошибка при входе.' });
    }
  });
});


// Обработчик для регистрации
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;

  // Проверка наличия пользователя с таким именем (опционально, но рекомендуется)
  const checkUserQuery = 'SELECT * FROM User WHERE username = ?';
  connection.execute(checkUserQuery, [username], async (err, results) => {
    if (err) {
      console.error('Ошибка при проверке пользователя:', err.stack);
      return res.status(500).json({ success: false, message: 'Произошла ошибка при регистрации.' });
    }

    if (results.length > 0) {
      return res.status(400).json({ success: false, message: 'Пользователь с таким именем уже существует.' });
    }

    try {
      // Генерируем соль и хешируем пароль
      const saltRounds = 10; // Количество раундов хеширования (можно увеличить)
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const id_role = 1;

      // Вставляем нового пользователя в базу данных с хешированным паролем
      const insertUserQuery = 'INSERT INTO User (id_role, username, password, email) VALUES (?, ?, ?, ?)';
      connection.execute(insertUserQuery, [id_role, username, hashedPassword, email], (err, result) => {
        if (err) {
          console.error('Ошибка при вставке пользователя:', err.stack);
          return res.status(500).json({ success: false, message: 'Произошла ошибка при регистрации.' });
        }
        console.log(`Пользователь ${username} успешно зарегистрирован.`);
        res.status(201).json({ success: true, message: 'Пользователь успешно зарегистрирован.' });
      });

    } catch (error) {
      console.error('Ошибка при хешировании пароля:', error);
      res.status(500).json({ success: false, message: 'Произошла ошибка при регистрации.' });
    }
  });
});
// Запускаем сервер
app.listen(PORT, () => {
  console.log(`Сервак работает на порту: http://localhost:${PORT}`);
});
