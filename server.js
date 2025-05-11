// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { create } = require('xmlbuilder2');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// Проверка JWT секрета
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.error('FATAL ERROR: JWT_SECRET is not defined.');
  process.exit(1);
}

// Подключение к базе данных
const connection = mysql.createConnection({
  host: '185.207.0.190',
  user: 'tsar',
  password: 'tsar12345',
  database: 'test_DB',
  charset: 'utf8mb4'
});

connection.connect((err) => {
  if (err) {
    console.error('Ошибка подключения: ' + err.stack);
    return;
  }
  console.log('Подключен к бд как id ' + connection.threadId);
});

// Middleware
app.use(cors());
app.use(express.json());

// =============================================
// Вспомогательные функции
// =============================================

/**
 * Middleware для проверки JWT токена
 */
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Требуется авторизация' });
  }

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      console.error('Ошибка валидации токена:', err.message);
      return res.status(403).json({ success: false, message: 'Недействительный токен' });
    }

    req.user = user;
    next();
  });
};

/**
 * Универсальная функция для генерации XML вопроса
 */
function generateQuestionXML(data) {
  const escapeXml = (unsafe) => {
    if (!unsafe) return '';
    return unsafe.toString()
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  };

  const root = create({ version: '1.0' }).ele('question', { type: data.questionType });

  // Общие поля
  root.ele('name').ele('text').txt(escapeXml(data.name));
  root.ele('questiontext', { format: 'html' }).ele('text').txt(escapeXml(data.questionText));
  root.ele('defaultgrade').txt(Number(data.defaultGrade || 1).toFixed(2));
  root.ele('penalty').txt(Number(data.penalty || 0).toFixed(2));
  root.ele('hidden').txt(data.hidden ? '1' : '0');

  // Обработка типов вопросов
  switch (data.questionType) {
    case 'multichoice':
    case 'truefalse':
      root.ele('shuffleanswers').txt(data.shuffleAnswers ? '1' : '0');
      root.ele('single').txt(data.single ? 'true' : 'false');

      data.answers.forEach((answer) => {
        root.ele('answer', {
          fraction: answer.isCorrect ? '100' : '0',
          format: 'html',
        })
          .ele('text').txt(escapeXml(answer.text)).up()
          .ele('feedback').ele('text').txt('');
      });
      break;

    case 'shortanswer':
      if (data.correctAnswer) {
        root.ele('answer').txt(escapeXml(data.correctAnswer));
      }
      break;

    case 'numerical':
      root.ele('answer', { fraction: '100' })
        .ele('text').txt(Number(data.numericalAnswer).toFixed(2));
      root.ele('tolerance').txt(Number(data.tolerance || 0).toFixed(2));
      break;

    case 'matching':
      data.matchingPairs.forEach((pair) => {
        root.ele('subquestion')
          .ele('text').txt(escapeXml(pair.question)).up()
          .ele('answer').txt(escapeXml(pair.answer));
      });
      break;

    case 'essay':
      const settings = data.essaySettings || {};
      const essayNode = root.ele('essay');
      essayNode.ele('responseformat').txt(settings.responseFormat || 'editor');
      essayNode.ele('responserequired').txt(settings.responseRequired ? '1' : '0');
      essayNode.ele('responsefieldlines')
        .txt(String(Math.min(Math.max(settings.responseFieldLines || 15, 5), 50)));
      break;

    default:
      throw new Error(`Unsupported question type: ${data.questionType}`);
  }

  return root.end({ prettyPrint: true, headless: true });
}

/**
 * Универсальная функция для получения или создания записи
 */
function getOrCreateRecord(connection, table, nameField, idField, value, callback) {
  connection.query(
    `SELECT ${idField} FROM ${table} WHERE ${nameField} = ?`,
    [value],
    (err, rows) => {
      if (err) return callback(err);
      
      if (rows.length > 0) {
        return callback(null, rows[0][idField]);
      }
      
      connection.query(
        `INSERT INTO ${table} (${nameField}) VALUES (?)`,
        [value],
        (err, result) => callback(err, err ? null : result.insertId)
      );
    }
  );
}

function getOrCreateQuestionType(connection, questionTypeStr, callback) {
  getOrCreateRecord(
    connection,
    'question_types',
    'name',
    'id_question_type',
    questionTypeStr,
    callback
  );
}

function getOrCreateCategory(connection, categoryName, callback) {
  getOrCreateRecord(
    connection,
    'Category',
    'name',
    'id_category',
    categoryName,
    callback
  );
}

// =============================================
// Роуты
// =============================================

// Валидация токена
app.get('/api/validate-token', authenticateJWT, (req, res) => {
  res.status(200).json({ 
    success: true, 
    message: 'Токен действителен',
    user: {
      userId: req.user.userId,
      username: req.user.username
    }
  });
});

// Получение списка вопросов
app.get('/api/questions', (req, res) => {
  const query = `SELECT 
                  moodle_questions.id_question as id,
                  moodle_questions.title as name,
                  question_types.name AS type,
                  Category.name as category,
                  moodle_questions.xml
                FROM moodle_questions
                JOIN question_types ON moodle_questions.id_question_type = question_types.id_question_type
                JOIN Category ON moodle_questions.id_category = Category.id_category`;
  
  connection.execute(query, (err, results) => {
    if (err) {
      console.error('Ошибка при выполнении запроса:', err.stack);
      return res.status(500).json({ message: 'Ошибка при загрузке вопросов' });
    }
    res.json(results);
  });
});



app.get('/api/my-questions', authenticateJWT, (req, res) => {
  const userId = req.user.userId;
  
  const query = `SELECT 
                  moodle_questions.id_question as id,
                  moodle_questions.title as name,
                  question_types.name AS type,
                  Category.name as category,
                  moodle_questions.xml
                FROM moodle_questions
                JOIN question_types ON moodle_questions.id_question_type = question_types.id_question_type
                JOIN Category ON moodle_questions.id_category = Category.id_category
                WHERE moodle_questions.id_user = ?`; // Добавляем условие WHERE
  
  connection.execute(query, [userId], (err, results) => { // Передаем userId как параметр
    if (err) {
      console.error('Ошибка при выполнении запроса:', err.stack);
      return res.status(500).json({ message: 'Ошибка при загрузке вопросов' });
    }
    res.json(results);
  });
});

// Авторизация
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  const findUserQuery = 'SELECT * FROM User WHERE username = ?';
  connection.execute(findUserQuery, [username], async (err, results) => {
    if (err) {
      console.error('Ошибка при поиске пользователя:', err);
      return res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }

    if (results.length === 0) {
      return res.status(401).json({ success: false, message: 'Неверные учетные данные' });
    }

    const user = results[0];
    
    try {
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        const token = jwt.sign(
          { userId: user.id_user, username: user.username },
          jwtSecret
        );

        res.status(200).json({ 
          success: true, 
          message: 'Авторизация успешна', 
          token,
          user: {
            userId: user.id_user,
            username: user.username
          }
        });
      } else {
        res.status(401).json({ success: false, message: 'Неверные учетные данные' });
      }
    } catch (error) {
      console.error('Ошибка при сравнении паролей:', error);
      res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
  });
});

// Регистрация
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;

  const checkUserQuery = 'SELECT * FROM User WHERE username = ?';
  connection.execute(checkUserQuery, [username], async (err, results) => {
    if (err) {
      console.error('Ошибка при проверке пользователя:', err);
      return res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }

    if (results.length > 0) {
      return res.status(400).json({ success: false, message: 'Пользователь уже существует' });
    }

    try {
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const id_role = 1;

      const insertUserQuery = 'INSERT INTO User (id_role, username, password, email) VALUES (?, ?, ?, ?)';
      connection.execute(insertUserQuery, [id_role, username, hashedPassword, email], (err) => {
        if (err) {
          console.error('Ошибка при регистрации:', err);
          return res.status(500).json({ success: false, message: 'Ошибка сервера' });
        }
        res.status(201).json({ success: true, message: 'Регистрация успешна' });
      });
    } catch (error) {
      console.error('Ошибка при хешировании пароля:', error);
      res.status(500).json({ success: false, message: 'Ошибка сервера' });
    }
  });
});

// Создание вопроса
app.post('/api/my-questions/create', authenticateJWT, (req, res) => {
  try {
    const xml = generateQuestionXML(req.body);
    console.log(xml);
    getOrCreateQuestionType(connection, req.body.questionType, (err, questionTypeId) => {
      if (err) {
        console.error('Ошибка типа вопроса:', err);
        return res.status(500).json({ status: 'error', message: 'Ошибка типа вопроса' });
      }

      getOrCreateCategory(connection, req.body.name, (err, categoryId) => {
        if (err) {
          console.error('Ошибка категории:', err);
          return res.status(500).json({ status: 'error', message: 'Ошибка категории' });
        }

        connection.query(
          `INSERT INTO moodle_questions 
           (id_category, id_question_type, id_user, title, xml) 
           VALUES (?, ?, ?, ?, ?)`,
          [categoryId, questionTypeId, req.user.userId, req.body.questionText, xml],
          (err) => {
            if (err) {
              console.error('Ошибка сохранения:', err);
              return res.status(500).json({ status: 'error', message: 'Ошибка сохранения' });
            }
         
            res.json({ 
              status: 'success', 
              message: 'Вопрос сохранен',
              data: { xml } 
            });
          }
        );
      });
    });
  } catch (error) {
    console.error('Ошибка генерации XML:', error);
    res.status(400).json({ status: 'error', message: error.message });
  }
});



/*
* @route DELETE /api/my-questions/:id
* @desc Удаление вопроса текущего пользователя
* @access Private
*/
app.delete('/api/my-questions/:id', authenticateJWT, (req, res) => {
 const questionId = req.params.id;
 const userId = req.user.userId;

 // 1. Проверяем существование вопроса и принадлежность пользователю
 const checkQuery = `
   SELECT id_question 
   FROM moodle_questions 
   WHERE id_question = ? AND id_user = ?
 `;

 connection.execute(checkQuery, [questionId, userId], (checkErr, checkResults) => {
   if (checkErr) {
     console.error('Ошибка проверки вопроса:', checkErr);
     return res.status(500).json({ 
       success: false,
       message: 'Ошибка при проверке вопроса' 
     });
   }

   if (checkResults.length === 0) {
     return res.status(404).json({ 
       success: false,
       message: 'Вопрос не найден или у вас нет прав на его удаление' 
     });
   }

   // 2. Удаляем вопрос
   const deleteQuery = `
     DELETE FROM moodle_questions 
     WHERE id_question = ?
   `;

   connection.execute(deleteQuery, [questionId], (deleteErr, deleteResult) => {
     if (deleteErr) {
       console.error('Ошибка удаления вопроса:', deleteErr);
       return res.status(500).json({ 
         success: false,
         message: 'Ошибка при удалении вопроса' 
       });
     }

     if (deleteResult.affectedRows === 0) {
       return res.status(404).json({ 
         success: false,
         message: 'Вопрос не найден' 
       });
     }

     // 3. Успешный ответ
     res.json({
       success: true,
       message: 'Вопрос успешно удален',
       deletedId: questionId
     });
   });
 });
});




// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту: http://localhost:${PORT}`);
});