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
  database: 'test2_DB',
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
  root.ele('name').ele('text').txt(escapeXml(data.name || ''));
  root.ele('questiontext', { format: 'html' }).ele('text').txt(escapeXml(data.questionText || ''));
  root.ele('defaultgrade').txt(Number(data.defaultGrade || 1).toFixed(2));
  root.ele('penalty').txt(Number(data.penalty || 0).toFixed(2));
  root.ele('hidden').txt(data.hidden ? '1' : '0');

  // Обработка типов вопросов
  switch (data.questionType) {
    case 'multichoice':
      root.ele('shuffleanswers').txt(data.shuffleAnswers ? '1' : '0');
      root.ele('single').txt(data.single ? 'true' : 'false');

      (data.answers || []).forEach((answer) => {
        const answerNode = root.ele('answer', {
          fraction: answer.isCorrect ? '100' : '0',
          format: 'html'
        });
        answerNode.ele('text').txt(escapeXml(answer.text || ''));
        answerNode.ele('feedback').ele('text').txt('');
      });
      break;

    case 'truefalse':
      root.ele('shuffleanswers').txt('0');
      root.ele('single').txt('true');
      
      // Добавляем стандартные ответы для true/false
      root.ele('answer', { fraction: '100', format: 'html' })
        .ele('text').txt('true').up()
        .ele('feedback').ele('text').txt('');
      
      root.ele('answer', { fraction: '0', format: 'html' })
        .ele('text').txt('false').up()
        .ele('feedback').ele('text').txt('');
      break;

    case 'shortanswer':
      root.ele('answer', { fraction: '100', format: 'plain_text' })
        .ele('text').txt(escapeXml(data.shortAnswer || ''));
      break;

    case 'numerical':
      root.ele('answer', { fraction: '100' })
        .ele('text').txt(Number(data.numericalAnswer || 0).toFixed(2));
      root.ele('tolerance').txt(Number(data.tolerance || 0).toFixed(2));
      break;

    case 'matching':
      (data.matchingPairs || []).forEach((pair) => {
        root.ele('subquestion', { format: 'html' })
          .ele('text').txt(escapeXml(pair.question || '')).up()
          .ele('answer').ele('text').txt(escapeXml(pair.answer || ''));
      });
      break;

    case 'essay':
      const settings = data.essaySettings || {};
      const essayNode = root.ele('essay');
      essayNode.ele('responseformat').txt(settings.responseFormat || 'editor');
      essayNode.ele('responserequired').txt(settings.responseRequired ? '1' : '0');
      essayNode.ele('responsefieldlines')
        .txt(String(Math.min(Math.max(settings.responseFieldLines || 15, 5), 50)));
      essayNode.ele('attachments').txt(settings.attachments || '0');
      essayNode.ele('attachmentsrequired').txt(settings.attachmentsRequired || '0');
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

// Получение списка категорий
app.get('/api/categories', (req, res) => {
  const query = 'SELECT name FROM Category ORDER BY name';
  connection.execute(query, (err, results) => {
    if (err) {
      console.error('Ошибка при загрузке категорий:', err.stack);
      return res.status(500).json({ message: 'Ошибка при загрузке категорий' });
    }
    res.json(results.map(row => row.name));
  });
});

// Получение тем по категории
app.get('/api/themes', (req, res) => {
  const { category } = req.query;
  if (!category) return res.status(400).json({ message: 'Укажите категорию' });

  const query = `
    SELECT t.name 
    FROM Theme t
    JOIN Category c ON t.id_category = c.id_category
    WHERE c.name = ?
    ORDER BY t.name
  `;
  
  connection.execute(query, [category], (err, results) => {
    if (err) {
      console.error('Ошибка при загрузке тем:', err.stack);
      return res.status(500).json({ message: 'Ошибка при загрузке тем' });
    }
    res.json(results.map(row => row.name));
  });
});

// Обновите запрос для получения вопросов, чтобы включать тему
app.get('/api/questions', (req, res) => {
  const query = `
    SELECT 
      mq.id_question as id,
      mq.title as name,
      qt.name AS type,
      c.name as category,
      t.name as theme,
      mq.xml
    FROM moodle_questions mq
    JOIN question_types qt ON mq.id_question_type = qt.id_question_type
    JOIN Theme t ON mq.id_theme = t.id_theme
    JOIN Category c ON t.id_category = c.id_category
  `;

  connection.execute(query, (err, results) => {
    if (err) {
      console.error('Ошибка при выполнении запроса:', err.stack);
      return res.status(500).json({ message: 'Ошибка при загрузке вопросов' });
    }
    res.json(results);
  });
});

//Вывод банка с тестами
app.get('/api/test-bank', authenticateJWT, (req, res) => {
  const sql = `
        SELECT 
            Test.id_test,
            Test.name AS test_name,
            User.username,
            Theme.name AS theme_name,
            Category.name AS category_name,
            COALESCE(AVG(TestRating.rating), 0) AS avg_rating,
            COUNT(TestRating.id_rating) AS rating_count,
            Test.xml
        FROM 
            Test
        LEFT JOIN 
            TestRating ON Test.id_test = TestRating.id_test
        LEFT JOIN
            Theme ON Test.id_theme = Theme.id_theme
        LEFT JOIN
            Category ON Theme.id_category = Category.id_category
        JOIN 
            User ON Test.id_user = User.id_user
        WHERE
            Test.public = 1
        GROUP BY 
            Test.id_test
        ORDER BY
            avg_rating DESC, rating_count DESC
  `;
  connection.query(sql, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Ошибка базы данных' });
    }
   
    res.json(results);
   
  });

});


// Обновленный маршрут для получения вопросов
app.get('/api/my-questions', authenticateJWT, (req, res) => {
  const userId = req.user.userId;

  const query = `
    SELECT 
      mq.id_question as id,
      mq.title as name,
      qt.name AS type,
      c.name as category,
      t.name as theme,
      mq.xml
    FROM moodle_questions mq
    JOIN question_types qt ON mq.id_question_type = qt.id_question_type
    JOIN Theme t ON mq.id_theme = t.id_theme
    JOIN Category c ON t.id_category = c.id_category
    WHERE mq.id_user = ?
  `;

  connection.execute(query, [userId], (err, results) => {
    if (err) {
      console.error('Ошибка при выполнении запроса:', err.stack);
      return res.status(500).json({ message: 'Ошибка при загрузке вопросов' });
    }
    res.json(results);
  });
});





//Тесты пользователя

app.get('/api/my-tests', authenticateJWT, (req, res) => {
  const userId = req.user.userId;

  const query = `
    SELECT 
      t.id_test as id,
      t.name as name,
      t.public,
      t.xml,
      th.name as theme,
      c.name as category
    FROM Test t
    JOIN Theme th ON t.id_theme = th.id_theme
    JOIN Category c ON th.id_category = c.id_category
    WHERE t.id_user = ?
    ORDER BY t.id_test DESC`;

  connection.execute(query, [userId], (err, results) => {
    if (err) {
      console.error('Ошибка при выполнении запроса:', err.stack);
      return res.status(500).json({ 
        success: false,
        message: 'Ошибка при загрузке тестов',
        error: err.message
      });
    }
    
    res.json({
      success: true,
      data: results
    });
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
// Обновленный маршрут для создания вопроса
app.post('/api/my-questions/create', authenticateJWT, async (req, res) => {
  try {
    const { name, theme, questionText, questionType, ...questionData } = req.body;
    
    // Генерация XML
    const xml = generateQuestionXML(req.body);
    
    // Начинаем транзакцию
    connection.beginTransaction(async (beginErr) => {
      if (beginErr) {
        console.error('Ошибка начала транзакции:', beginErr);
        return res.status(500).json({ status: 'error', message: 'Ошибка сервера' });
      }

      try {
        // 1. Получаем или создаем категорию
        const [categoryResult] = await connection.promise().execute(
          'SELECT id_category FROM Category WHERE name = ?',
          [name]
        );
        
        let categoryId;
        if (categoryResult.length > 0) {
          categoryId = categoryResult[0].id_category;
        } else {
          const [insertResult] = await connection.promise().execute(
            'INSERT INTO Category (name) VALUES (?)',
            [name]
          );
          categoryId = insertResult.insertId;
        }

        // 2. Получаем или создаем тему
        const [themeResult] = await connection.promise().execute(
          'SELECT id_theme FROM Theme WHERE name = ? AND id_category = ?',
          [theme, categoryId]
        );
        
        let themeId;
        if (themeResult.length > 0) {
          themeId = themeResult[0].id_theme;
        } else {
          const [insertResult] = await connection.promise().execute(
            'INSERT INTO Theme (id_category, name) VALUES (?, ?)',
            [categoryId, theme]
          );
          themeId = insertResult.insertId;
        }

        // 3. Получаем ID типа вопроса
        const [typeResult] = await connection.promise().execute(
          'SELECT id_question_type FROM question_types WHERE name = ?',
          [questionType]
        );
        
        if (typeResult.length === 0) {
          throw new Error('Тип вопроса не найден');
        }
        const questionTypeId = typeResult[0].id_question_type;

        // 4. Сохраняем вопрос
        await connection.promise().execute(
          `INSERT INTO moodle_questions 
           (id_theme, id_question_type, id_user, title, xml) 
           VALUES (?, ?, ?, ?, ?)`,
          [themeId, questionTypeId, req.user.userId, questionText, xml]
        );

        // Подтверждаем транзакцию
        connection.commit((commitErr) => {
          if (commitErr) {
            console.error('Ошибка подтверждения транзакции:', commitErr);
            return connection.rollback(() => {
              res.status(500).json({ status: 'error', message: 'Ошибка сохранения' });
            });
          }

          res.json({
            status: 'success',
            message: 'Вопрос сохранен',
            data: { xml }
          });
        });
      } catch (error) {
        // Откатываем транзакцию при ошибке
        connection.rollback(() => {
          console.error('Ошибка в транзакции:', error);
          res.status(500).json({ status: 'error', message: error.message });
        });
      }
    });
  } catch (error) {
    console.error('Ошибка генерации XML:', error);
    res.status(400).json({ status: 'error', message: error.message });
  }
});
/* функция для для добавления отзыва */



app.post('/api/rate-test', authenticateJWT, (req, res) => {
    const { id_test, rating } = req.body;
  const id_user = req.user.userId; // предполагается, что в JWT есть userId

  // Проверка валидности rating
  if (typeof rating !== 'number' || rating < 1 || rating > 5) {
    return res.status(400).json({ message: 'Недопустимый рейтинг' });
  }

  // Вставка или обновление оценки
  const query = `
    INSERT INTO TestRating (id_test, id_user, rating)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE rating = VALUES(rating)
  `;

  connection.execute(query, [id_test, id_user, rating], (err, result) => {
    if (err) {
      console.error('Ошибка записи оценки:', err);
      return res.status(500).json({ message: 'Ошибка при сохраненииawait fetchTests(); оценки' });
    }
    res.sendStatus(200); 
  });
});
/*
*
* Сохранение  теста на сайте 
*
*/
app.post('/api/save-test', authenticateJWT, async (req, res) => {
    const { name, theme, xml } = req.body;
    const userId = req.user.userId;

    if (!name || !theme || !xml) {
        return res.status(400).json({ 
            success: false,
            message: 'Необходимо указать название теста, тему и XML-контент' 
        });
    }

    try {
        // 1. Находим или создаем тему
        const [themeResult] = await connection.promise().execute(
            `SELECT id_theme FROM Theme WHERE name = ?`,
            [theme]
        );
        
        let themeId;
        if (themeResult.length > 0) {
            themeId = themeResult[0].id_theme;
        } else {
            const [insertResult] = await connection.promise().execute(
                `INSERT INTO Theme (name) VALUES (?)`,
                [theme]
            );
            themeId = insertResult.insertId;
        }

        // 2. Сохраняем тест (без привязки к вопросам)
        const [testResult] = await connection.promise().execute(
            `INSERT INTO Test (id_user, id_theme, name, xml, public) 
             VALUES (?, ?, ?, ?, 1)`,
            [userId, themeId, name, xml]
        );

        res.status(200).json({
            success: true,
            message: 'Тест успешно сохранен',
            testId: testResult.insertId
        });

    } catch (error) {
        console.error('Ошибка сохранения теста:', error);
        res.status(500).json({
            success: false,
            message: 'Ошибка сервера при сохранении теста'
        });
    }
});

// Получение списка категорий (остается без изменений)
app.get('/api/categories', (req, res) => {
  const query = 'SELECT name FROM Category ORDER BY name';
  connection.execute(query, (err, results) => {
    if (err) {
      console.error('Ошибка при загрузке категорий:', err.stack);
      return res.status(500).json({ message: 'Ошибка при загрузке категорий' });
    }
    res.json(results.map(row => row.name));
  });
});

// Создание новой категории
app.post('/api/categories/create', authenticateJWT, (req, res) => {
  const { name } = req.body;
  
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ 
      success: false,
      message: 'Укажите корректное название категории' 
    });
  }

  const trimmedName = name.trim();

  connection.beginTransaction(err => {
    if (err) {
      console.error('Ошибка начала транзакции:', err);
      return res.status(500).json({ message: 'Ошибка сервера' });
    }

    // 1. Проверка существования категории
    connection.execute(
      'SELECT id_category FROM Category WHERE name = ? FOR UPDATE',
      [trimmedName],
      (err, results) => {
        if (err) {
          return connection.rollback(() => {
            console.error('Ошибка проверки категории:', err);
            res.status(500).json({ message: 'Ошибка сервера' });
          });
        }

        if (results.length > 0) {
          return connection.rollback(() => {
            res.status(409).json({ 
              success: false,
              message: 'Категория с таким названием уже существует' 
            });
          });
        }

        // 2. Создание категории
        connection.execute(
          'INSERT INTO Category (name) VALUES (?)',
          [trimmedName],
          (err, result) => {
            if (err) {
              return connection.rollback(() => {
                console.error('Ошибка создания категории:', err);
                res.status(500).json({ message: 'Ошибка создания категории' });
              });
            }

            connection.commit(err => {
              if (err) {
                return connection.rollback(() => {
                  console.error('Ошибка коммита:', err);
                  res.status(500).json({ message: 'Ошибка сервера' });
                });
              }

              res.status(201).json({ 
                success: true,
                id: result.insertId,
                name: trimmedName
              });
            });
          }
        );
      }
    );
  });
});

// Создание новой темы
app.post('/api/themes/create', authenticateJWT, (req, res) => {
  const { category, theme } = req.body;
  
  if (!category || typeof category !== 'string' || category.trim().length === 0) {
    return res.status(400).json({ 
      success: false,
      message: 'Укажите корректное название категории' 
    });
  }

  if (!theme || typeof theme !== 'string' || theme.trim().length === 0) {
    return res.status(400).json({ 
      success: false,
      message: 'Укажите корректное название темы' 
    });
  }

  const trimmedCategory = category.trim();
  const trimmedTheme = theme.trim();

  connection.beginTransaction(err => {
    if (err) {
      console.error('Ошибка начала транзакции:', err);
      return res.status(500).json({ message: 'Ошибка сервера' });
    }

    // 1. Находим ID категории с блокировкой
    connection.execute(
      'SELECT id_category FROM Category WHERE name = ? FOR UPDATE',
      [trimmedCategory],
      (err, categoryResults) => {
        if (err) {
          return connection.rollback(() => {
            console.error('Ошибка поиска категории:', err);
            res.status(500).json({ message: 'Ошибка сервера' });
          });
        }

        if (categoryResults.length === 0) {
          return connection.rollback(() => {
            res.status(404).json({ 
              success: false,
              message: 'Категория не найдена' 
            });
          });
        }

        const categoryId = categoryResults[0].id_category;

        // 2. Проверяем существование темы в категории
        connection.execute(
          'SELECT id_theme FROM Theme WHERE name = ? AND id_category = ? FOR UPDATE',
          [trimmedTheme, categoryId],
          (err, themeResults) => {
            if (err) {
              return connection.rollback(() => {
                console.error('Ошибка проверки темы:', err);
                res.status(500).json({ message: 'Ошибка сервера' });
              });
            }

            if (themeResults.length > 0) {
              return connection.rollback(() => {
                res.status(409).json({ 
                  success: false,
                  message: 'Тема с таким названием уже существует в этой категории' 
                });
              });
            }

            // 3. Создаем тему
            connection.execute(
              'INSERT INTO Theme (id_category, name) VALUES (?, ?)',
              [categoryId, trimmedTheme],
              (err, result) => {
                if (err) {
                  return connection.rollback(() => {
                    console.error('Ошибка создания темы:', err);
                    res.status(500).json({ message: 'Ошибка создания темы' });
                  });
                }

                connection.commit(err => {
                  if (err) {
                    return connection.rollback(() => {
                      console.error('Ошибка коммита:', err);
                      res.status(500).json({ message: 'Ошибка сервера' });
                    });
                  }

                  res.status(201).json({ 
                    success: true,
                    id: result.insertId,
                    category: trimmedCategory,
                    theme: trimmedTheme
                  });
                });
              }
            );
          }
        );
      }
    );
  });
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

//удаление теста
app.delete('/api/my-tests/:id', authenticateJWT, (req, res) => {
  const testId = req.params.id;

    // 2. Удаляем тест
    const deleteQuery = `
      DELETE FROM Test 
      WHERE id_test = ?
    `;

    connection.execute(deleteQuery, [testId], (deleteErr, deleteResult) => {
      if (deleteErr) {
        console.error('Ошибка удаления теста:', deleteErr);
        return res.status(500).json({
          success: false,
          message: 'Ошибка при удалении теста'
        });
      }

      if (deleteResult.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: 'Тест не найден'
        });
      }

      // 3. Успешный ответ
      res.json({
        success: true,
        message: 'Тест успешно удален',
        deletedId: testId
      });
    });
});

/*
*
*
PUT запросы
*
*/
/**
 * @route PUT /api/my-tests/:id/status
 * @desc Изменение статуса теста (публичный/приватный)
 * @access Private
 */
app.put('/api/my-tests/:id/status', authenticateJWT, (req, res) => {
    const testId = req.params.id;
    const userId = req.user.userId;
    const { public } = req.body;


    // Обновляем статус теста
        const updateQuery = `
            UPDATE Test 
            SET public = ? 
            WHERE id_test = ?
        `;

        connection.execute(updateQuery, [public ? 1 : 0, testId], (updateErr, updateResult) => {
            if (updateErr) {
                console.error('Ошибка обновления статуса теста:', updateErr);
                return res.status(500).json({
                    success: false,
                    message: 'Ошибка при обновлении статуса теста'
                });
            }

            // 3. Успешный ответ
            res.json({
                success: true,
                message: 'Статус теста успешно обновлен',
                testId,
                public: public ? 1 : 0
            });
        });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту: http://localhost:${PORT}`);
});