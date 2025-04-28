// server.js
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 5000;  // Порт, на котором будет запущен сервер

app.use(cors());  // Разрешаем CORS
app.use(express.json());  // Для парсинга данных в JSON

// Пример данных (можно заменить на вашу базу данных)
const sampleQuestions = [
    {
      id: 1,
      name: "Функции высшего порядка: Примеры",
      type: "multichoice",
      category: "Kotlin",
      xml: `<question type="multichoice">
        <name>
          <text>Функции высшего порядка: Примеры</text>
        </name>
        <questiontext format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">Какие методы являются функциями высшего порядка в Kotlin?</p>]]></text>
        </questiontext>
        <generalfeedback format="html">
          <text></text>
        </generalfeedback>
        <defaultgrade>1.0000000</defaultgrade>
        <penalty>0</penalty>
        <hidden>0</hidden>
        <idnumber></idnumber>
        <single>false</single>
        <shuffleanswers>true</shuffleanswers>
        <answernumbering>none</answernumbering>
        <showstandardinstruction>0</showstandardinstruction>
        <answer fraction="33.3333" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">forEach</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="33.3333" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">filter</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="33.3334" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">map</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="-50" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">size</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
      </question>`
    },
    {
      id: 2,
      name: "Основы Kotlin",
      type: "multichoice",
      category: "Kotlin",
      xml: `<question type="multichoice">
        <name>
          <text>Основы Kotlin</text>
        </name>
        <questiontext format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">Какой ключевое слово используется для объявления переменной в Kotlin?</p>]]></text>
        </questiontext>
        <generalfeedback format="html">
          <text></text>
        </generalfeedback>
        <defaultgrade>1.0000000</defaultgrade>
        <penalty>0</penalty>
        <hidden>0</hidden>
        <idnumber></idnumber>
        <single>true</single>
        <shuffleanswers>true</shuffleanswers>
        <answernumbering>none</answernumbering>
        <showstandardinstruction>0</showstandardinstruction>
        <answer fraction="100" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">val</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="0" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">var</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="0" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">let</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
      </question>`
    },
    {
      id: 3,
      name: "Null безопасность в Kotlin",
      type: "multichoice",
      category: "Kotlin",
      xml: `<question type="multichoice">
        <name>
          <text>Null безопасность в Kotlin</text>
        </name>
        <questiontext format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">Какой оператор используется для безопасного вызова метода у nullable переменной?</p>]]></text>
        </questiontext>
        <generalfeedback format="html">
          <text></text>
        </generalfeedback>
        <defaultgrade>1.0000000</defaultgrade>
        <penalty>0</penalty>
        <hidden>0</hidden>
        <idnumber></idnumber>
        <single>true</single>
        <shuffleanswers>true</shuffleanswers>
        <answernumbering>none</answernumbering>
        <showstandardinstruction>0</showstandardinstruction>
        <answer fraction="100" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">?.</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="0" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">!!</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="0" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">?:</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
      </question>`
    },
    {
      id: 4,
      name: "Основы JavaScript",
      type: "multichoice",
      category: "JavaScript",
      xml: `<question type="multichoice">
        <name>
          <text>Основы JavaScript</text>
        </name>
        <questiontext format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">Как объявить переменную в JavaScript?</p>]]></text>
        </questiontext>
        <generalfeedback format="html">
          <text></text>
        </generalfeedback>
        <defaultgrade>1.0000000</defaultgrade>
        <penalty>0</penalty>
        <hidden>0</hidden>
        <idnumber></idnumber>
        <single>false</single>
        <shuffleanswers>true</shuffleanswers>
        <answernumbering>none</answernumbering>
        <showstandardinstruction>0</showstandardinstruction>
        <answer fraction="50" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">let</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="50" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">const</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
        <answer fraction="0" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">var</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
      </question>`
    },
    {
      id: 5,
      name: "Типы данных в Python",
      type: "shortanswer",
      category: "Python",
      xml: `<question type="shortanswer">
        <name>
          <text>Типы данных в Python</text>
        </name>
        <questiontext format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">Какой тип данных в Python используется для хранения последовательности элементов?</p>]]></text>
        </questiontext>
        <generalfeedback format="html">
          <text></text>
        </generalfeedback>
        <defaultgrade>1.0000000</defaultgrade>
        <penalty>0</penalty>
        <hidden>0</hidden>
        <idnumber></idnumber>
        <answer fraction="100" format="html">
          <text><![CDATA[<p dir="ltr" style="text-align: left;">list</p>]]></text>
          <feedback format="html">
            <text></text>
          </feedback>
        </answer>
      </question>`
    },
    {
      id: 6,
      name: 'Условные операторы: when',
      type: 'truefalse',
      category: 'Kotlin',
      xml: `<question type="truefalse">
        <name>
        <text>Условные операторы: when</text>
        </name>
        <questiontext format="html">
        <text>
        <![CDATA[ <p dir="ltr" style="text-align: left;">Оператор when в Kotlin требует обязательного блока else.</p> ]]>
        </text>
          </questiontext>
          <generalfeedback format="html">
          <text/>
          </generalfeedback>
          <defaultgrade>1.0000000</defaultgrade>
          <penalty>1</penalty>
          <hidden>0</hidden>
          <idnumber/>
          <answer fraction="0" format="moodle_auto_format">
          <text>false</text>
          <feedback format="html">
          <text/>
          </feedback>
          </answer>
          <answer fraction="100" format="moodle_auto_format">
          <text>true</text>
          <feedback format="html">
          <text/>
          </feedback>
          </answer>
        </question>`
    }
];



// Обработка GET-запроса на /api/items
app.get('/api/questions', (req, res) => {
    res.json(sampleQuestions);  // Возвращаем данные клиенту
});

// Запускаем сервер
app.listen(PORT, () => {
    console.log(`Сервак работает на порту: http://localhost:${PORT}`);
});