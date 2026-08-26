/* Движок тренажёров ЕГЭ/ОГЭ. Банк вопросов задаётся на странице в переменной BANK:
   {q: "вопрос", o: ["варианты"], a: индекс_верного, e: "пояснение"}  — выбор ответа
   {q: "вопрос", input: true, accept: ["ответ", ...], e: "пояснение"} — краткий ответ */
(function () {
  "use strict";
  var root = document.getElementById("quiz");
  if (!root || typeof BANK === "undefined") return;

  var order, idx, score;

  function shuffle(arr) {
    for (var i = arr.length - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
    return arr;
  }

  function norm(s) {
    return s.toLowerCase().replace(/ё/g, "е").replace(/[^a-zа-я0-9]/g, "");
  }

  function start() {
    order = shuffle(BANK.map(function (_, i) { return i; }));
    idx = 0; score = 0;
    render();
  }

  function render() {
    if (idx >= order.length) { return result(); }
    var qz = BANK[order[idx]];
    var card = document.createElement("div");
    card.className = "quiz-card";
    var answered = false;

    var h = '<div class="qnum">Вопрос ' + (idx + 1) + ' из ' + order.length +
            ' · верных: ' + score + '</div><div class="qtext"></div>';
    card.innerHTML = h;
    card.querySelector(".qtext").textContent = qz.q;

    var expl = document.createElement("div");
    expl.className = "expl";

    function finish(ok) {
      if (answered) return;
      answered = true;
      if (ok) score++;
      expl.className = "expl " + (ok ? "good" : "bad");
      expl.textContent = (ok ? "Верно! " : "Неверно. ") + (qz.e || "");
      expl.style.display = "block";
      var next = document.createElement("button");
      next.className = "qbtn";
      next.textContent = (idx + 1 < order.length) ? "Следующий вопрос" : "Показать результат";
      next.onclick = function () { idx++; render(); };
      card.appendChild(next);
    }

    if (qz.input) {
      var inp = document.createElement("input");
      inp.className = "short";
      inp.placeholder = "Введите ответ…";
      var btn = document.createElement("button");
      btn.className = "qbtn";
      btn.textContent = "Ответить";
      var check = function () {
        if (answered) return;
        var v = norm(inp.value);
        var ok = qz.accept.some(function (acc) { return norm(acc) === v; });
        if (!ok) expl.textContent = "";
        finish(ok);
        if (!ok) expl.textContent = "Неверно. Правильный ответ: " + qz.accept[0] + ". " + (qz.e || "");
      };
      btn.onclick = check;
      inp.addEventListener("keydown", function (ev) { if (ev.key === "Enter") check(); });
      card.appendChild(inp);
      card.appendChild(btn);
    } else {
      qz.o.forEach(function (opt, i) {
        var b = document.createElement("button");
        b.className = "opt";
        b.textContent = opt;
        b.onclick = function () {
          if (answered) return;
          if (i === qz.a) { b.classList.add("correct"); }
          else {
            b.classList.add("wrong");
            var all = card.querySelectorAll(".opt");
            all[qz.a].classList.add("correct");
          }
          finish(i === qz.a);
        };
        card.appendChild(b);
      });
    }

    card.appendChild(expl);
    root.innerHTML = "";
    root.appendChild(card);
  }

  function result() {
    var pct = Math.round(100 * score / order.length);
    var verdict;
    if (pct >= 90) verdict = "Отлично! Вы готовы к экзамену на высокий балл.";
    else if (pct >= 70) verdict = "Хороший результат — осталось закрыть отдельные пробелы.";
    else if (pct >= 50) verdict = "Неплохо, но стоит повторить конспекты и попробовать ещё раз.";
    else verdict = "Начните с конспектов по классам, затем вернитесь к тренажёру.";
    var card = document.createElement("div");
    card.className = "quiz-card quiz-result";
    card.innerHTML = '<div>Результат</div><div class="big">' + score + " из " + order.length +
      " (" + pct + '%)</div><p></p>';
    card.querySelector("p").textContent = verdict;
    var again = document.createElement("button");
    again.className = "qbtn";
    again.textContent = "Пройти ещё раз";
    again.onclick = start;
    card.appendChild(again);
    root.innerHTML = "";
    root.appendChild(card);
  }

  start();
})();
