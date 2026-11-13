# Agent Hub Core

**Ядро безопасного LLM-агента для автоматизации: Code Mode MCP + конвейер с подтверждениями.**

Один MCP-сервер, два инструмента, sandbox-исполнение, серверные проверки правды и секрет-индирекция. Боевой пример использования: [agent-hub-code-mode](https://github.com/nekto9852-bit/agent-hub-code-mode) — 100 отзывов Wildberries → LLM-классификация → CSV за 8.1 секунды, с 5 итерациями автономного ремонта.

## Состав

```
├── code-mode/
│   ├── server.js      ← MCP-сервер: search() + execute(), sandbox, confirm-гейт
│   ├── registry.json  ← реестр методов n8n/github/notion/gsheets (сигнатуры, danger-уровни)
│   ├── selftest.js    ← самотест (sandbox, гейт, verify-цикл, секрет-страж)
│   └── package.json
├── pipeline/
│   └── SOUL.md        ← конвейер агента: 6 фаз, read-only до «да», эскалация
├── docs/
│   ├── security.md    ← модель безопасности
│   └── wb-case.md     ← разбор боевого кейса
└── LICENSE (MIT)
```

## Архитектура (3 уровня контекста)

```
Постоянный контекст агента   — каталог скиллов (1 строка на скилл) + 2 инструмента
        ↓ по требованию
SKILL                        — алгоритм + ИМЕНА методов (без сигнатур)
        ↓ по требованию
Code Mode                    — search(): полные сигнатуры
                               execute(): JS-цепочка в sandbox одним вызовом
```

Новая интеграция = +методы в `registry.json` +1 строка в каталоге скиллов. Контекст агента не растёт. Инструментов всегда два.

## Ключевые механизмы надёжности

Каждый родился из реального сбоя в боевом прогоне (см. docs/wb-case.md):

| Механизм | Сбой, который его породил | Как работает |
|---|---|---|
| `setNodeCode` | LLM пересобирает JS при передаче и ломает экранирование (`"` → `"""`) | сервер читает код из файла; модель не касается тела кода |
| `verifyNodeCode` | агент заявил «код сохранён корректен» — фактически нет (hallucinated audit) | серверная сверка sha256 факта с эталоном; `match:false` = ❌ в аудите без обсуждений |
| Секрет-страж | ключ API оказался зашит в ноду workflow и утёк в export-JSON | execute ОТКАЗЫВАЕТСЯ писать сырые значения известных секретов; ноды носят ссылки `={{$env.NAME}}` |
| `exportWorkflowSafe` | в export попали email владельца и паттерны ключей | серверный санитайзер: `shared`→вырезано, ключи→REDACTED, отчёт `rawSecretsFound` |
| Confirm-гейт | — | write/delete без `confirm=true` → `confirmation_required`, код не исполняется |
| Эскалация (SOUL) | агент перебирал после исчерпания лимита итераций | на 3-й итерации ремонта — стоп, диагноз, handoff оператору |
| Hot-reload реестра | новый метод не виден до рестарта gateway | `fs.watch` на registry.json |

## Быстрый старт

```bash
cd code-mode
npm install
node selftest.js                 # статические проверки (sandbox, гейт)
# с живым окружением Hermes:
HERMES_HOME=~/.hermes node selftest.js
HERMES_HOME=~/.hermes DEMO_WF_ID=<id> DEMO_CODE_FILE=<file.js> node selftest.js
```

Подключение к агенту (пример для Hermes):

```yaml
mcp_servers:
  code-mode:
    command: node
    args: ["<путь>/code-mode/server.js", "--registry", "<путь>/code-mode/registry.json", "--env-file", "<путь>/.env"]
    timeout: 120
```

Секреты — только через `.env` (ключи реестра ссылаются по имени переменной); в `registry.json` значений нет.

## Документация

- [docs/security.md](docs/security.md) — sandbox, confirm-гейт, секрет-индирекция, аудит-лог
- [docs/wb-case.md](docs/wb-case.md) — боевой кейс: 5 итераций ремонта как источник улучшений
- [agent-hub-code-mode](https://github.com/nekto9852-bit/agent-hub-code-mode) — демо-кейс на этом ядре

## Лицензия

MIT
