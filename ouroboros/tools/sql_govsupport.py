"""SQL tool for government support measures DB (read-only).

Безопасный инструмент для запросов к БД мер господдержки.
Только SELECT. Параметризованные запросы. Автозагрузка схемы БД.
"""

from __future__ import annotations

import json
import logging
import os
import re
import pathlib
from typing import Any, Dict, List, Optional, Tuple

from ouroboros.tools.registry import ToolContext, ToolEntry

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level schema cache (загружается один раз за процесс)
# ---------------------------------------------------------------------------

_schema_cache: Optional[Dict[str, List[str]]] = None  # {table_name: [col1, col2, ...]}
_schema_raw: Optional[str] = None
_schema_loaded: bool = False

_SCHEMA_PATHS = [
    "/content/drive/MyDrive/Ouroboros/memory/BD_schema_for_skill.md",
    "/content/drive/MyDrive/Ouroboros/memory/BD_schema_for_skill.txt",
    "/content/ouroboros_repo/skills/BD_schema_for_skill.md",
    "/content/ouroboros_repo/skills/BD_schema_for_skill.txt",
]

# Fallback schema если файл не найден
_FALLBACK_SCHEMA = {
    "measures": ["id", "name", "description", "region", "applicant_type",
                 "subsidy_amount", "goal", "competition_code", "deadline", "status"],
    "documents": ["id", "measure_id", "name", "required", "source", "notes", "description"],
    "conditions": ["id", "measure_id", "condition_text", "condition_type"],
    "selections": ["id", "measure_id", "competition_code", "start_date", "end_date",
                   "status", "max_applications", "selection_type"],
}

# Таблицы мер/отборов и документов (для определения режима)
_MEASURE_TABLE_KEYWORDS = {"measure", "мер", "subsid", "субсид", "отбор", "selection", "grant", "грант"}
_DOCUMENT_TABLE_KEYWORDS = {"document", "документ", "doc", "file", "attachment", "файл"}

# ---------------------------------------------------------------------------
# Security: блокировка опасных операций
# ---------------------------------------------------------------------------

_BLOCKED_PATTERNS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|TRUNCATE|EXEC(?:UTE)?|GRANT|REVOKE|MERGE|REPLACE|UPSERT|CALL|COPY)\b",
    re.IGNORECASE,
)

_SENSITIVE_FIELD_PATTERNS = re.compile(
    r"\b(password|passwd|token|secret|api_key|hash|credential|auth)\b",
    re.IGNORECASE,
)


def _check_sql_safety(sql: str) -> Optional[str]:
    """Проверяет SQL на безопасность. Возвращает сообщение об ошибке или None."""
    normalized = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)  # убрать комментарии
    normalized = re.sub(r"--.*", " ", normalized)  # однострочные комментарии
    normalized = normalized.strip()

    if not normalized.upper().lstrip().startswith("SELECT"):
        return "⛔ Разрешены только SELECT-запросы. Запрос должен начинаться с SELECT."

    match = _BLOCKED_PATTERNS.search(normalized)
    if match:
        return f"⛔ Запрещённая операция: {match.group(0).upper()}. Только SELECT."

    return None


def _sanitize_results(rows: List[Dict]) -> List[Dict]:
    """Убирает чувствительные поля из результатов."""
    sanitized = []
    for row in rows:
        clean = {}
        for k, v in row.items():
            if _SENSITIVE_FIELD_PATTERNS.search(str(k)):
                clean[k] = "***"
            else:
                clean[k] = v
        sanitized.append(clean)
    return sanitized


# ---------------------------------------------------------------------------
# Загрузка схемы
# ---------------------------------------------------------------------------

def _load_schema() -> Tuple[Dict[str, List[str]], str]:
    """Загружает и парсит схему БД из файла. Возвращает (schema_dict, raw_text)."""
    raw = None
    for path in _SCHEMA_PATHS:
        p = pathlib.Path(path)
        if p.exists():
            try:
                raw = p.read_text(encoding="utf-8")
                log.info("Загружена схема БД из %s", path)
                break
            except Exception as e:
                log.warning("Не удалось прочитать схему из %s: %s", path, e)

    if not raw:
        log.warning("Файл схемы BD_schema_for_skill не найден. Используется fallback-схема.")
        return _FALLBACK_SCHEMA.copy(), ""

    schema: Dict[str, List[str]] = {}

    # Паттерн 1: CREATE TABLE table_name (...)
    create_table_re = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\']?(\w+)[`\"\']?\s*\(([^;]+?)(?:\);|\)$)",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    for m in create_table_re.finditer(raw):
        table = m.group(1).lower()
        body = m.group(2)
        cols = []
        for line in body.splitlines():
            line = line.strip().rstrip(",")
            # строка определения колонки: первое слово — имя колонки
            if line and not line.upper().startswith(("PRIMARY", "FOREIGN", "UNIQUE", "INDEX", "KEY", "CONSTRAINT", "CHECK")):
                col_match = re.match(r'^[`"\']?(\w+)[`"\']?\s+\w', line)
                if col_match:
                    cols.append(col_match.group(1).lower())
        if cols:
            schema[table] = cols

    # Паттерн 2: Markdown ## table_name или ### table_name
    if not schema:
        md_table_re = re.compile(r"^#{1,4}\s+[`]?(\w+)[`]?\s*$", re.MULTILINE)
        md_col_re = re.compile(r"^\|?\s*[`]?(\w+)[`]?\s*\|", re.MULTILINE)
        current_table = None
        for line in raw.splitlines():
            header_match = md_table_re.match(line.strip())
            if header_match:
                current_table = header_match.group(1).lower()
                schema[current_table] = []
            elif current_table and "|" in line:
                col_match = md_col_re.match(line)
                if col_match:
                    col = col_match.group(1).lower()
                    if col not in ("id", "name") or col not in schema.get(current_table, []):
                        schema[current_table].append(col)

    # Паттерн 3: "table_name: col1, col2, col3" или "table_name — col1, col2"
    if not schema:
        inline_re = re.compile(r"^(\w+)\s*[:\—\-]+\s*(.+)$", re.MULTILINE)
        for m in inline_re.finditer(raw):
            table = m.group(1).lower()
            cols_raw = m.group(2)
            cols = [c.strip().lower() for c in re.split(r"[,;]", cols_raw) if c.strip() and c.strip().isidentifier()]
            if len(cols) >= 2:
                schema[table] = cols

    if not schema:
        log.warning("Не удалось распарсить схему. Используется fallback.")
        return _FALLBACK_SCHEMA.copy(), raw

    return schema, raw


def _get_schema() -> Tuple[Dict[str, List[str]], bool]:
    """Возвращает схему (с кешированием). Второй элемент — был ли файл найден."""
    global _schema_cache, _schema_raw, _schema_loaded
    if not _schema_loaded:
        _schema_cache, _schema_raw = _load_schema()
        _schema_loaded = True
    schema_from_file = bool(_schema_raw)
    return _schema_cache, schema_from_file


def _find_tables_by_role(schema: Dict[str, List[str]]) -> Tuple[List[str], List[str]]:
    """Определяет таблицы мер/отборов и таблицы документов по именам."""
    measure_tables = []
    document_tables = []
    for table in schema:
        tl = table.lower()
        if any(kw in tl for kw in _MEASURE_TABLE_KEYWORDS):
            measure_tables.append(table)
        elif any(kw in tl for kw in _DOCUMENT_TABLE_KEYWORDS):
            document_tables.append(table)

    # Если не нашли — берём первые таблицы из fallback
    if not measure_tables:
        measure_tables = ["measures"]
    if not document_tables:
        document_tables = ["documents"]

    return measure_tables, document_tables


# ---------------------------------------------------------------------------
# Подключение к БД
# ---------------------------------------------------------------------------

def _get_connection():
    """Создаёт новое соединение с БД (create/close per call)."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        raise RuntimeError(
            "psycopg2 не установлен. Выполни: !pip install psycopg2-binary"
        )

    host = os.environ.get("DB_HOST", "")
    port = os.environ.get("DB_PORT", "5432")
    dbname = os.environ.get("DB_NAME", "")
    user = os.environ.get("DB_USER", "")
    password = os.environ.get("DB_PASS", "")

    missing = [k for k, v in [("DB_HOST", host), ("DB_NAME", dbname), ("DB_USER", user), ("DB_PASS", password)] if not v]
    if missing:
        raise RuntimeError(f"Не заданы секреты Colab: {', '.join(missing)}")

    conn = psycopg2.connect(
        host=host, port=int(port), dbname=dbname,
        user=user, password=password,
        connect_timeout=10,
        options="-c default_transaction_read_only=on",  # read-only на уровне сессии
    )
    return conn


def _execute_query(sql: str, params: tuple = ()) -> Tuple[List[Dict], str]:
    """Выполняет SELECT-запрос. Возвращает (rows, error_or_empty)."""
    import psycopg2.extras

    safety_err = _check_sql_safety(sql)
    if safety_err:
        return [], safety_err

    conn = None
    try:
        conn = _get_connection()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            rows = [dict(r) for r in cur.fetchall()]
        return _sanitize_results(rows), ""
    except Exception as e:
        log.warning("Ошибка выполнения запроса: %s | SQL: %s", e, sql)
        return [], f"Ошибка БД: {str(e)}"
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Построение SQL по режимам
# ---------------------------------------------------------------------------

def _build_search_measures_sql(
    question: str,
    schema: Dict[str, List[str]],
    context: Dict[str, str],
    limit: int = 50,
) -> Tuple[str, tuple, str]:
    """
    Строит SQL для поиска мер/отборов.
    Возвращает (sql, params, explanation).
    """
    measure_tables, _ = _find_tables_by_role(schema)
    table = measure_tables[0]
    cols = schema.get(table, ["id", "name", "description", "region", "applicant_type"])

    # Определяем доступные колонки
    has = lambda c: any(c in col for col in cols)

    select_parts = []
    # ID
    id_col = next((c for c in cols if c in ("id", "measure_id", "код", "code")), cols[0] if cols else "id")
    select_parts.append(id_col)
    # Название
    name_col = next((c for c in cols if "name" in c or "наимен" in c or "title" in c or "название" in c), None)
    if name_col:
        select_parts.append(name_col)
    # Описание
    desc_col = next((c for c in cols if "desc" in c or "описан" in c or "summary" in c or "цель" in c or "goal" in c), None)
    if desc_col:
        select_parts.append(desc_col)
    # Регион
    region_col = next((c for c in cols if "region" in c or "регион" in c or "субъект" in c), None)
    if region_col:
        select_parts.append(region_col)
    # Тип получателя
    type_col = next((c for c in cols if "type" in c or "тип" in c or "получател" in c or "applicant" in c), None)
    if type_col:
        select_parts.append(type_col)

    # Дедупликация с сохранением порядка
    seen = set()
    final_cols = []
    for c in select_parts:
        if c not in seen:
            seen.add(c)
            final_cols.append(c)
    if not final_cols:
        final_cols = ["*"]

    conditions = []
    params = []
    explanations = []

    # Полнотекстовый поиск по вопросу
    if question:
        search_cols = [c for c in [name_col, desc_col] if c]
        if search_cols:
            text_conditions = [f"{c} ILIKE %s" for c in search_cols]
            conditions.append("(" + " OR ".join(text_conditions) + ")")
            for _ in search_cols:
                params.append(f"%{question}%")
            explanations.append(f"Текстовый поиск по: {', '.join(search_cols)}")

    # Фильтр по региону
    region = context.get("region", "")
    if region and region_col:
        conditions.append(f"{region_col} ILIKE %s")
        params.append(f"%{region}%")
        explanations.append(f"Фильтр по региону: {region}")

    # Фильтр по типу получателя
    applicant_type = context.get("applicant_type", "")
    if applicant_type and type_col:
        conditions.append(f"({type_col} ILIKE %s OR {type_col} IS NULL)")
        params.append(f"%{applicant_type}%")
        explanations.append(f"Фильтр по типу получателя: {applicant_type}")

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    cols_str = ", ".join(final_cols)
    sql = f"SELECT {cols_str} FROM {table} {where_clause} LIMIT {min(limit, 200)}"

    explanation = "Режим: поиск мер/отборов. " + ("; ".join(explanations) if explanations else "Без фильтров, возвращены первые записи.")

    return sql, tuple(params), explanation


def _build_get_documents_sql(
    question: str,
    schema: Dict[str, List[str]],
    context: Dict[str, str],
    limit: int = 50,
) -> Tuple[str, tuple, str]:
    """
    Строит SQL для получения перечня документов по мере/отбору.
    """
    _, document_tables = _find_tables_by_role(schema)
    measure_tables, _ = _find_tables_by_role(schema)

    doc_table = document_tables[0]
    measure_table = measure_tables[0]

    doc_cols = schema.get(doc_table, ["id", "measure_id", "name", "required", "source", "notes"])
    measure_cols = schema.get(measure_table, ["id", "name", "competition_code"])

    # Находим колонку связи
    fk_col = next((c for c in doc_cols if "measure" in c or "мер" in c or "_id" in c and c != "id"), "measure_id")
    measure_id_col = next((c for c in measure_cols if c == "id" or "code" in c or "шифр" in c), "id")

    competition_code = context.get("competition_code", "")

    # Ищем competition_code в вопросе если не задан явно
    if not competition_code and question:
        code_match = re.search(r"\b([А-ЯA-Z0-9]{2,}-\d{4,}|\d{4,}[/-][А-ЯA-Z]{1,3})\b", question)
        if code_match:
            competition_code = code_match.group(1)

    params = []
    explanation = "Режим: перечень документов для отбора. "

    if competition_code:
        # Есть код отбора — джойним и фильтруем
        comp_col = next((c for c in measure_cols if "code" in c or "шифр" in c or "competition" in c), measure_id_col)
        sql = (
            f"SELECT d.* FROM {doc_table} d "
            f"JOIN {measure_table} m ON d.{fk_col} = m.{measure_id_col} "
            f"WHERE m.{comp_col} = %s "
            f"LIMIT {min(limit, 200)}"
        )
        params.append(competition_code)
        explanation += f"Шифр/код отбора: {competition_code}"
    else:
        # Нет кода — возвращаем все документы с текстовым поиском
        name_col = next((c for c in doc_cols if "name" in c or "наимен" in c), None)
        if name_col and question:
            sql = (
                f"SELECT * FROM {doc_table} "
                f"WHERE {name_col} ILIKE %s "
                f"LIMIT {min(limit, 200)}"
            )
            params.append(f"%{question}%")
            explanation += f"Текстовый поиск документов по: {question}"
        else:
            sql = f"SELECT * FROM {doc_table} LIMIT {min(limit, 200)}"
            explanation += "Нет конкретного шифра отбора. Возвращены первые документы."

    return sql, tuple(params), explanation


def _format_measure_results(rows: List[Dict], schema: Dict[str, List[str]]) -> List[Dict]:
    """Форматирует строки мер в стандартный формат [{measure_id, name, summary, why_matched}]."""
    measure_tables, _ = _find_tables_by_role(schema)
    table = measure_tables[0]
    cols = schema.get(table, [])

    id_col = next((c for c in cols if c in ("id", "measure_id")), None)
    name_col = next((c for c in cols if "name" in c or "наимен" in c or "title" in c), None)
    desc_col = next((c for c in cols if "desc" in c or "goal" in c or "цель" in c or "summary" in c), None)

    result = []
    for row in rows:
        # Пытаемся найти значения по известным именам колонок или по первым ключам
        keys = list(row.keys())
        measure_id = row.get(id_col) if id_col else (row.get(keys[0]) if keys else None)
        name = row.get(name_col) if name_col else (row.get(keys[1]) if len(keys) > 1 else None)
        summary = row.get(desc_col) if desc_col else None

        result.append({
            "measure_id": str(measure_id) if measure_id is not None else "—",
            "name": str(name) if name is not None else "—",
            "summary": str(summary)[:300] if summary else "—",
            "why_matched": "Соответствует условиям поиска",
            "_raw": row,  # полные данные для прозрачности
        })
    return result


def _format_document_results(rows: List[Dict]) -> List[Dict]:
    """Форматирует строки документов в стандартный формат [{name, required, source, notes}]."""
    result = []
    for row in rows:
        keys = list(row.keys())
        name_col = next((k for k in keys if "name" in k or "наимен" in k or "title" in k), None)
        req_col = next((k for k in keys if "required" in k or "обязат" in k or "необход" in k), None)
        src_col = next((k for k in keys if "source" in k or "источник" in k or "откуда" in k), None)
        notes_col = next((k for k in keys if "note" in k or "примеч" in k or "коммент" in k or "desc" in k), None)

        result.append({
            "name": str(row.get(name_col, "—")) if name_col else (str(row.get(keys[0], "—")) if keys else "—"),
            "required": bool(row.get(req_col)) if req_col else True,
            "source": str(row.get(src_col, "не указан")) if src_col else "не указан",
            "notes": str(row.get(notes_col, ""))[:200] if notes_col else "",
            "_raw": row,
        })
    return result


# ---------------------------------------------------------------------------
# Основная функция инструмента
# ---------------------------------------------------------------------------

def _query_govsupport(
    ctx: ToolContext,
    question: str,
    context: Optional[Dict] = None,
    mode: str = "search_measures",
    raw_sql: Optional[str] = None,
) -> str:
    """Основная точка входа SQL-инструмента мер господдержки."""
    if context is None:
        context = {}

    schema, schema_from_file = _get_schema()

    output: Dict[str, Any] = {
        "sql_queries": [],
        "results": [],
        "explanations": "",
        "schema_loaded": schema_from_file,
        "error": None,
    }

    if not schema_from_file:
        output["explanations"] = "⚠️ Файл BD_schema_for_skill не найден. Используется fallback-схема (таблицы могут отличаться от реальных). Поместите файл схемы в /content/drive/MyDrive/Ouroboros/memory/BD_schema_for_skill.md"

    try:
        if mode == "raw_sql":
            if not raw_sql:
                output["error"] = "Режим raw_sql требует параметр raw_sql с текстом запроса."
                return json.dumps(output, ensure_ascii=False, indent=2, default=str)

            safety_err = _check_sql_safety(raw_sql)
            if safety_err:
                output["error"] = safety_err
                return json.dumps(output, ensure_ascii=False, indent=2, default=str)

            output["sql_queries"].append(raw_sql)
            rows, err = _execute_query(raw_sql)
            if err:
                output["error"] = err
            else:
                output["results"] = rows
                output["explanations"] = f"Прямой SQL-запрос выполнен. Получено {len(rows)} записей."

        elif mode == "get_documents":
            sql, params, explanation = _build_get_documents_sql(question, schema, context)
            output["sql_queries"].append(sql)
            output["explanations"] = explanation

            rows, err = _execute_query(sql, params)
            if err:
                output["error"] = err
            else:
                output["results"] = _format_document_results(rows)

        else:  # search_measures (default)
            sql, params, explanation = _build_search_measures_sql(question, schema, context)
            output["sql_queries"].append(sql)
            output["explanations"] = explanation

            rows, err = _execute_query(sql, params)
            if err:
                output["error"] = err
            else:
                output["results"] = _format_measure_results(rows, schema)

    except RuntimeError as e:
        # psycopg2 не установлен или нет секретов
        output["error"] = str(e)
    except Exception as e:
        log.exception("Неожиданная ошибка в query_govsupport")
        output["error"] = f"Внутренняя ошибка: {type(e).__name__}: {e}"

    return json.dumps(output, ensure_ascii=False, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def get_tools() -> List[ToolEntry]:
    return [
        ToolEntry("query_govsupport", {
            "name": "query_govsupport",
            "description": (
                "Запрос к БД мер господдержки (субсидии, отборы, документы). Read-only. "
                "Режимы: search_measures — найти подходящие меры/отборы по тексту/параметрам; "
                "get_documents — получить перечень документов для конкретного отбора; "
                "raw_sql — выполнить произвольный SELECT-запрос."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Вопрос на естественном языке или текст для поиска",
                    },
                    "context": {
                        "type": "object",
                        "description": "Дополнительные фильтры",
                        "properties": {
                            "competition_code": {"type": "string", "description": "Шифр/код отбора"},
                            "region": {"type": "string", "description": "Регион (напр. 'Ленинградская область')"},
                            "applicant_type": {"type": "string", "description": "Тип получателя: ИП, ЮЛ, и т.п."},
                        },
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["search_measures", "get_documents", "raw_sql"],
                        "description": "Режим работы. По умолчанию: search_measures",
                    },
                    "raw_sql": {
                        "type": "string",
                        "description": "SQL-запрос (только для mode=raw_sql). Только SELECT.",
                    },
                },
                "required": ["question"],
            },
        }, _query_govsupport),
    ]
