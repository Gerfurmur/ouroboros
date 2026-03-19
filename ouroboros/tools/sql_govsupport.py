"""SQL tool for government support measures DB (read-only).

Безопасный инструмент для запросов к БД мер господдержки.
Работает с реальной схемой: subsidies_promote, selections, selections_files, regions.
Только SELECT. Параметризованные запросы.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from ouroboros.tools.registry import ToolContext, ToolEntry

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

_BLOCKED = re.compile(
    r"\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|TRUNCATE|EXEC(?:UTE)?|GRANT|REVOKE|MERGE|REPLACE|UPSERT|CALL|COPY)\b",
    re.IGNORECASE,
)
_SENSITIVE = re.compile(
    r"\b(password|passwd|token|secret|api_key|hash|credential|auth)\b",
    re.IGNORECASE,
)


def _check_safety(sql: str) -> Optional[str]:
    """Возвращает сообщение об ошибке или None."""
    clean = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    clean = re.sub(r"--.*", " ", clean).strip()
    if not clean.upper().startswith("SELECT"):
        return "⛔ Разрешены только SELECT-запросы."
    m = _BLOCKED.search(clean)
    if m:
        return f"⛔ Запрещённая операция: {m.group(0).upper()}."
    return None


def _sanitize_rows(rows: List[Dict]) -> List[Dict]:
    return [{k: "***" if _SENSITIVE.search(str(k)) else v for k, v in r.items()} for r in rows]


# ---------------------------------------------------------------------------
# DB connection
# ---------------------------------------------------------------------------

def _get_conn():
    try:
        import psycopg2
        import psycopg2.extras  # noqa: F401
    except ImportError:
        raise RuntimeError("psycopg2 не установлен. Выполни: !pip install psycopg2-binary")

    missing = [k for k in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASS") if not os.environ.get(k)]
    if missing:
        raise RuntimeError(f"Не заданы секреты Colab: {', '.join(missing)}")

    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        connect_timeout=10,
        options="-c default_transaction_read_only=on",
    )


def _run(sql: str, params: tuple = ()) -> Tuple[List[Dict], str]:
    """Выполняет SELECT. Возвращает (rows, error)."""
    import psycopg2.extras

    err = _check_safety(sql)
    if err:
        return [], err

    conn = None
    try:
        conn = _get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            rows = [dict(r) for r in cur.fetchall()]
        return _sanitize_rows(rows), ""
    except Exception as e:
        log.warning("DB error: %s | SQL: %s", e, sql)
        return [], f"Ошибка БД: {e}"
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Mode 1: Search measures/selections
# ---------------------------------------------------------------------------

def _search_measures(question: str, ctx_data: Dict) -> Dict:
    """Ищет субсидии и отборы по текстовому запросу."""
    conditions = []
    params: List[Any] = []
    explanations = []

    # Текстовый поиск
    if question:
        conditions.append("(sp.title ILIKE %s OR sp.description ILIKE %s)")
        params += [f"%{question}%", f"%{question}%"]
        explanations.append(f"поиск по тексту: «{question}»")

    # Тип получателя
    app_type = ctx_data.get("applicant_type", "").lower()
    if "ип" in app_type or "individual" in app_type or "предприним" in app_type:
        conditions.append("sp.individual_entrepreneur = true")
        explanations.append("тип: ИП")
    elif "юл" in app_type or "legal" in app_type or "юридич" in app_type:
        conditions.append("sp.legal_entity = true")
        explanations.append("тип: ЮЛ")

    # Регион
    region = ctx_data.get("region", "")
    if region:
        conditions.append("r.name ILIKE %s")
        params.append(f"%{region}%")
        explanations.append(f"регион: {region}")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    sql = f"""
SELECT
    sp.subsidy_id AS measure_id,
    sp.title AS name,
    LEFT(sp.description, 400) AS summary,
    sp.legal_entity,
    sp.individual_entrepreneur,
    r.name AS region_name,
    sp.region_code,
    sp.document_number,
    sp.short_num,
    sp.publication_date,
    (SELECT COUNT(*) FROM selections s WHERE s.subsidy_id = sp.subsidy_id AND NOT s.status_closed) AS open_selections_count
FROM subsidies_promote sp
LEFT JOIN regions r ON r.id = sp.region_code
{where}
ORDER BY sp.load_dttm DESC
LIMIT 30
""".strip()

    rows, err = _run(sql, tuple(params))

    results = []
    for r in rows:
        types = []
        if r.get("individual_entrepreneur"):
            types.append("ИП")
        if r.get("legal_entity"):
            types.append("ЮЛ")
        results.append({
            "measure_id": r["measure_id"],
            "name": r["name"],
            "summary": r.get("summary", ""),
            "applicant_types": "/".join(types) if types else "не указано",
            "region": r.get("region_name") or str(r.get("region_code", "")),
            "open_selections": r.get("open_selections_count", 0),
            "document_number": r.get("document_number"),
            "why_matched": "; ".join(explanations) if explanations else "общий поиск",
        })

    explanation = "Режим: поиск субсидий. " + ("; ".join(explanations) or "Без фильтров.")
    out: Dict = {"sql_queries": [sql], "results": results, "explanations": explanation}
    if err:
        out["error"] = err
    return out


# ---------------------------------------------------------------------------
# Mode 2: Get selection details
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_INT_RE = re.compile(r"\b(\d{4,})\b")


def _get_selection(question: str, ctx_data: Dict) -> Dict:
    """Возвращает детали отбора и список документов."""
    competition_code = ctx_data.get("competition_code", "")

    conditions = []
    params: List[Any] = []

    # Пробуем найти UUID в competition_code или в вопросе
    uuids = _UUID_RE.findall(competition_code) or _UUID_RE.findall(question)
    int_ids = _INT_RE.findall(question) if not uuids else []

    if uuids:
        uuid_val = uuids[0]
        conditions.append("(sel.id::text = %s OR sel.competition_id::text = %s)")
        params += [uuid_val, uuid_val]
    elif int_ids:
        conditions.append("sel.selection_id = %s")
        params.append(int(int_ids[0]))
    elif competition_code:
        # Пробуем как текст в title
        conditions.append("(sel.title ILIKE %s OR sp.title ILIKE %s)")
        params += [f"%{competition_code}%", f"%{competition_code}%"]
    else:
        # Поиск по тексту вопроса среди открытых отборов
        conditions.append("(sel.title ILIKE %s OR sel.list_of_req_doc ILIKE %s)")
        params += [f"%{question}%", f"%{question}%"]

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    sql_sel = f"""
SELECT
    sel.selection_id,
    sel.title,
    sel.short_name,
    sel.status_closed,
    sel.begin_competition_date,
    sel.end_competition_date,
    sel.selection_winner_date,
    sel.selection_agreement_date,
    sel.max_amount_for_person,
    sel.max_amount_for_year,
    sel.selection_cofinancing,
    sel.contacts,
    sel.post_address,
    sel.email,
    sel.link_selection,
    sel.list_of_req_doc,
    sel.documents,
    sel.npa_llm,
    sp.title AS subsidy_title,
    sp.description AS subsidy_description,
    r.name AS region_name
FROM selections sel
LEFT JOIN subsidies_promote sp ON sp.subsidy_id = sel.subsidy_id
LEFT JOIN regions r ON r.id = sp.region_code
{where}
LIMIT 5
""".strip()

    rows, err = _run(sql_sel, tuple(params))
    sqls = [sql_sel]

    if not rows and not err:
        return {
            "sql_queries": sqls,
            "results": [],
            "explanations": "Отбор не найден. Попробуй указать точный ID или UUID.",
            "error": None,
        }

    selection = rows[0] if rows else {}
    sel_id = selection.get("selection_id")

    # Файлы отбора
    files = []
    if sel_id:
        sql_files = "SELECT name, file_url FROM selections_files WHERE selection_id = %s ORDER BY id"
        file_rows, _ = _run(sql_files, (sel_id,))
        sqls.append(sql_files)
        files = [{"name": r.get("name"), "url": r.get("file_url")} for r in file_rows]

    # Форматируем результат
    result = {
        "selection": {
            "id": sel_id,
            "title": selection.get("title"),
            "subsidy_title": selection.get("subsidy_title"),
            "status": "закрыт" if selection.get("status_closed") else "открыт",
            "region": selection.get("region_name"),
            "begin_date": str(selection.get("begin_competition_date", "")),
            "end_date": str(selection.get("end_competition_date", "")),
            "winner_date": str(selection.get("selection_winner_date", "")),
            "max_amount_per_person": selection.get("max_amount_for_person"),
            "max_amount_per_year": selection.get("max_amount_for_year"),
            "cofinancing": selection.get("selection_cofinancing"),
            "contacts": selection.get("contacts"),
            "email": selection.get("email"),
            "link": selection.get("link_selection"),
        },
        "documents_text": selection.get("list_of_req_doc") or selection.get("documents") or "",
        "npa_summary": selection.get("npa_llm") or "",
        "files": files,
    }

    return {
        "sql_queries": sqls,
        "results": [result],
        "explanations": f"Режим: детали отбора selection_id={sel_id}. Найдено файлов: {len(files)}.",
        "error": err or None,
    }


# ---------------------------------------------------------------------------
# Main tool function
# ---------------------------------------------------------------------------

def _query_govsupport(
    ctx: ToolContext,
    question: str = "",
    context: Optional[Dict] = None,
    sql: Optional[str] = None,
) -> Dict:
    """
    Запрос к БД мер господдержки.

    Режимы:
    1. search_measures — поиск субсидий по тексту/региону/типу получателя
    2. get_selection — детали отбора + перечень документов
    3. raw_sql — прямой SELECT (только при явном параметре sql=)
    """
    ctx_data: Dict = context or {}

    # Режим 3: Raw SQL
    if sql:
        err = _check_safety(sql)
        if err:
            return {"sql_queries": [sql], "results": [], "explanations": "Raw SQL", "error": err}
        # Добавляем LIMIT если нет
        if "limit" not in sql.lower():
            sql = sql.rstrip("; \n") + " LIMIT 100"
        rows, run_err = _run(sql)
        return {
            "sql_queries": [sql],
            "results": rows,
            "explanations": "Режим: raw SQL.",
            "error": run_err or None,
        }

    # Режим 2: Получить детали отбора
    has_code = bool(ctx_data.get("competition_code"))
    has_uuid = bool(_UUID_RE.search(question))
    has_sel_id = bool(_INT_RE.search(question)) and any(
        w in question.lower() for w in ("отбор", "selection", "selection_id", "заявк", "документ")
    )

    if has_code or has_uuid or has_sel_id:
        return _get_selection(question, ctx_data)

    # Режим 1: Поиск мер/субсидий
    return _search_measures(question, ctx_data)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def get_tools() -> List[ToolEntry]:
    return [
        ToolEntry(
            name="query_govsupport",
            description=(
                "Запрос к БД мер господдержки. "
                "Режим 1 (поиск): передай question с описанием нужной субсидии, "
                "context={region, applicant_type} для фильтрации. "
                "Режим 2 (детали отбора): передай context={competition_code: UUID/ID} или UUID в question. "
                "Режим 3 (raw SQL): передай sql=SELECT... "
                "Только SELECT. БД read-only."
            ),
            fn=_query_govsupport,
            params={
                "question": {"type": "string", "description": "Текстовый запрос пользователя на русском"},
                "context": {
                    "type": "object",
                    "description": "Фильтры: {competition_code, region, applicant_type}",
                    "required": False,
                },
                "sql": {
                    "type": "string",
                    "description": "Прямой SELECT-запрос (только для отладки)",
                    "required": False,
                },
            },
        )
    ]
