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

# Стоп-слова — слишком общие для поиска
_STOPWORDS = {
    "субсидии", "субсидия", "субсидиям", "для", "на", "и", "в", "с", "по", "от",
    "получение", "получения", "предоставление", "предоставления", "предоставлению",
    "мер", "меры", "господдержки", "господдержка", "лицам", "лицо",
    "организаций", "организации", "организация",
}


def _check_safety(sql: str) -> Optional[str]:
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


def _extract_keywords(text: str) -> List[str]:
    """Значимые ключевые слова из запроса."""
    words = re.findall(r"[а-яёА-ЯЁa-zA-Z]{4,}", text.lower())
    keywords = [w for w in words if w not in _STOPWORDS]
    seen: set = set()
    unique = []
    for w in keywords:
        if w not in seen:
            seen.add(w)
            unique.append(w)
    return unique[:5]


# ---------------------------------------------------------------------------
# DB connection
# ---------------------------------------------------------------------------

def _get_conn():
    try:
        import psycopg2
        import psycopg2.extras  # noqa: F401
    except ImportError:
        raise RuntimeError("psycopg2 не установлен.")

    missing = [k for k in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASS") if not os.environ.get(k)]
    if missing:
        raise RuntimeError(f"Не заданы секреты: {', '.join(missing)}")

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
    """SELECT → (rows, error_or_empty)."""
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
        log.warning("DB error: %s", e)
        return [], f"Ошибка БД: {e}"
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Mode 1: Search (selections + subsidies_promote)
# ---------------------------------------------------------------------------

def _search_measures(question: str, ctx_data: Dict) -> Dict:
    """Ищет отборы и субсидии по ключевым словам."""
    explanations = []

    # --- Ключевые слова ---
    keywords = _extract_keywords(question)
    kw_params: List[Any] = []
    kw_conditions = []

    if keywords:
        for kw in keywords:
            kw_conditions.append(
                "(sel.title ILIKE %s OR sel.short_name ILIKE %s OR sel.list_of_req_doc ILIKE %s"
                " OR sp.title ILIKE %s OR sp.description ILIKE %s)"
            )
            kw_params += [f"%{kw}%", f"%{kw}%", f"%{kw}%", f"%{kw}%", f"%{kw}%"]
        explanations.append(f"ключевые слова: {', '.join(keywords)}")
    else:
        kw_conditions.append("1=1")

    # Требуем совпадение хотя бы ОДНОГО ключевого слова (OR)
    kw_where = " OR ".join(kw_conditions) if kw_conditions else "1=1"

    extra_conditions: List[str] = []
    extra_params: List[Any] = []

    # Тип получателя
    q_lower = question.lower()
    app_type = (ctx_data.get("applicant_type") or "").lower()
    combined = q_lower + " " + app_type

    is_ip = any(w in combined for w in ("ип ", " ип", "предприним", "individual"))
    is_ul = any(w in combined for w in ("юл ", " юл", "юридич", "legal"))
    is_msp = any(w in combined for w in ("мсп", "малого", "среднего", "малый", "средний"))

    if is_ip and not is_ul:
        extra_conditions.append("sp.individual_entrepreneur = true")
        explanations.append("тип: ИП")
    elif is_ul and not is_ip:
        extra_conditions.append("sp.legal_entity = true")
        explanations.append("тип: ЮЛ")
    elif is_msp:
        extra_conditions.append("(sp.individual_entrepreneur = true OR sp.legal_entity = true)")
        explanations.append("тип: МСП")

    # Регион
    region = ctx_data.get("region", "")
    if region:
        extra_conditions.append("r.name ILIKE %s")
        extra_params.append(f"%{region}%")
        explanations.append(f"регион: {region}")

    # Статус отбора
    if any(w in q_lower for w in ("открыт", "активн", "принима", "идёт", "текущ")):
        extra_conditions.append("sel.status_closed = false")
        explanations.append("только открытые")

    extra_where = ""
    if extra_conditions:
        extra_where = "AND " + " AND ".join(extra_conditions)

    all_params = tuple(kw_params + extra_params)

    sql = f"""
SELECT
    sel.selection_id,
    sel.title,
    sel.short_name,
    sel.status_closed,
    sel.begin_competition_date,
    sel.end_competition_date,
    sel.max_amount_for_person,
    sel.link_selection,
    sp.individual_entrepreneur,
    sp.legal_entity,
    r.name AS region_name,
    sp.title AS subsidy_title
FROM selections sel
LEFT JOIN subsidies_promote sp ON sp.subsidy_id = sel.subsidy_id
LEFT JOIN regions r ON r.id = sp.region_code
WHERE ({kw_where})
{extra_where}
ORDER BY sel.load_dttm DESC
LIMIT 20
""".strip()

    rows, err = _run(sql, all_params)

    results = []
    for r in rows:
        types = []
        if r.get("individual_entrepreneur"):
            types.append("ИП")
        if r.get("legal_entity"):
            types.append("ЮЛ")
        results.append({
            "measure_id": r["selection_id"],
            "name": r.get("title") or r.get("short_name", ""),
            "subsidy_name": r.get("subsidy_title", ""),
            "status": "закрыт" if r.get("status_closed") else "открыт",
            "applicant_types": "/".join(types) if types else "не указано",
            "region": r.get("region_name", ""),
            "end_date": str(r.get("end_competition_date", "")),
            "max_amount": str(r.get("max_amount_for_person", "")),
            "link": r.get("link_selection", ""),
            "why_matched": "; ".join(explanations) if explanations else "общий поиск",
        })

    explanation = "Режим: поиск отборов/субсидий. " + ("; ".join(explanations) or "Без фильтров.")
    out: Dict = {"sql_queries": [sql], "results": results, "explanations": explanation}
    if err:
        out["error"] = err
    return out


# ---------------------------------------------------------------------------
# Mode 2: Selection details
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_INT_RE = re.compile(r"\b(\d{4,})\b")


def _get_selection(question: str, ctx_data: Dict) -> Dict:
    competition_code = ctx_data.get("competition_code", "")

    conditions: List[str] = []
    params: List[Any] = []

    uuids = _UUID_RE.findall(competition_code) or _UUID_RE.findall(question)
    int_ids = _INT_RE.findall(question) if not uuids else []

    if uuids:
        conditions.append("(sel.id::text = %s OR sel.competition_id::text = %s)")
        params += [uuids[0], uuids[0]]
    elif int_ids:
        conditions.append("sel.selection_id = %s")
        params.append(int(int_ids[0]))
    elif competition_code:
        conditions.append("(sel.title ILIKE %s OR sp.title ILIKE %s)")
        params += [f"%{competition_code}%", f"%{competition_code}%"]
    else:
        conditions.append("(sel.title ILIKE %s OR sel.list_of_req_doc ILIKE %s)")
        params += [f"%{question}%", f"%{question}%"]

    where = "WHERE " + " AND ".join(conditions)

    sql_sel = f"""
SELECT
    sel.selection_id,
    sel.title,
    sel.short_name,
    sel.status_closed,
    sel.begin_competition_date,
    sel.end_competition_date,
    sel.selection_winner_date,
    sel.max_amount_for_person,
    sel.max_amount_for_year,
    sel.selection_cofinancing,
    sel.contacts,
    sel.email,
    sel.link_selection,
    sel.list_of_req_doc,
    sel.documents,
    sel.npa_llm,
    sp.title AS subsidy_title,
    r.name AS region_name
FROM selections sel
LEFT JOIN subsidies_promote sp ON sp.subsidy_id = sel.subsidy_id
LEFT JOIN regions r ON r.id = sp.region_code
{where}
LIMIT 5
""".strip()

    rows, err = _run(sql_sel, tuple(params))
    sqls = [sql_sel]

    if not rows:
        return {
            "sql_queries": sqls,
            "results": [],
            "explanations": "Отбор не найден.",
            "error": err or None,
        }

    sel = rows[0]
    sel_id = sel.get("selection_id")

    files: List[Dict] = []
    if sel_id:
        sql_files = "SELECT name, file_url FROM selections_files WHERE selection_id = %s ORDER BY id"
        file_rows, _ = _run(sql_files, (sel_id,))
        sqls.append(sql_files)
        files = [{"name": r.get("name"), "url": r.get("file_url")} for r in file_rows]

    result = {
        "selection": {
            "id": sel_id,
            "title": sel.get("title"),
            "subsidy_title": sel.get("subsidy_title"),
            "status": "закрыт" if sel.get("status_closed") else "открыт",
            "region": sel.get("region_name"),
            "begin_date": str(sel.get("begin_competition_date", "")),
            "end_date": str(sel.get("end_competition_date", "")),
            "winner_date": str(sel.get("selection_winner_date", "")),
            "max_amount_per_person": str(sel.get("max_amount_for_person", "")),
            "max_amount_per_year": str(sel.get("max_amount_for_year", "")),
            "cofinancing": sel.get("selection_cofinancing"),
            "contacts": sel.get("contacts"),
            "email": sel.get("email"),
            "link": sel.get("link_selection"),
        },
        "documents_text": sel.get("list_of_req_doc") or sel.get("documents") or "",
        "npa_summary": sel.get("npa_llm") or "",
        "files": files,
    }

    return {
        "sql_queries": sqls,
        "results": [result],
        "explanations": f"Детали отбора selection_id={sel_id}. Файлов: {len(files)}.",
        "error": err or None,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _query_govsupport(
    ctx: ToolContext,
    question: str = "",
    context: Optional[Dict] = None,
    sql: Optional[str] = None,
) -> Dict:
    """
    Запрос к БД мер господдержки РФ.
    Режим 1 (поиск): question + context={region, applicant_type}.
    Режим 2 (детали): context={competition_code} или UUID/numeric-ID в question.
    Режим 3 (raw): sql=SELECT...
    """
    ctx_data: Dict = context or {}

    if sql:
        err = _check_safety(sql)
        if err:
            return {"sql_queries": [sql], "results": [], "explanations": "Raw SQL", "error": err}
        if "limit" not in sql.lower():
            sql = sql.rstrip("; \n") + " LIMIT 100"
        rows, run_err = _run(sql)
        return {"sql_queries": [sql], "results": rows, "explanations": "Режим: raw SQL.", "error": run_err or None}

    has_code = bool(ctx_data.get("competition_code"))
    has_uuid = bool(_UUID_RE.search(question))
    has_sel_kw = bool(_INT_RE.search(question)) and any(
        w in question.lower() for w in ("отбор", "selection", "заявк", "документ")
    )

    if has_code or has_uuid or has_sel_kw:
        return _get_selection(question, ctx_data)

    return _search_measures(question, ctx_data)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def get_tools() -> List[ToolEntry]:
    return [
        ToolEntry("query_govsupport", {
            "name": "query_govsupport",
            "description": (
                "Запрос к БД мер господдержки РФ (субсидии, отборы, перечни документов). "
                "Режим 1 (поиск мер): question='субсидии МСП сертификация', "
                "context={region: 'Ленинградская', applicant_type: 'ИП'}. "
                "Режим 2 (детали отбора): context={competition_code: 'UUID или ID'} "
                "или UUID/числовой ID в поле question. "
                "Режим 3 (raw SQL): sql='SELECT ...' — только SELECT, БД read-only."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Текстовый запрос на русском (что ищем)",
                    },
                    "context": {
                        "type": "object",
                        "description": "Фильтры: competition_code (UUID/ID), region, applicant_type (ИП/ЮЛ/МСП)",
                    },
                    "sql": {
                        "type": "string",
                        "description": "Прямой SELECT-запрос (режим отладки)",
                    },
                },
                "required": [],
            },
        }, _query_govsupport),
    ]
