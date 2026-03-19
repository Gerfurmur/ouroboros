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

# Стоп-слова для поиска — слишком общие
_STOPWORDS = {
    "субсидии", "субсидия", "для", "на", "и", "в", "с", "по",
    "получение", "получения", "предоставление", "предоставления",
    "мер", "меры", "господдержки", "господдержка",
}


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


def _extract_keywords(text: str) -> List[str]:
    """Извлекает значимые ключевые слова из запроса."""
    words = re.findall(r"[а-яёА-ЯЁa-zA-Z]{4,}", text.lower())
    keywords = [w for w in words if w not in _STOPWORDS]
    # Убираем дубли, сохраняем порядок
    seen = set()
    unique = []
    for w in keywords:
        if w not in seen:
            seen.add(w)
            unique.append(w)
    return unique[:6]  # не более 6 ключевых слов


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
    """Ищет субсидии по ключевым словам из запроса."""
    conditions = []
    params: List[Any] = []
    explanations = []

    # Извлекаем ключевые слова
    keywords = _extract_keywords(question)

    if keywords:
        # Каждое ключевое слово — отдельное условие (AND логика для первых 2, OR для остальных)
        kw_conds = []
        for kw in keywords:
            kw_conds.append("(sp.title ILIKE %s OR sp.description ILIKE %s)")
            params += [f"%{kw}%", f"%{kw}%"]
        # Первые 2 ключевых слова обязательны (AND), остальные — опционально
        if len(kw_conds) >= 2:
            mandatory = f"({kw_conds[0]} AND {kw_conds[1]})"
            optional = " OR ".join(kw_conds[2:]) if kw_conds[2:] else None
            conditions.append(f"({mandatory}{' OR ' + optional if optional else ''})")
        else:
            conditions.append(kw_conds[0])
        explanations.append(f"ключевые слова: {', '.join(keywords)}")
    elif question:
        # Фолбек: полная фраза
        conditions.append("(sp.title ILIKE %s OR sp.description ILIKE %s)")
        params += [f"%{question}%", f"%{question}%"]
        explanations.append(f"полная фраза: «{question}»")

    # Тип получателя
    app_type = (ctx_data.get("applicant_type") or question).lower()
    if any(w in app_type for w in ("ип", "предприним", "individual")):
        conditions.append("sp.individual_entrepreneur = true")
        explanations.append("тип: ИП")
    elif any(w in app_type for w in ("юл", "юридич", "legal")):
        conditions.append("sp.legal_entity = true")
        explanations.append("тип: ЮЛ")

    # МСП = ИП или ЮЛ
    if any(w in (question or "").lower() for w in ("мсп", "малого", "среднего", "предприниматель")):
        if "sp.individual_entrepreneur = true" not in conditions and "sp.legal_entity = true" not in conditions:
            conditions.append("(sp.individual_entrepreneur = true OR sp.legal_entity = true)")
            explanations.append("тип: МСП (ИП или ЮЛ)")

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
    sp.document_number,
    sp.short_num,
    sp.publication_date,
    (SELECT COUNT(*) FROM selections s WHERE s.subsidy_id = sp.subsidy_id AND NOT s.status_closed) AS open_selections
FROM subsidies_promote sp
LEFT JOIN regions r ON r.id = sp.region_code
{where}
ORDER BY sp.load_dttm DESC
LIMIT 20
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
            "region": r.get("region_name", ""),
            "open_selections": r.get("open_selections", 0),
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
        conditions.append("(sel.title ILIKE %s OR sp.title ILIKE %s)")
        params += [f"%{competition_code}%", f"%{competition_code}%"]
    else:
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
    LEFT(sp.description, 300) AS subsidy_description,
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
            "explanations": "Отбор не найден. Уточни ID или UUID.",
            "error": err or None,
        }

    selection = rows[0]
    sel_id = selection.get("selection_id")

    # Файлы отбора
    files = []
    if sel_id:
        sql_files = "SELECT name, file_url FROM selections_files WHERE selection_id = %s ORDER BY id"
        file_rows, _ = _run(sql_files, (sel_id,))
        sqls.append(sql_files)
        files = [{"name": r.get("name"), "url": r.get("file_url")} for r in file_rows]

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
            "max_amount_per_person": str(selection.get("max_amount_for_person", "")),
            "max_amount_per_year": str(selection.get("max_amount_for_year", "")),
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
        "explanations": f"Режим: детали отбора selection_id={sel_id}. Файлов: {len(files)}.",
        "error": err or None,
    }


# ---------------------------------------------------------------------------
# Main entry point
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
    2. get_selection — детали отбора + перечень документов (при наличии competition_code или UUID)
    3. raw_sql — прямой SELECT (при явном параметре sql=)
    """
    ctx_data: Dict = context or {}

    # Режим 3: Raw SQL
    if sql:
        err = _check_safety(sql)
        if err:
            return {"sql_queries": [sql], "results": [], "explanations": "Raw SQL", "error": err}
        if "limit" not in sql.lower():
            sql = sql.rstrip("; \n") + " LIMIT 100"
        rows, run_err = _run(sql)
        return {
            "sql_queries": [sql],
            "results": rows,
            "explanations": "Режим: raw SQL.",
            "error": run_err or None,
        }

    # Режим 2: Детали отбора
    has_code = bool(ctx_data.get("competition_code"))
    has_uuid = bool(_UUID_RE.search(question))
    has_sel_keywords = bool(_INT_RE.search(question)) and any(
        w in question.lower() for w in ("отбор", "selection_id", "заявк", "документ", "selection")
    )

    if has_code or has_uuid or has_sel_keywords:
        return _get_selection(question, ctx_data)

    # Режим 1: Поиск субсидий
    return _search_measures(question, ctx_data)


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def get_tools() -> List[ToolEntry]:
    return [
        ToolEntry("query_govsupport", {
            "name": "query_govsupport",
            "description": (
                "Запрос к БД мер господдержки РФ (субсидии, отборы, документы). "
                "Режим 1 — поиск: question='субсидии МСП на сертификацию', "
                "context={region: 'Ленинградская', applicant_type: 'ИП'}. "
                "Режим 2 — детали отбора: context={competition_code: 'UUID'} или UUID/ID в question. "
                "Режим 3 — raw: sql='SELECT ...'. "
                "Только SELECT. БД read-only."
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
                        "description": "Фильтры: competition_code (UUID/ID отбора), region, applicant_type (ИП/ЮЛ/МСП)",
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
