"""
Engineering Hardening, Feature Completeness, Security & Bilingual Verification Tests
for Automated GraphRAG (Phases 1-4).
"""
from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.auth import (
    get_session_signing_secret,
    reset_rate_limiter_state,
    revoke_all_user_sessions,
)
from backend.config import AppSettings, settings
from backend.database import get_db_connection, init_db
from backend.main import (
    app,
    invalidate_runtime_config_cache,
    load_persisted_runtime_config,
)


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Configure an isolated temporary SQLite database for each test."""
    db_file = str(tmp_path / "hardening_test.db")
    monkeypatch.setattr(settings, "sqlite_db_path", db_file)
    invalidate_runtime_config_cache()
    reset_rate_limiter_state(db_file)
    init_db(db_file)
    return db_file


@pytest.fixture()
def client(isolated_db: str) -> TestClient:
    """Return a FastAPI TestClient bound to the isolated database."""
    return TestClient(app)


# ============================================================================
# 1. DOCUMENT ACL: PRIVATE VISIBILITY, ALLOWED_USER_IDS PRESERVATION & TENANT CHECK
# ============================================================================

def test_document_acl_private_and_user_allowlist_preservation(client: TestClient) -> None:
    admin_headers = {"X-API-Key": "dev-admin-key"}
    analyst_headers = {"X-API-Key": "dev-analyst-key"}
    viewer_headers = {"X-API-Key": "dev-viewer-key"}

    doc_body = "# Private Risk Briefing\n\nAurelia Financial Cloud operates Helios Payment Gateway (HPG)."
    r_up = client.post(
        "/api/documents/upload",
        headers=admin_headers,
        files={"file": ("private_briefing.md", doc_body.encode("utf-8"), "text/markdown")},
        data={"visibility": "restricted", "allowed_roles": "admin"},
    )
    assert r_up.status_code == 200
    doc_id = r_up.json()["doc_id"]

    # Grant explicit per-user access to user-viewer while restricted
    r_acl1 = client.put(
        f"/api/documents/{doc_id}/acl",
        headers=admin_headers,
        json={
            "visibility": "restricted",
            "allowed_roles": ["admin"],
            "allowed_user_ids": ["user-viewer"],
        },
    )
    assert r_acl1.status_code == 200
    assert r_acl1.json()["allowed_user_ids"] == ["user-viewer"]

    # Switch to visibility="private" WITHOUT sending allowed_user_ids -> must preserve ["user-viewer"]!
    r_acl2 = client.put(
        f"/api/documents/{doc_id}/acl",
        headers=admin_headers,
        json={
            "visibility": "private",
            "allowed_roles": ["admin"],
        },
    )
    assert r_acl2.status_code == 200
    assert r_acl2.json()["visibility"] == "private"
    assert r_acl2.json()["allowed_user_ids"] == ["user-viewer"]

    # Viewer (explicitly in allowed_user_ids) retains chunk read access; non-owner analyst gets 403
    assert client.get(f"/api/documents/{doc_id}/chunks", headers=viewer_headers).status_code == 200
    assert client.get(f"/api/documents/{doc_id}/chunks", headers=analyst_headers).status_code == 403

    # Cross-tenant user ID (user-beta in tenant-beta) must be rejected with HTTP 422
    r_bad_user = client.put(
        f"/api/documents/{doc_id}/acl",
        headers=admin_headers,
        json={
            "visibility": "private",
            "allowed_roles": ["admin"],
            "allowed_user_ids": ["user-beta"],
        },
    )
    assert r_bad_user.status_code == 422


# ============================================================================
# 2. PRODUCTION HARDENING: FAIL-CLOSED SECRET, QUICK-FILL FLAG & API KEYS
# ============================================================================

def test_production_fail_closed_secret_client_config_and_api_keys(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)

    # Empty or short SESSION_SECRET in production must fail closed
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        AppSettings(APP_ENV="production", SESSION_SECRET="").validate_production_security()

    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        AppSettings(APP_ENV="production", SESSION_SECRET="too-short").validate_production_security()

    # Valid production settings pass validation
    prod_ok = AppSettings(
        APP_ENV="production",
        SESSION_SECRET="x" * 48,
        ALLOWED_ORIGINS="https://graphrag.example.com",
    )
    prod_ok.validate_production_security()

    # get_session_signing_secret fails closed when app_env is production without valid secret
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "session_secret", "")
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        get_session_signing_secret()

    # Dev API keys (`dev-*`) are disabled in production mode
    assert "dev-admin-key" not in settings.parse_api_keys()

    # Client auth config reflects quick_fill_enabled=False in production, True in development
    r_prod_cfg = client.get("/api/auth/client-config")
    assert r_prod_cfg.status_code == 200
    assert r_prod_cfg.json()["quick_fill_enabled"] is False

    monkeypatch.setattr(settings, "app_env", "development")
    r_dev_cfg = client.get("/api/auth/client-config")
    assert r_dev_cfg.status_code == 200
    assert r_dev_cfg.json()["quick_fill_enabled"] is True


# ============================================================================
# 3. CORS STRICT ALLOWLIST ENFORCEMENT
# ============================================================================

def test_cors_allowlist_enforcement(client: TestClient) -> None:
    with pytest.raises(ValueError, match="Wildcard"):
        AppSettings(ALLOWED_ORIGINS="*").parse_allowed_origins()

    parsed = AppSettings(
        ALLOWED_ORIGINS="https://app.example.com/, http://localhost:8765"
    ).parse_allowed_origins()
    assert parsed == ["https://app.example.com", "http://localhost:8765"]

    # Configured dev origin is echoed back on preflight
    r_ok = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:8765",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert r_ok.status_code == 200
    assert r_ok.headers.get("access-control-allow-origin") == "http://localhost:8765"

    # Untrusted external origin receives NO Access-Control-Allow-Origin header
    r_evil = client.options(
        "/api/health",
        headers={
            "Origin": "https://evil-attacker.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in r_evil.headers


# ============================================================================
# 4. DB-BACKED RATE LIMITER & CROSS-WORKER TOKEN_VERSION REVOCATION
# ============================================================================

def test_db_rate_limiter_and_token_version_revocation(
    client: TestClient, isolated_db: str
) -> None:
    # Trigger 5 failed logins -> persisted in login_rate_limits
    for _ in range(5):
        r_fail = client.post(
            "/api/auth/login",
            json={"identifier": "viewer", "password": "IncorrectPassword!"},
        )
        assert r_fail.status_code == 401

    with get_db_connection(isolated_db) as conn:
        cnt = conn.execute("SELECT COUNT(*) AS c FROM login_rate_limits").fetchone()["c"]
        assert int(cnt) >= 5

    r_throttled = client.post(
        "/api/auth/login",
        json={"identifier": "viewer", "password": "IncorrectPassword!"},
    )
    assert r_throttled.status_code == 429

    # Clear IP rate-limit window so analyst can sign in cleanly for token_version checks
    reset_rate_limiter_state(isolated_db)

    # Analyst signs in to obtain signed v1. token
    r_login = client.post(
        "/api/auth/login",
        json={"identifier": "analyst", "password": settings.initial_analyst_password},
    )
    assert r_login.status_code == 200
    token_v1 = r_login.json()["session_token"]
    assert token_v1.startswith("v1.")
    client.cookies.clear()

    # Simulate another container where user_sessions table does not yet have token_v1
    with get_db_connection(isolated_db) as conn:
        conn.execute("DELETE FROM user_sessions WHERE user_id = 'user-analyst'")

    assert (
        client.get("/api/auth/whoami", headers={"Authorization": f"Bearer {token_v1}"}).status_code
        == 200
    )

    # Admin revokes all analyst sessions -> increments token_version in users table
    revoke_all_user_sessions("tenant-alpha", "user-analyst", db_path=isolated_db)

    # Even if user_sessions row didn't exist in another worker, token_version mismatch blocks token_v1!
    with get_db_connection(isolated_db) as conn:
        conn.execute("DELETE FROM user_sessions WHERE user_id = 'user-analyst'")

    r_revoked = client.get(
        "/api/auth/whoami",
        headers={"Authorization": f"Bearer {token_v1}"},
    )
    assert r_revoked.status_code == 401


# ============================================================================
# 5. PERSISTENT RUNTIME CONFIG & SSRF GUARD
# ============================================================================

def test_runtime_config_persistence_and_ssrf_guard(
    client: TestClient, isolated_db: str
) -> None:
    admin_headers = {"X-API-Key": "dev-admin-key"}
    orig_top_k = settings.default_top_k_chunks

    try:
        r_upd = client.put(
            "/api/config",
            headers=admin_headers,
            json={"default_top_k_chunks": 11},
        )
        assert r_upd.status_code == 200
        assert r_upd.json()["config"]["default_top_k_chunks"] == 11

        # Verify persisted in DB runtime_settings and reloads after cache clear & memory reset
        settings.default_top_k_chunks = 6
        invalidate_runtime_config_cache()
        cfg_resp = client.get("/api/config", headers=admin_headers)
        assert cfg_resp.status_code == 200
        assert cfg_resp.json()["config"]["default_top_k_chunks"] == 11

        load_persisted_runtime_config()
        assert settings.default_top_k_chunks == 11

        # SSRF metadata endpoint rejection
        r_ssrf = client.put(
            "/api/config",
            headers=admin_headers,
            json={"ollama_base_url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert r_ssrf.status_code == 422
    finally:
        settings.default_top_k_chunks = orig_top_k
        invalidate_runtime_config_cache()


# ============================================================================
# 6. MULTI-HOP PATH FINDER + DOCUMENT ACL ISOLATION
# ============================================================================

def test_multihop_path_finder_and_acl_isolation(client: TestClient) -> None:
    admin_headers = {"X-API-Key": "dev-admin-key"}
    viewer_headers = {"X-API-Key": "dev-viewer-key"}

    assert client.post("/api/documents/load-demo-fixtures", headers=admin_headers).status_code == 200

    entities = client.get("/api/graph/entities", headers=admin_headers).json()
    inc_ent = next(e for e in entities if "INC-2026-041" in e["canonical_name"])
    bank_ent = next(e for e in entities if "Meridian Retail Bank" in e["canonical_name"])

    r_path = client.get(
        f"/api/graph/shortest-path?source_id={inc_ent['entity_id']}&target_id={bank_ent['entity_id']}&max_hops=5",
        headers=admin_headers,
    )
    assert r_path.status_code == 200
    pdata = r_path.json()
    assert pdata["found"] is True
    assert pdata["hop_count"] >= 1
    assert len(pdata["paths"]) >= 1
    assert len(pdata["paths"][0]["node_ids"]) >= 2
    assert len(pdata["paths"][0]["edge_ids"]) >= 1
    assert len(pdata["path_nodes"]) >= 2
    assert len(pdata["path_edges"]) >= 1

    # Restrict regulatory audit document containing Meridian Retail Bank
    docs = client.get("/api/documents", headers=admin_headers).json()
    audit_doc = next(d for d in docs if "03_regulatory_compliance_audit" in d["filename"])
    r_acl = client.put(
        f"/api/documents/{audit_doc['doc_id']}/acl",
        headers=admin_headers,
        json={"visibility": "private", "allowed_roles": ["admin"], "allowed_user_ids": []},
    )
    assert r_acl.status_code == 200

    # Viewer must NOT discover Meridian Retail Bank in /api/graph/entities or shortest-path
    viewer_ents = client.get("/api/graph/entities", headers=viewer_headers).json()
    assert all("Meridian Retail Bank" not in e["canonical_name"] for e in viewer_ents)

    r_v_path = client.get(
        f"/api/graph/shortest-path?source_id={inc_ent['entity_id']}&target_id={bank_ent['entity_id']}&max_hops=5",
        headers=viewer_headers,
    )
    assert r_v_path.status_code == 200
    assert r_v_path.json()["found"] is False


# ============================================================================
# 7. UNCERTAIN MATCHES INTERACTIVE RESOLUTION (KEEP DISTINCT & APPROVE MERGE)
# ============================================================================

def test_uncertain_matches_keep_distinct_and_merge_workflow(client: TestClient) -> None:
    admin_headers = {"X-API-Key": "dev-admin-key"}
    analyst_headers = {"X-API-Key": "dev-analyst-key"}
    viewer_headers = {"X-API-Key": "dev-viewer-key"}

    assert client.post("/api/documents/load-demo-fixtures", headers=admin_headers).status_code == 200

    pending = client.get("/api/graph/uncertain-matches?status=pending", headers=admin_headers).json()
    assert len(pending) >= 2

    # 1. Viewer cannot resolve uncertain matches -> 403
    first_match = pending[0]
    r_viewer_deny = client.post(
        f"/api/graph/uncertain-matches/{first_match['match_id']}/resolve",
        headers=viewer_headers,
        json={"action": "keep_distinct"},
    )
    assert r_viewer_deny.status_code == 403

    # 2. Analyst marks first match permanently distinct -> survives document re-indexing
    r_keep = client.post(
        f"/api/graph/uncertain-matches/{first_match['match_id']}/resolve",
        headers=analyst_headers,
        json={"action": "keep_distinct", "note": "Distinct production versions verified"},
    )
    assert r_keep.status_code == 200
    assert r_keep.json()["status"] == "kept_distinct"

    # Re-ingest demo corpus -> first_match must NOT reappear in pending list
    assert client.post("/api/documents/load-demo-fixtures", headers=admin_headers).status_code == 200
    pending_after_reingest = client.get(
        "/api/graph/uncertain-matches?status=pending", headers=admin_headers
    ).json()
    assert all(m["match_id"] != first_match["match_id"] for m in pending_after_reingest)

    # 3. Admin approves merge on second pending match -> entity consolidated cleanly
    second_match = pending_after_reingest[0]
    r_merge = client.post(
        f"/api/graph/uncertain-matches/{second_match['match_id']}/resolve",
        headers=admin_headers,
        json={
            "action": "merge",
            "canonical_entity_id": second_match["entity_a_id"],
            "note": "Consolidated duplicate variant in test",
        },
    )
    assert r_merge.status_code == 200
    mdata = r_merge.json()
    assert mdata["status"] == "merged"
    assert mdata["canonical_entity_id"] == second_match["entity_a_id"]

    # Merged entity_b_id must be absent from graph entities
    entities_after = client.get("/api/graph/entities", headers=admin_headers).json()
    entity_ids_after = {e["entity_id"] for e in entities_after}
    assert second_match["entity_a_id"] in entity_ids_after
    assert second_match["entity_b_id"] not in entity_ids_after

    # Audit log must record the resolution event
    audits = client.get("/api/audit-logs?action=graph.uncertain_match.resolve", headers=admin_headers).json()
    assert audits["total"] >= 2


# ============================================================================
# 8. BILINGUAL INDONESIAN + ENGLISH EXTRACTION & QUERY ALIGNMENT
# ============================================================================

def test_bilingual_indonesian_extraction_and_cross_lingual_qa(client: TestClient) -> None:
    admin_headers = {"X-API-Key": "dev-admin-key"}

    id_doc = (
        "# Laporan Insiden Infrastruktur & Regulasi\n\n"
        "[Page 1]\n"
        "PT Nusantara FinTech mengoperasikan Gerbang Pembayaran Nusantara di Pusat Data Jakarta Selatan. "
        "Pada 14 Oktober 2026, Insiden INC-2026-099 disebabkan oleh Sistem Inti Nusantara dan "
        "berdampak pada Bank Mandiri Sejahtera serta denda Rp 2.5 miliar. "
        "PT Nusantara FinTech diatur oleh POJK No. 11/POJK.03/2022.\n"
    )
    r_id_up = client.post(
        "/api/documents/upload",
        headers=admin_headers,
        files={"file": ("laporan_insiden_id.md", id_doc.encode("utf-8"), "text/markdown")},
    )
    assert r_id_up.status_code == 200
    assert r_id_up.json()["entity_count"] >= 4
    assert r_id_up.json()["relationship_count"] >= 2

    entities_id = {
        e["canonical_name"] for e in client.get("/api/graph/entities", headers=admin_headers).json()
    }
    assert any("PT Nusantara FinTech" in name for name in entities_id)
    assert any("POJK" in name for name in entities_id)

    # Load English enterprise demo corpus and query in Indonesian (cross-lingual non-false-abstention)
    assert client.post("/api/documents/load-demo-fixtures", headers=admin_headers).status_code == 200
    r_q_id = client.post(
        "/api/query",
        headers=admin_headers,
        json={
            "question": "Apa yang menyebabkan insiden INC-2026-041 pada Helios Payment Gateway dan apa dampak terhadap regulasi serta penalti SLA?",
            "strategy": "hybrid",
            "max_hops": 2,
        },
    )
    assert r_q_id.status_code == 200
    q_data = r_q_id.json()
    assert q_data["abstained"] is False
    assert len(q_data["citations"]) >= 1
    assert len(q_data["graph_paths"]) >= 1

    # Out-of-corpus Indonesian question must still abstain cleanly
    r_q_oos = client.post(
        "/api/query",
        headers=admin_headers,
        json={"question": "Berapa harga saham Mars Rover di tahun 2035?"},
    )
    assert r_q_oos.status_code == 200
    assert r_q_oos.json()["abstained"] is True


# ============================================================================
# 9. ASYNC BACKGROUND INGESTION (HTTP 202) & JOB POLLING
# ============================================================================

def test_async_background_ingestion_202_and_job_polling(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin_headers = {"X-API-Key": "dev-admin-key"}
    beta_headers = {"X-API-Key": "dev-beta-key"}
    for var in ("VERCEL", "AWS_LAMBDA_FUNCTION_NAME", "LAMBDA_TASK_ROOT"):
        monkeypatch.delenv(var, raising=False)

    md_content = (
        "# Async Pipeline Test Document\n\n"
        "Aurelia Financial Cloud operates Chronos Consensus Engine v2.4 for automated clearing.\n"
    )
    r_async = client.post(
        "/api/documents/upload?async_mode=true",
        headers=admin_headers,
        files={"file": ("async_doc.md", md_content.encode("utf-8"), "text/markdown")},
        data={"visibility": "tenant", "allowed_roles": "admin,analyst,viewer"},
    )
    assert r_async.status_code == 202
    resp_data = r_async.json()
    assert resp_data["status"] == "queued"
    job_id = resp_data["job_id"]

    # Poll GET /api/jobs/{job_id} until completed
    final_job = None
    for _ in range(30):
        r_job = client.get(f"/api/jobs/{job_id}", headers=admin_headers)
        assert r_job.status_code == 200
        job_data = r_job.json()
        if job_data["status"] in ("completed", "failed"):
            final_job = job_data
            break
        time.sleep(0.05)

    assert final_job is not None
    assert final_job["status"] == "completed"
    assert final_job["progress_pct"] == 100
    assert final_job["details"]["chunk_count"] >= 1

    # Cross-tenant caller cannot inspect tenant-alpha's job (404)
    assert client.get(f"/api/jobs/{job_id}", headers=beta_headers).status_code == 404


# ============================================================================
# 10. LEGACY SCHEMA MIGRATION SAFETY CHECK (DATA/GRAPHRAG.DB)
# ============================================================================

def test_legacy_database_copy_migrates_safely(tmp_path: Path) -> None:
    repo_db = Path("data/graphrag.db")
    if not repo_db.exists():
        pytest.skip("No local data/graphrag.db present to test migration.")

    copy_db = tmp_path / "migrated_copy.db"
    shutil.copy2(repo_db, copy_db)
    init_db(str(copy_db))

    with get_db_connection(str(copy_db)) as conn:
        user_cols = {r[1] for r in conn.execute("PRAGMA table_info(users);").fetchall()}
        unc_cols = {r[1] for r in conn.execute("PRAGMA table_info(uncertain_matches);").fetchall()}
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table';"
            ).fetchall()
        }
    assert "token_version" in user_cols
    assert {"status", "resolved_by", "resolved_at", "resolution_note"} <= unc_cols
    assert {"login_rate_limits", "runtime_settings", "entity_resolution_decisions"} <= tables
