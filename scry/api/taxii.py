"""Minimal read-only TAXII 2.1 server for scry intel.

Implements the TAXII 2.1 server-side surface needed by consumers such as
MISP, OpenCTI and Microsoft Sentinel:

- ``GET /taxii2/`` — server discovery
- ``GET /taxii2/{api_root}/`` — api-root discovery
- ``GET /taxii2/{api_root}/collections/`` — collection list
- ``GET /taxii2/{api_root}/collections/{collection_id}/objects/`` — STIX
  objects envelope with simple ``limit``/``next`` pagination

Two collections are offered:

- ``intel`` — entities + observables + relationships as STIX 2.1 objects
  (``scry.exports.stix21.build_intel_bundle``)
- ``articles`` — report SDOs for recent articles
  (``scry.exports.stix21.build_articles_bundle``)

Everything is read-only: ``can_write`` is always false and no object-adding
endpoints exist. Auth reuses ``require_api_key`` (wired at mount time in
``scry.main``), so TAXII requires the API key whenever the rest of the API
does — TAXII has no discovery exemption.

Deviations from a full TAXII 2.1 implementation (intentional, minimal scope):
- pagination is an opaque index into a deterministic object-id manifest rather
  than a TAXII ``next`` token tied to server state;
- no manifest endpoint (``/manifest/``), no filtering (``?match[type]=``),
  no `can_write`-gated POST.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from scry.api.deps import get_session
from scry.exports.stix21 import build_articles_bundle, build_intel_bundle

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

API_ROOT_ID = "api-root"

COLLECTIONS = [
    {
        "id": "intel",
        "title": "scry intel",
        "description": "Entities, observable indicators (with SCOs) and relationships.",
    },
    {
        "id": "articles",
        "title": "scry articles",
        "description": "Report SDOs for recently ingested articles.",
    },
]
_COLLECTION_IDS = {c["id"] for c in COLLECTIONS}

MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MiB, well under TAXII's 100 MiB cap

taxii_router = APIRouter(prefix="/taxii2")


def _taxii_response(payload: dict, status_code: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=payload, media_type=TAXII_MEDIA_TYPE)


def _taxii_error(status_code: int, description: str) -> JSONResponse:
    return _taxii_response({"description": description}, status_code=status_code)


def _api_root_url(request: Request) -> str:
    return f"{str(request.base_url).rstrip('/')}/taxii2/{API_ROOT_ID}"


def _collection_bundle(session: Session, collection_id: str) -> dict:
    if collection_id == "intel":
        return build_intel_bundle(session)
    return build_articles_bundle(session)


@taxii_router.get("")
def taxii_server_discovery(request: Request):
    """TAXII server discovery — points clients at the default api-root."""
    root = _api_root_url(request)
    return _taxii_response({"title": "scry", "default": root, "api_roots": [root]})


@taxii_router.get("/{api_root}/")
def taxii_api_root(api_root: str):
    if api_root != API_ROOT_ID:
        return _taxii_error(404, f"Unknown api-root '{api_root}'")
    return _taxii_response(
        {
            "title": "scry",
            "versions": [TAXII_MEDIA_TYPE],
            "max_content_length": MAX_CONTENT_LENGTH,
        }
    )


@taxii_router.get("/{api_root}/collections/")
def taxii_collections(api_root: str):
    if api_root != API_ROOT_ID:
        return _taxii_error(404, f"Unknown api-root '{api_root}'")
    return _taxii_response(
        {
            "collections": [
                {
                    "id": c["id"],
                    "title": c["title"],
                    "description": c["description"],
                    "can_read": True,
                    "can_write": False,
                    "media_types": [STIX_MEDIA_TYPE],
                }
                for c in COLLECTIONS
            ]
        }
    )


@taxii_router.get("/{api_root}/collections/{collection_id}/objects/")
def taxii_collection_objects(
    api_root: str,
    collection_id: str,
    request: Request,
    limit: int | None = None,
    next: str | None = None,
    session: Session = Depends(get_session),
):
    if api_root != API_ROOT_ID:
        return _taxii_error(404, f"Unknown api-root '{api_root}'")
    if collection_id not in _COLLECTION_IDS:
        return _taxii_error(404, f"Unknown collection '{collection_id}'")

    bundle = _collection_bundle(session, collection_id)
    manifest = [obj["id"] for obj in bundle["objects"]]  # deterministic order

    page_size = min(limit, 1000) if limit else 100
    try:
        offset = int(next) if next else 0
    except ValueError:
        offset = 0
    offset = max(0, offset)

    page = bundle["objects"][offset : offset + page_size]
    new_offset = offset + page_size
    has_more = new_offset < len(manifest)
    envelope = {
        "more": has_more,
        "next": str(new_offset) if has_more else None,
        "objects": page,
    }
    return JSONResponse(content=envelope, media_type=STIX_MEDIA_TYPE)
