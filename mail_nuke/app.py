from __future__ import annotations

from contextlib import asynccontextmanager
import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from mail_nuke import __version__
from mail_nuke.config import load_settings
from mail_nuke.database import Database
from mail_nuke.imap_service import discover_folders, test_connection
from mail_nuke.indexer import process_next_job
from mail_nuke.security import (
    SecretCipher,
    generate_session_token,
    hash_password,
    hash_session_token,
    session_expiry,
    verify_password,
)


settings = load_settings()
database = Database(settings.database_path)
secret_cipher = SecretCipher.load(settings.secret_key, settings.generated_secret_key_path)
bearer = HTTPBearer(auto_error=False)


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize()
    database.recover_interrupted_jobs()
    stop = asyncio.Event()

    async def worker() -> None:
        last_schedule_check = 0.0
        while not stop.is_set():
            now = asyncio.get_running_loop().time()
            if now - last_schedule_check >= 60:
                await asyncio.to_thread(
                    database.queue_due_reconciliations,
                    settings.reconcile_interval_seconds,
                )
                await asyncio.to_thread(
                    database.queue_due_training,
                    settings.training_interval_seconds,
                )
                last_schedule_check = now
            worked = await asyncio.to_thread(
                process_next_job, database, secret_cipher, settings.data_dir
            )
            if not worked:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=2)
                except TimeoutError:
                    pass

    task = asyncio.create_task(worker())
    try:
        yield
    finally:
        stop.set()
        await task


app = FastAPI(
    title="Mail Nuke",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


class InitialAdminRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=12, max_length=1024)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class ModelGroupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class AccountRequest(BaseModel):
    model_group_id: str
    display_name: str = Field(min_length=1, max_length=128)
    email_address: str = Field(min_length=3, max_length=320)
    imap_host: str = Field(min_length=1, max_length=253)
    imap_port: int = Field(ge=1, le=65535, default=993)
    imap_use_ssl: bool = True
    imap_username: str = Field(min_length=1, max_length=320)
    imap_password: str = Field(min_length=1, max_length=2048)


FolderRole = Literal["spam", "ham", "monitored", "excluded", "neutral"]


class FolderRoleAssignment(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    role: FolderRole


class FolderRoleRequest(BaseModel):
    assignments: list[FolderRoleAssignment]


class PrivacyProfileRequest(BaseModel):
    user_names: list[str] = Field(default_factory=list, max_length=100)
    custom_emails: list[str] = Field(default_factory=list, max_length=100)
    known_secrets: list[str] | None = Field(default=None, max_length=100)
    normalize_other_emails: bool = False


class MessageReviewRequest(BaseModel):
    label: Literal["ham", "spam"] | None = None
    training_status: Literal["included", "excluded"] | None = None


class ThresholdOverrideRequest(BaseModel):
    threshold: float | None = Field(default=None, ge=0, le=1)


class AccountAutomationRequest(BaseModel):
    mode: Literal["off", "observe", "move"]
    spam_destination_folder_id: str | None = None


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required")
    user = database.session_user(hash_session_token(credentials.credentials))
    if user is None:
        raise HTTPException(status_code=401, detail="Session is invalid or expired")
    return dict(user)


AuthenticatedUser = Annotated[dict, Depends(current_user)]


def account_with_secret(account_id: str) -> tuple[dict, str]:
    row = database.get_account(account_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Account not found")
    account = dict(row)
    password = secret_cipher.decrypt(account.pop("imap_password_ciphertext"))
    account["imap_use_ssl"] = bool(account["imap_use_ssl"])
    return account, password


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/v2/setup/status")
def setup_status() -> dict[str, bool]:
    return {"configured": database.is_configured()}


@app.post("/api/v2/setup/admin", status_code=status.HTTP_201_CREATED)
def create_initial_admin(payload: InitialAdminRequest) -> dict[str, str]:
    try:
        password_hash = hash_password(payload.password)
        user_id = str(uuid4())
        database.create_initial_admin(user_id, payload.username, password_hash)
        return {"id": user_id, "username": payload.username.strip()}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/v2/auth/login")
def login(payload: LoginRequest) -> dict[str, str]:
    user = database.find_user_by_username(payload.username)
    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = generate_session_token()
    database.create_session(hash_session_token(token), user["id"], session_expiry())
    return {"access_token": token, "token_type": "bearer"}


@app.post("/api/v2/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
    _: AuthenticatedUser,
) -> None:
    database.revoke_session(hash_session_token(credentials.credentials))


@app.get("/api/v2/model-groups")
def list_model_groups(_: AuthenticatedUser) -> list[dict]:
    return database.list_model_groups()


@app.post("/api/v2/model-groups", status_code=status.HTTP_201_CREATED)
def create_model_group(payload: ModelGroupRequest, _: AuthenticatedUser) -> dict:
    try:
        return database.create_model_group(str(uuid4()), payload.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="A model group with this name already exists") from exc


@app.get("/api/v2/accounts")
def list_accounts(_: AuthenticatedUser) -> list[dict]:
    return database.list_accounts()


@app.post("/api/v2/accounts", status_code=status.HTTP_201_CREATED)
def create_account(payload: AccountRequest, _: AuthenticatedUser) -> dict:
    if database.get_model_group(payload.model_group_id) is None:
        raise HTTPException(status_code=400, detail="Model group does not exist")
    if not payload.display_name.strip() or not payload.imap_host.strip() or not payload.imap_username.strip():
        raise HTTPException(status_code=400, detail="Account fields cannot contain only whitespace")
    return database.create_account(
        {
            "id": str(uuid4()),
            "model_group_id": payload.model_group_id,
            "display_name": payload.display_name.strip(),
            "email_address": payload.email_address.strip(),
            "imap_host": payload.imap_host.strip(),
            "imap_port": payload.imap_port,
            "imap_use_ssl": payload.imap_use_ssl,
            "imap_username": payload.imap_username.strip(),
            "imap_password_ciphertext": secret_cipher.encrypt(payload.imap_password),
        }
    )


@app.post("/api/v2/accounts/{account_id}/test-connection")
def test_account_connection(account_id: str, _: AuthenticatedUser) -> dict:
    account, password = account_with_secret(account_id)
    try:
        return test_connection(account, password)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"IMAP connection failed ({type(exc).__name__})",
        ) from exc


@app.post("/api/v2/accounts/{account_id}/discover-folders")
def discover_account_folders(account_id: str, _: AuthenticatedUser) -> list[dict]:
    account, password = account_with_secret(account_id)
    try:
        discovered = discover_folders(account, password)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Folder discovery failed ({type(exc).__name__})",
        ) from exc
    stored = [dict(item, id=str(uuid4())) for item in discovered]
    return database.replace_discovered_folders(account_id, stored)


@app.get("/api/v2/accounts/{account_id}/folders")
def list_account_folders(account_id: str, _: AuthenticatedUser) -> list[dict]:
    if database.get_account(account_id) is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return database.list_folders(account_id)


@app.put("/api/v2/accounts/{account_id}/folders/roles")
def update_folder_roles(
    account_id: str, payload: FolderRoleRequest, _: AuthenticatedUser
) -> list[dict]:
    if database.get_account(account_id) is None:
        raise HTTPException(status_code=404, detail="Account not found")
    try:
        return database.set_folder_roles(
            account_id, [assignment.model_dump() for assignment in payload.assignments]
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v2/accounts/{account_id}/index", status_code=status.HTTP_202_ACCEPTED)
def queue_account_index(account_id: str, _: AuthenticatedUser) -> dict:
    try:
        return database.create_index_job(str(uuid4()), account_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Account not found") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v2/accounts/{account_id}/index-status")
def account_index_status(account_id: str, _: AuthenticatedUser) -> dict:
    if database.get_account(account_id) is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return {
        "counts": database.account_message_counts(account_id),
        "folders": database.list_folders(account_id),
        "jobs": database.list_jobs(account_id)[:10],
    }


def public_privacy_profile(group_id: str) -> dict:
    profile = database.get_privacy_profile(group_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Model group not found")
    ciphertext = profile.pop("known_secrets_ciphertext", None)
    try:
        secret_count = len(json.loads(secret_cipher.decrypt(ciphertext))) if ciphertext else 0
    except (RuntimeError, json.JSONDecodeError):
        secret_count = 0
    profile["known_secret_count"] = secret_count
    profile["account_emails"] = database.group_email_addresses(group_id)
    return profile


@app.get("/api/v2/model-groups/{group_id}/privacy-profile")
def get_privacy_profile(group_id: str, _: AuthenticatedUser) -> dict:
    return public_privacy_profile(group_id)


@app.put("/api/v2/model-groups/{group_id}/privacy-profile")
def update_privacy_profile(
    group_id: str, payload: PrivacyProfileRequest, _: AuthenticatedUser
) -> dict:
    names = sorted({value.strip() for value in payload.user_names if value.strip()})
    emails = sorted({value.strip().casefold() for value in payload.custom_emails if value.strip()})
    replace_secrets = payload.known_secrets is not None
    encrypted = None
    if replace_secrets:
        secrets = sorted({value for value in payload.known_secrets or [] if value})
        encrypted = secret_cipher.encrypt(json.dumps(secrets)) if secrets else None
    try:
        database.update_privacy_profile(
            group_id, names, emails, payload.normalize_other_emails, encrypted, replace_secrets
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Model group not found") from exc
    job = database.create_reprocess_job(str(uuid4()), group_id)
    result = public_privacy_profile(group_id)
    result["reprocessing_job"] = job
    return result


@app.post("/api/v2/accounts/{account_id}/reconcile", status_code=status.HTTP_202_ACCEPTED)
def queue_account_reconciliation(account_id: str, _: AuthenticatedUser) -> dict:
    try:
        return database.create_reconcile_job(str(uuid4()), account_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Account not found") from exc


@app.get("/api/v2/messages")
def list_review_messages(
    _: AuthenticatedUser,
    account_id: str | None = None,
    group_id: str | None = None,
    label: Literal["ham", "spam"] | None = None,
    mailbox_status: Literal["present", "moved", "deleted", "unavailable"] | None = None,
    training_status: Literal["included", "excluded", "purged"] | None = None,
    search: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
) -> dict:
    return database.list_messages(
        account_id, group_id, label, mailbox_status, training_status, search, limit, offset
    )


@app.patch("/api/v2/messages/{message_id}")
def review_message(
    message_id: str, payload: MessageReviewRequest, _: AuthenticatedUser
) -> dict:
    if payload.label is None and payload.training_status is None:
        raise HTTPException(status_code=400, detail="No review change was supplied")
    try:
        return database.update_message_review(
            message_id, payload.label, payload.training_status
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Message not found") from exc


@app.get("/api/v2/messages/{message_id}/events")
def get_message_events(message_id: str, _: AuthenticatedUser) -> list[dict]:
    return database.message_events(message_id)


@app.delete("/api/v2/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
def purge_message(message_id: str, _: AuthenticatedUser) -> None:
    try:
        raw_path = database.purge_message(message_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Message not found") from exc
    if raw_path and database.raw_path_reference_count(raw_path) == 0:
        path = (settings.data_dir / raw_path).resolve()
        raw_root = (settings.data_dir / "raw-mail").resolve()
        if raw_root in path.parents:
            path.unlink(missing_ok=True)


@app.post("/api/v2/model-groups/{group_id}/train", status_code=status.HTTP_202_ACCEPTED)
def queue_model_training(group_id: str, _: AuthenticatedUser) -> dict:
    try:
        return database.create_training_job(str(uuid4()), group_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Model group not found") from exc


@app.get("/api/v2/model-groups/{group_id}/model-status")
def model_status(group_id: str, _: AuthenticatedUser) -> dict:
    try:
        return database.model_group_status(group_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Model group not found") from exc


@app.put("/api/v2/model-groups/{group_id}/threshold")
def update_threshold(
    group_id: str, payload: ThresholdOverrideRequest, _: AuthenticatedUser
) -> dict:
    try:
        return database.set_threshold_override(group_id, payload.threshold)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Model group not found") from exc


@app.put("/api/v2/accounts/{account_id}/automation")
def update_account_automation(
    account_id: str, payload: AccountAutomationRequest, _: AuthenticatedUser
) -> dict:
    try:
        return database.set_account_automation(
            account_id, payload.mode, payload.spam_destination_folder_id
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Account not found") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v2/readiness")
def deployment_readiness(_: AuthenticatedUser) -> dict:
    return database.deployment_readiness()


@app.get("/", response_class=FileResponse)
def portal(_: Request) -> FileResponse:
    return FileResponse(static_dir / "index.html")
