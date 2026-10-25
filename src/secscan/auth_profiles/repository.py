"""auth_profiles 與 auth_profile_versions 的資料存取；回傳 frozen domain model。

誰能看到、修改哪些 profile 由 service 決定。profile 所屬的 project 由 target 取得（join targets），
不重複存放。密文欄位以 deferred 載入：一般的查詢不讀它，只有沿用 secret 與金鑰換版時才讀。
讀回的資料再經過 domain 的規則：DB 中不合規則的資料會讓讀取失敗（fail closed）。
"""

from collections.abc import Iterable, Mapping
from typing import cast
from uuid import UUID

from sqlalchemy import Select, func, select, update
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.credentials import AuthType, Credential
from secscan.auth_profiles.domain.model import (
    AuthProfile,
    NewAuthProfile,
    NewProfileVersion,
    ProfileDefinition,
    ProfileVersion,
    StoredSecret,
)
from secscan.auth_profiles.domain.preflight import ExpectedValue, Preflight
from secscan.auth_profiles.models import AuthProfileModel, AuthProfileVersionModel
from secscan.core.db import flush_or_raise
from secscan.core.pagination import Page, PageRequest
from secscan.targets.models import TargetModel


class AuthProfileRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create(self, new_profile: NewAuthProfile) -> UUID:
        """新增 profile（還沒有版本）；同一個 target 已有相同 role_label 時拋出
        ConstraintViolationError（uq_auth_profiles_target_id_role_label）。"""
        model = AuthProfileModel(
            target_id=new_profile.target_id,
            name=new_profile.name,
            role_label=new_profile.role_label,
            created_by_key_id=new_profile.created_by_key_id,
        )
        self._session.add(model)
        flush_or_raise(self._session)
        return model.id

    def add_version(
        self, profile_id: UUID, *, version: int, new_version: NewProfileVersion
    ) -> None:
        """新增一個版本。上一版的密文必須先清除（uq_auth_profile_versions_live_secret）。"""
        definition = new_version.definition
        preflight = definition.preflight
        self._session.add(
            AuthProfileVersionModel(
                profile_id=profile_id,
                version=version,
                type=definition.credential.type.value,
                header_name=definition.credential.header_name,
                preflight_method=preflight.method,
                preflight_path=preflight.path,
                preflight_expected_status=preflight.expected_status,
                preflight_expected_json=dict(preflight.expected_json),
                encrypted_secret=new_version.encrypted_secret,
                created_by_key_id=new_version.created_by_key_id,
            )
        )
        flush_or_raise(self._session)

    def erase_secret(self, profile_id: UUID, *, version: int) -> None:
        """清除這一版的密文；清除的時間是 transaction 開始的時間（與新版本的 created_at 相同）。"""
        self._session.execute(
            update(AuthProfileVersionModel)
            .where(
                AuthProfileVersionModel.profile_id == profile_id,
                AuthProfileVersionModel.version == version,
                AuthProfileVersionModel.encrypted_secret.is_not(None),
            )
            .values(encrypted_secret=None, secret_erased_at=func.now())
            .execution_options(synchronize_session=False)
        )

    def current_secret_for_update(self, profile_id: UUID, *, version: int) -> bytes | None:
        """以 FOR UPDATE 鎖住版本列再讀密文：金鑰換版還沒 commit 時會等它，讀到的是換版後的密文。"""
        return self._session.execute(
            select(AuthProfileVersionModel.encrypted_secret)
            .where(
                AuthProfileVersionModel.profile_id == profile_id,
                AuthProfileVersionModel.version == version,
            )
            .with_for_update()
        ).scalar_one()

    def get(self, profile_id: UUID) -> AuthProfile | None:
        row = self._session.execute(
            _with_project().where(AuthProfileModel.id == profile_id)
        ).first()
        if row is None:
            return None
        model, project_id = row
        return _profile(model, project_id, self._current(profile_id))

    def lock(self, profile_id: UUID) -> AuthProfile | None:
        """FOR UPDATE 鎖住 profile（只鎖 profile 的列），並以 DB 的最新值覆蓋已載入的物件。

        建立新版本前呼叫：同時更新同一個 profile 時，version 依 commit 的先後遞增。
        """
        row = self._session.execute(
            _with_project()
            .where(AuthProfileModel.id == profile_id)
            .with_for_update(of=AuthProfileModel)
            .execution_options(populate_existing=True)
        ).first()
        if row is None:
            return None
        model, project_id = row
        return _profile(model, project_id, self._current(profile_id))

    def count_for_target(self, target_id: UUID) -> int:
        return (
            self._session.scalar(
                select(func.count())
                .select_from(AuthProfileModel)
                .where(AuthProfileModel.target_id == target_id)
            )
            or 0
        )

    def list_by_target(self, target_id: UUID, page: PageRequest) -> Page[AuthProfile]:
        """依建立時間由舊到新（同時間再依 id），每個 profile 帶它目前的版本。"""
        rows = self._session.execute(
            _with_project()
            .where(AuthProfileModel.target_id == target_id)
            .order_by(AuthProfileModel.created_at, AuthProfileModel.id)
            .offset(page.offset)
            .limit(page.limit)
        ).all()
        current = self._current_versions(model.id for model, _ in rows)
        items = tuple(_profile(model, project_id, current[model.id]) for model, project_id in rows)
        return Page(items=items, total=self.count_for_target(target_id), request=page)

    def list_versions(self, profile_id: UUID, page: PageRequest) -> Page[ProfileVersion]:
        """新版本在前。"""
        of_profile = AuthProfileVersionModel.profile_id == profile_id
        total = (
            self._session.scalar(
                select(func.count()).select_from(AuthProfileVersionModel).where(of_profile)
            )
            or 0
        )
        models = self._session.scalars(
            select(AuthProfileVersionModel)
            .where(of_profile)
            .order_by(AuthProfileVersionModel.version.desc())
            .offset(page.offset)
            .limit(page.limit)
        )
        return Page(items=tuple(_version(model) for model in models), total=total, request=page)

    def secrets_for_update(self) -> tuple[StoredSecret, ...]:
        """所有還在的密文（金鑰換版用），以 FOR UPDATE 鎖住。

        依 profile 與版本排序：鎖的順序固定。
        """
        rows = self._session.execute(
            select(
                AuthProfileVersionModel.profile_id,
                AuthProfileVersionModel.version,
                AuthProfileVersionModel.encrypted_secret,
            )
            .where(AuthProfileVersionModel.encrypted_secret.is_not(None))
            .order_by(AuthProfileVersionModel.profile_id, AuthProfileVersionModel.version)
            .with_for_update()
        )
        return tuple(
            StoredSecret(profile_id=profile_id, version=version, token=token)
            for profile_id, version, token in rows
            if token is not None
        )

    def replace_secret(self, profile_id: UUID, *, version: int, token: bytes) -> None:
        """以重新加密的密文取代原本的（trigger 只允許換成另一份密文，不允許恢復已清除的）。"""
        self._session.execute(
            update(AuthProfileVersionModel)
            .where(
                AuthProfileVersionModel.profile_id == profile_id,
                AuthProfileVersionModel.version == version,
                AuthProfileVersionModel.encrypted_secret.is_not(None),
            )
            .values(encrypted_secret=token)
            .execution_options(synchronize_session=False)
        )

    def _current(self, profile_id: UUID) -> ProfileVersion:
        # profile 與第一個版本在同一個 transaction 建立：沒有版本代表資料不一致，one() 會失敗。
        model = self._session.scalars(
            select(AuthProfileVersionModel)
            .where(AuthProfileVersionModel.profile_id == profile_id)
            .order_by(AuthProfileVersionModel.version.desc())
            .limit(1)
        ).one()
        return _version(model)

    def _current_versions(self, profile_ids: Iterable[UUID]) -> dict[UUID, ProfileVersion]:
        """每個 profile 最新的版本（PostgreSQL 的 DISTINCT ON），一次查完，不逐一查詢。"""
        models = self._session.scalars(
            select(AuthProfileVersionModel)
            .where(AuthProfileVersionModel.profile_id.in_(list(profile_ids)))
            .ext(distinct_on(AuthProfileVersionModel.profile_id))
            .order_by(AuthProfileVersionModel.profile_id, AuthProfileVersionModel.version.desc())
        )
        return {model.profile_id: _version(model) for model in models}


def _with_project() -> Select[AuthProfileModel, UUID]:
    return select(AuthProfileModel, TargetModel.project_id).join(
        TargetModel, TargetModel.id == AuthProfileModel.target_id
    )


def _profile(model: AuthProfileModel, project_id: UUID, current: ProfileVersion) -> AuthProfile:
    return AuthProfile(
        id=model.id,
        target_id=model.target_id,
        project_id=project_id,
        name=model.name,
        role_label=model.role_label,
        created_by_key_id=model.created_by_key_id,
        created_at=model.created_at,
        current=current,
    )


def _version(model: AuthProfileVersionModel) -> ProfileVersion:
    credential = Credential(AuthType(model.type), header_name=model.header_name)
    preflight = Preflight(
        method=model.preflight_method,
        path=model.preflight_path,
        expected_status=model.preflight_expected_status,
        # jsonb 讀回的是任意 JSON 值；Preflight 建立時逐一檢查型別，不合規則就拋錯（fail closed）。
        expected_json=cast(Mapping[str, ExpectedValue], model.preflight_expected_json),
    )
    return ProfileVersion(
        profile_id=model.profile_id,
        version=model.version,
        definition=ProfileDefinition(credential=credential, preflight=preflight),
        # CHECK 保證兩者成對：清除時間是 NULL 就還有密文（不必為此讀出 deferred 的密文欄位）。
        secret_configured=model.secret_erased_at is None,
        secret_erased_at=model.secret_erased_at,
        created_by_key_id=model.created_by_key_id,
        created_at=model.created_at,
    )
