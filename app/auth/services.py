from __future__ import annotations

from flask import current_app, session
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    options_to_json_dict,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.extensions import db
from app.models import User, WebAuthnCredential


class WebAuthnService:
    @staticmethod
    def begin_registration(user: User) -> dict:
        cfg = current_app.config

        existing: list[PublicKeyCredentialDescriptor] = []
        for cred in user.webauthn_credentials:
            existing.append(
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred.credential_id))
            )

        options = generate_registration_options(
            rp_id=cfg["WEBAUTHN_RP_ID"],
            rp_name=cfg["WEBAUTHN_RP_NAME"],
            user_id=str(user.id).encode("utf-8"),
            user_name=user.email or (user.username or str(user.id)),
            user_display_name=user.email or (user.username or str(user.id)),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=existing,
        )

        options_json = options_to_json_dict(options)
        session["webauthn_challenge"] = options_json["challenge"]

        return options_json

    @staticmethod
    def complete_registration(user: User, credential_data: dict) -> tuple[bool, str]:
        cfg = current_app.config

        challenge_b64 = session.pop("webauthn_challenge", None)
        if not challenge_b64:
            return False, "No registration in progress"

        expected_challenge = base64url_to_bytes(challenge_b64)

        try:
            credential = parse_registration_credential_json(credential_data)
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=cfg["WEBAUTHN_RP_ID"],
                expected_origin=cfg["WEBAUTHN_ORIGIN"],
                require_user_verification=True,
            )
        except Exception as exc:
            current_app.logger.exception("WebAuthn registration failed")
            return False, f"Registration failed: {exc}"

        db_cred = WebAuthnCredential(
            user_id=user.id,
            credential_id=credential.raw_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )
        db.session.add(db_cred)
        db.session.commit()

        return True, "Registration successful"

    @staticmethod
    def begin_login() -> dict:
        cfg = current_app.config

        options = generate_authentication_options(
            rp_id=cfg["WEBAUTHN_RP_ID"],
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        options_json = options_to_json_dict(options)
        session["webauthn_login_challenge"] = options_json["challenge"]

        return options_json

    @staticmethod
    def complete_login(credential_data: dict) -> tuple[bool, str, User | None]:
        cfg = current_app.config

        challenge_b64 = session.pop("webauthn_login_challenge", None)
        if not challenge_b64:
            return False, "No login in progress", None

        expected_challenge = base64url_to_bytes(challenge_b64)

        try:
            credential = parse_authentication_credential_json(credential_data)
        except Exception as exc:
            current_app.logger.exception("WebAuthn parse failed")
            return False, f"Parse failed: {exc}", None

        db_cred = WebAuthnCredential.query.filter_by(credential_id=credential.raw_id).first()
        if not db_cred:
            return False, "Credential not found", None

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_rp_id=cfg["WEBAUTHN_RP_ID"],
                expected_origin=cfg["WEBAUTHN_ORIGIN"],
                credential_public_key=db_cred.public_key,
                credential_current_sign_count=db_cred.sign_count,
                require_user_verification=True,
            )
        except Exception as exc:
            current_app.logger.exception("WebAuthn auth failed")
            return False, f"Authentication failed: {exc}", None

        db_cred.sign_count = verification.new_sign_count
        from datetime import datetime

        db_cred.last_used_at = datetime.utcnow()
        db.session.commit()

        return True, "Authentication successful", db_cred.user


class CredentialService:
    @staticmethod
    def rename_credential(user_id: int, cred_id: int, new_name: str) -> tuple[bool, str]:
        if not new_name:
            return False, "Name required"

        cred = WebAuthnCredential.query.filter_by(id=cred_id, user_id=user_id).first()

        if not cred:
            return False, "Credential not found"

        cred.name = new_name
        db.session.commit()

        return True, "Passkey renamed"

    @staticmethod
    def delete_credential(user_id: int, cred_id: int) -> tuple[bool, str]:
        cred = WebAuthnCredential.query.filter_by(id=cred_id, user_id=user_id).first()

        if not cred:
            return False, "Credential not found"

        db.session.delete(cred)
        db.session.commit()

        return True, "Passkey deleted"
