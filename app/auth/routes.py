from __future__ import annotations

from flask import (
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_security import auth_required, current_user
from flask_security.utils import login_user

from . import auth_bp
from .services import CredentialService, WebAuthnService


@auth_bp.route("/webauthn/manage", methods=["GET"])
@auth_required()
def webauthn_manage() -> str:
    return render_template("webauthn_manage.html")


@auth_bp.route("/webauthn/register/begin", methods=["POST"])
@auth_required()
def webauthn_register_begin():
    options_json = WebAuthnService.begin_registration(current_user)
    return jsonify(options_json)


@auth_bp.route("/webauthn/register/complete", methods=["POST"])
@auth_required()
def webauthn_register_complete():
    data = request.get_json()
    success, message = WebAuthnService.complete_registration(current_user, data)

    if not success:
        return message, 400

    return "", 204


@auth_bp.route("/webauthn/login/begin", methods=["POST"])
def webauthn_login_begin():
    options_json = WebAuthnService.begin_login()
    return jsonify(options_json)


@auth_bp.route("/webauthn/login/complete", methods=["POST"])
def webauthn_login_complete():
    data = request.get_json()
    success, message, user = WebAuthnService.complete_login(data)

    if not success:
        return message, 400

    login_user(user, authn_via=["webauthn"])
    return "", 204


@auth_bp.route("/webauthn/credential/<int:cred_id>/rename", methods=["POST"])
@auth_required()
def rename_credential(cred_id: int):
    data = request.get_json() if request.is_json else request.form
    new_name = data.get("name", "").strip()

    success, message = CredentialService.rename_credential(current_user.id, cred_id, new_name)

    if request.is_json:
        if not success:
            return jsonify({"success": False, "message": message}), (
                404 if "not found" in message else 400
            )
        return jsonify({"success": True, "message": message})
    else:
        if success:
            flash(f"Passkey renamed to '{new_name}'", "success")
        else:
            flash(message, "error")
        return redirect(url_for("auth.webauthn_manage"))


@auth_bp.route("/webauthn/credential/<int:cred_id>/delete", methods=["POST", "DELETE"])
@auth_required()
def delete_credential(cred_id: int):
    success, message = CredentialService.delete_credential(current_user.id, cred_id)

    if request.is_json or request.method == "DELETE":
        if not success:
            return jsonify({"success": False, "message": message}), 404
        return jsonify({"success": True, "message": message})
    else:
        if success:
            flash(message, "success")
        else:
            flash(message, "error")
        return redirect(url_for("auth.webauthn_manage"))
