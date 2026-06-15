"""Shared AAA helper routes for the RADIUS + TACACS+ pages: resolving the
address gateways / Gaia should connect to (the host's public IP, not the
Traefik web domain) and pinning a manual override. The heavy lifting lives in
app.utils.models_aaa.public_endpoint."""
from flask import Blueprint, jsonify, request, redirect, url_for, flash

from app.routes.admin import admin_required
from app.utils.models_aaa import public_endpoint, set_setting
from app.utils.activity import record

aaa_bp = Blueprint('aaa', __name__, url_prefix='/admin/aaa')

# Only these views may be returned to after saving (no open redirect).
_RETURN_TO = {'radius': 'radius.config', 'tacacs': 'tacacs.config'}


@aaa_bp.route('/endpoint')
@admin_required
def endpoint():
    """Reachable address as JSON. ?refresh=1 forces re-detection."""
    refresh = request.args.get('refresh') == '1'
    host, source = public_endpoint(refresh=refresh, detect=True)
    return jsonify({"ok": True, "host": host, "source": source})


@aaa_bp.route('/public-host', methods=['POST'])
@admin_required
def set_public_host():
    """Pin (or clear, when blank) the address shown to operators."""
    host = (request.form.get('public_host') or '').strip()
    set_setting('public_host', host)
    record('settings', f"Set reachable address to {host}" if host
           else "Cleared reachable-address override (auto-detect)")
    flash(f"Reachable address pinned to {host}" if host
          else "Reachable address set to auto-detect", 'success')
    target = _RETURN_TO.get(request.form.get('return_to'), 'radius.config')
    return redirect(url_for(target))
