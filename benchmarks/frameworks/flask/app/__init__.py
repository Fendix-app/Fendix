from flask import Flask

from app.blueprint import bp

# Importing each case module registers its route on the shared blueprint.
from app import (  # noqa: E402,F401
    cmdi_direct,
    cmdi_indirect,
    cmdi_safe,
    cmdi_safe_lookalike,
    hardcoded_secret_direct,
    hardcoded_secret_indirect,
    hardcoded_secret_safe,
    hardcoded_secret_safe_lookalike,
    open_redirect_direct,
    open_redirect_indirect,
    open_redirect_safe,
    open_redirect_safe_lookalike,
    path_traversal_direct,
    path_traversal_indirect,
    path_traversal_safe,
    path_traversal_safe_lookalike,
    sqli_direct,
    sqli_indirect,
    sqli_safe,
    sqli_safe_lookalike,
    ssrf_direct,
    ssrf_indirect,
    ssrf_safe,
    ssrf_safe_lookalike,
    xss_direct,
    xss_indirect,
    xss_safe,
    xss_safe_lookalike,
)
from app import (  # noqa: E402,F401
    cmdi_alt_api,
    cmdi_cross_file,
    hardcoded_secret_alt_api,
    hardcoded_secret_cross_file,
    jwt_no_verify_direct,
    jwt_no_verify_indirect,
    jwt_no_verify_safe,
    jwt_no_verify_safe_lookalike,
    open_redirect_alt_api,
    open_redirect_cross_file,
    path_traversal_alt_api,
    path_traversal_cross_file,
    sqli_alt_api,
    sqli_cross_file,
    ssrf_alt_api,
    ssrf_cross_file,
    ssti_direct,
    ssti_indirect,
    ssti_safe,
    ssti_safe_lookalike,
    weak_password_hash_direct,
    weak_password_hash_indirect,
    weak_password_hash_safe,
    weak_password_hash_safe_lookalike,
    weak_random_token_direct,
    weak_random_token_indirect,
    weak_random_token_safe,
    weak_random_token_safe_lookalike,
    xss_alt_api,
    xss_cross_file,
)


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app
