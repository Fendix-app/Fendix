package semgrep

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ruleFixture is one Python file and the bundled rule it exercises: the rule
// must fire on it when fires is true and stay silent when false.
type ruleFixture struct {
	rule  string
	file  string
	fires bool
	body  string
}

// ruleBehaviourFixtures pins what the four injection/auth rules repaired in
// v3.6.3 actually match. Each one listed its alternatives as sibling
// `pattern:` entries under `patterns:`, which Semgrep ANDs, so none of them
// could ever fire; these fixtures were red against that rule pack.
var ruleBehaviourFixtures = []ruleFixture{
	// python-eval-injection: eval()/exec() with a non-literal argument.
	{"python-eval-injection", "eval_dynamic.py", true, "def run(user_input):\n    return eval(user_input)\n"},
	{"python-eval-injection", "exec_dynamic.py", true, "def run(user_code):\n    exec(user_code)\n"},
	{"python-eval-injection", "eval_with_globals.py", true, "def run(expr, env):\n    return eval(expr, env)\n"},
	{"python-eval-injection", "eval_literal.py", false, "def run():\n    return eval(\"2 + 2\")\n"},
	{"python-eval-injection", "exec_literal.py", false, "def run():\n    exec(\"x = 1\")\n"},
	{"python-eval-injection", "literal_eval.py", false, "import ast\ndef run(user_input):\n    return ast.literal_eval(user_input)\n"},

	// python-jwt-decode-no-verification: signature verification disabled, or "none" allowed.
	{"python-jwt-decode-no-verification", "jwt_verify_false.py", true, "import jwt\ndef read(token):\n    return jwt.decode(token, options={\"verify_signature\": False})\n"},
	{"python-jwt-decode-no-verification", "jwt_verify_false_with_key.py", true, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, algorithms=[\"HS256\"], options={\"verify_signature\": False})\n"},
	{"python-jwt-decode-no-verification", "jwt_verify_false_among_options.py", true, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, options={\"verify_exp\": True, \"verify_signature\": False})\n"},
	{"python-jwt-decode-no-verification", "jwt_alg_none.py", true, "import jwt\ndef read(token):\n    return jwt.decode(token, algorithms=[\"none\"])\n"},
	{"python-jwt-decode-no-verification", "jwt_alg_none_with_key.py", true, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, algorithms=[\"HS256\", \"none\"])\n"},
	{"python-jwt-decode-no-verification", "jwt_verified.py", false, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, algorithms=[\"HS256\"])\n"},
	{"python-jwt-decode-no-verification", "jwt_other_option.py", false, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, algorithms=[\"HS256\"], options={\"verify_exp\": False})\n"},

	// python-sql-injection-string-format: a query built by formatting, passed to execute().
	{"python-sql-injection-string-format", "sql_percent.py", true, "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = %s\" % uid)\n"},
	{"python-sql-injection-string-format", "sql_concat.py", true, "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = \" + uid)\n"},
	{"python-sql-injection-string-format", "sql_fstring.py", true, "def q(cursor, uid):\n    cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n"},
	{"python-sql-injection-string-format", "sql_format_method.py", true, "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = {}\".format(uid))\n"},
	{"python-sql-injection-string-format", "sql_parameterised.py", false, "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n"},
	{"python-sql-injection-string-format", "sql_literal_concat.py", false, "def q(cursor):\n    cursor.execute(\"SELECT * FROM users \" + \"WHERE active = 1\")\n"},
	// An f-string whose interpolations are all string constants builds no
	// injectable query; a constant must not hide a value from input beside
	// it, a local that rebinds it, or a query built another way.
	{"python-sql-injection-string-format", "sql_const_table.py", false, "USERS_TABLE = \"users\"\ndef h(cur):\n    cur.execute(f\"SELECT id FROM {USERS_TABLE}\")\n"},
	{"python-sql-injection-string-format", "sql_local_const.py", false, "def h(cur):\n    table = \"users\"\n    cur.execute(f\"SELECT id FROM {table}\")\n"},
	{"python-sql-injection-string-format", "sql_var.py", true, "def h(cur, name):\n    cur.execute(f\"SELECT id FROM users WHERE n = '{name}'\")\n"},
	{"python-sql-injection-string-format", "sql_upper_tainted.py", true, "from flask import request\ndef h(cur):\n    QUERY = request.args[\"q\"]\n    cur.execute(f\"SELECT id FROM users WHERE n = '{QUERY}'\")\n"},
	{"python-sql-injection-string-format", "sql_mixed_const_and_var.py", true, "COLS = \"id, name\"\ndef h(cur, name):\n    cur.execute(f\"SELECT {COLS} FROM users WHERE n = '{name}'\")\n"},
	{"python-sql-injection-string-format", "sql_const_shadowed_by_local.py", true, "from flask import request\nTABLE = \"users\"\ndef h(cur):\n    TABLE = request.args[\"t\"]\n    cur.execute(f\"SELECT id FROM {TABLE}\")\n"},
	{"python-sql-injection-string-format", "sql_const_rebound_conditionally.py", true, "def h(cur, name):\n    where = \"\"\n    if name:\n        where = f\"WHERE n = '{name}'\"\n    cur.execute(f\"SELECT id FROM users {where}\")\n"},
	{"python-sql-injection-string-format", "sql_percent_beside_const.py", true, "TABLE = \"users\"\ndef h(cur, name):\n    cur.execute(\"SELECT id FROM users WHERE n = '%s'\" % name)\n"},
	// Constant propagation is per function: a rebinding through nonlocal or
	// after a lambda's definition is invisible to it, so the rule must still
	// fire there. A global write elsewhere and a module-level reassignment
	// are visible to it; these pin that.
	{"python-sql-injection-string-format", "sql_const_rebound_nonlocal.py", true, "def h(cur, s):\n    t = \"users\"\n    def setit():\n        nonlocal t\n        t = s\n    setit()\n    cur.execute(f\"SELECT id FROM {t}\")\n"},
	{"python-sql-injection-string-format", "sql_const_rebound_lambda.py", true, "from flask import request\ndef h(cur):\n    table = \"users\"\n    run = lambda: cur.execute(f\"SELECT id FROM {table}\")\n    table = request.args[\"t\"]\n    run()\n"},
	{"python-sql-injection-string-format", "sql_const_rebound_lambda_param.py", true, "from flask import request\ndef h(conn):\n    table = \"users\"\n    run = lambda c: c.execute(f\"SELECT id FROM {table}\")\n    table = request.args[\"t\"]\n    run(conn.cursor())\n"},
	{"python-sql-injection-string-format", "sql_const_global_rebound.py", true, "TABLE = \"users\"\ndef set_table(v):\n    global TABLE\n    TABLE = v\ndef h(cur):\n    cur.execute(f\"SELECT id FROM {TABLE}\")\n"},
	{"python-sql-injection-string-format", "sql_const_module_reassigned.py", true, "import sys\nTABLE = \"users\"\nTABLE = sys.argv[1]\ndef h(cur):\n    cur.execute(f\"SELECT id FROM {TABLE}\")\n"},

	// python-command-injection-shell-true: os.system / os.popen with a non-literal command.
	{"python-command-injection-shell-true", "os_system_var.py", true, "import os\ndef go(cmd):\n    os.system(cmd)\n"},
	{"python-command-injection-shell-true", "os_system_fstring.py", true, "import os\ndef go(path):\n    os.system(f\"ls {path}\")\n"},
	{"python-command-injection-shell-true", "os_popen_var.py", true, "import os\ndef go(cmd):\n    return os.popen(cmd).read()\n"},
	{"python-command-injection-shell-true", "os_system_literal.py", false, "import os\ndef go():\n    os.system(\"ls -la\")\n"},
	{"python-command-injection-shell-true", "argv_list.py", false, "import subprocess\ndef go(path):\n    subprocess.run([\"ls\", path])\n"},
	// subprocess(..., shell=True) is python-subprocess-shell-true-with-variable's;
	// this rule must not report the same call a second time.
	{"python-command-injection-shell-true", "subprocess_shell_var.py", false, "import subprocess\ndef go(cmd):\n    subprocess.run(cmd, shell=True)\n"},
	{"python-subprocess-shell-true-with-variable", "subprocess_shell_var.py", true, ""},

	// flask-route-no-auth-decorator: the one missing-auth rule for a Flask
	// route since flask-missing-login-required was removed (ADR-012). A route
	// is protected only by an auth decorator below @app.route(...): route()
	// must be the outermost decorator, so one placed above it wraps the
	// already-registered view and leaves the URL open. Semgrep matches a
	// function's decorators in any order, so the above-the-route shape needs
	// its own branch; before it, neither Flask rule reported @login_required
	// there, and an @requires_auth placed there was reported only by the
	// removed rule.
	{"flask-route-no-auth-decorator", "flask_route_no_decorator.py", true, "from flask import Flask\napp = Flask(__name__)\n\n@app.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_blueprint_no_decorator.py", true, "from flask import Blueprint\nbp = Blueprint(\"admin\", __name__)\n\n@bp.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_login_required_below.py", false, "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@app.route(\"/admin\")\n@login_required\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_requires_auth_below.py", false, "from flask import Flask\napp = Flask(__name__)\n\n@app.route(\"/admin\")\n@requires_auth\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_jwt_required_below.py", false, "from flask import Flask\nfrom flask_jwt_extended import jwt_required\napp = Flask(__name__)\n\n@app.route(\"/admin\")\n@jwt_required()\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_auth_login_required_below.py", false, "from flask import Flask\nfrom flask_httpauth import HTTPBasicAuth\napp = Flask(__name__)\nauth = HTTPBasicAuth()\n\n@app.route(\"/admin\")\n@auth.login_required\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_login_required_above.py", true, "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@login_required\n@app.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_requires_auth_above.py", true, "from flask import Flask\napp = Flask(__name__)\n\n@requires_auth\n@app.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_jwt_required_above_blueprint.py", true, "from flask import Blueprint\nfrom flask_jwt_extended import jwt_required\nbp = Blueprint(\"admin\", __name__)\n\n@jwt_required()\n@bp.route(\"/admin\", methods=[\"GET\", \"POST\"])\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_login_required_above_other_between.py", true, "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@login_required\n@limiter.limit(\"5/minute\")\n@app.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_login_required_above_multiline_route.py", true, "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@login_required\n@app.route(\n    \"/admin\",\n    methods=[\"GET\"],\n)\ndef admin_view():\n    return \"secret\"\n"},
	// Protected by the decorator below the route; the one above is redundant.
	// Below the route, any arguments and a module prefix count as auth.
	{"flask-route-no-auth-decorator", "flask_auth_above_and_below.py", false, "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@login_required\n@app.route(\"/admin\")\n@requires_auth\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_above_and_requires_auth_args_below.py", false, "from flask import Flask\napp = Flask(__name__)\n\n@login_required\n@app.route(\"/admin\")\n@requires_auth(\"admin\")\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_above_and_qualified_below.py", false, "import flask_login\nfrom flask import Flask\napp = Flask(__name__)\n\n@login_required\n@app.route(\"/admin\")\n@flask_login.login_required\ndef admin_view():\n    return \"secret\"\n"},
	// Spacing Python allows: a space before route's parenthesis, after the @.
	{"flask-route-no-auth-decorator", "flask_above_route_space_paren.py", true, "from flask import Flask\napp = Flask(__name__)\n\n@requires_auth\n@app.route (\"/admin\")\ndef admin_view():\n    return \"secret\"\n"},
	{"flask-route-no-auth-decorator", "flask_above_space_after_at.py", true, "from flask import Flask\napp = Flask(__name__)\n\n@ requires_auth\n@app.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n"},

	// fastapi-route-missing-auth-dependency counts any Depends(...) or
	// Security(...) on a route as auth, including a non-auth one such as a DB
	// session (the rule's documented false negative). Task 2.4b adds the
	// Annotated spellings the rule missed: Depends/Security in any Annotated
	// metadata position, a module-level alias in the same file, and an alias
	// imported from a deps/dependencies module, and keeps that semantics for
	// them.
	{"fastapi-route-missing-auth-dependency", "fastapi_no_auth.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/items\")\ndef read_items(q: str = \"\"):\n    return q\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_depends_default.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/me\")\ndef me(user: dict = Depends(get_current_user)):\n    return user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_depends_default_non_auth.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/items\")\ndef read_items(session: dict = Depends(get_db)):\n    return []\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_annotated_inline.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/me\")\nasync def me(user: Annotated[dict, Depends(get_current_user)]):\n    return user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_annotated_inline_extra_metadata.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/me\")\ndef me(user: Annotated[dict, \"the caller\", Depends(get_current_user)]):\n    return user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_annotated_alias.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nCurrentUser = Annotated[dict, Depends(get_current_user)]\n\n@router.get(\"/me\")\ndef me(current_user: CurrentUser):\n    return current_user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_annotated_alias_async_among_params.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nCurrentUser = Annotated[dict, Depends(get_current_user)]\n\n@router.post(\"/items\")\nasync def create(*, name: str, current_user: CurrentUser, limit: int = 10):\n    return current_user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_annotated_alias_non_auth.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nSessionDep = Annotated[dict, Depends(get_db)]\n\n@router.get(\"/items\")\ndef read_items(session: SessionDep):\n    return []\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_security_default.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/me\")\ndef me(user: dict = Security(get_current_user, scopes=[\"me\"])):\n    return user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_security_inline.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/me\")\ndef me(user: Annotated[dict, Security(get_current_user, scopes=[\"me\"])]):\n    return user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_security_alias.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nCurrentUser = Annotated[dict, Security(get_current_user, scopes=[\"me\"])]\n\n@router.get(\"/me\")\ndef me(current_user: CurrentUser):\n    return current_user\n"},
	// An alias imported from a deps/dependencies module (FastAPI's template
	// layout) is assumed to be such an Annotated alias.
	{"fastapi-route-missing-auth-dependency", "fastapi_imported_alias_deps.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.api.deps import CurrentUser, SessionDep\n\n@router.get(\"/me\")\ndef me(session: SessionDep, current_user: CurrentUser):\n    return current_user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_imported_alias_relative_dependencies.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom ..dependencies import CurrentUser\n\n@router.get(\"/me\")\ndef me(current_user: CurrentUser):\n    return current_user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_imported_alias_renamed.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.api.deps import CurrentUser as CU\n\n@router.get(\"/me\")\ndef me(c: CU):\n    return c\n"},
	// The exclusion binds the name the import binds here: the original name
	// of a renamed deps import is not an alias in this file.
	{"fastapi-route-missing-auth-dependency", "fastapi_deps_import_renamed_original_name_used.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.config import Settings\nfrom app.dependencies import Settings as SettingsDep\n\n@router.post(\"/x\")\ndef x(s: Settings):\n    return s\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_deps_import_renamed_original_name_only.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.api.deps import Pagination as Pg\n\n@router.get(\"/x\")\ndef x(p: Pagination):\n    return p\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_decorator_dependencies.py", false, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/items\", dependencies=[Depends(get_current_user)])\ndef read_items():\n    return []\n"},
	// Still reported: an alias or import does not protect a route that does
	// not use it, and a name that is not an Annotated[..., Depends] alias is an
	// ordinary parameter.
	{"fastapi-route-missing-auth-dependency", "fastapi_alias_beside_unprotected_route.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nCurrentUser = Annotated[dict, Depends(get_current_user)]\n\n@router.get(\"/open\")\ndef open_route(q: str = \"\"):\n    return q\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_imported_deps_unused_as_annotation.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.api.deps import CurrentUser, get_current_active_superuser\n\n@router.get(\"/open\")\ndef open_route(q: str = \"\"):\n    return q\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_imported_model.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.models import ItemCreate\n\n@router.post(\"/items\")\ndef create(item_in: ItemCreate):\n    return item_in\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_request_only.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/x\")\ndef x(request: Request):\n    return 1\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_query_alias.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nLimit = Annotated[int, Query(le=100)]\n\n@router.get(\"/x\")\ndef x(limit: Limit = 10):\n    return limit\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_inline_query.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\n@router.get(\"/x\")\ndef x(limit: Annotated[str, Query()] = \"\"):\n    return limit\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_imported_from_mydeps.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.mydeps import Pagination\n\n@router.get(\"/x\")\ndef x(p: Pagination):\n    return p\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_imported_from_depsutil.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.api.depsutil import Pagination\n\n@router.get(\"/x\")\ndef x(p: Pagination):\n    return p\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_alias_assigned_in_function.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\ndef make():\n    CurrentUser = Annotated[dict, Depends(get_current_user)]\n    return CurrentUser\n\n@router.get(\"/me\")\ndef me(current_user: CurrentUser):\n    return current_user\n"},
	// FastAPI does not read a dependency out of `Alias | None`.
	{"fastapi-route-missing-auth-dependency", "fastapi_optional_alias.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nCurrentUser = Annotated[dict, Depends(get_current_user)]\n\n@router.get(\"/me\")\ndef me(current_user: CurrentUser | None = None):\n    return current_user\n"},
	// Known limits, pinned: an alias imported from another module, and a
	// router-level APIRouter(dependencies=[...]), are not followed.
	{"fastapi-route-missing-auth-dependency", "fastapi_imported_alias_other_module.py", true, "from typing import Annotated\nfrom fastapi import APIRouter, Depends, Security, Query, Request\nrouter = APIRouter()\n\ndef get_current_user(): ...\ndef get_db(): ...\n\nfrom app.api.security import CurrentUser\n\n@router.get(\"/me\")\ndef me(current_user: CurrentUser):\n    return current_user\n"},
	{"fastapi-route-missing-auth-dependency", "fastapi_router_level_dependencies.py", true, "from fastapi import APIRouter, Depends\n\ndef verify(): ...\n\nrouter = APIRouter(dependencies=[Depends(verify)])\n\n@router.get(\"/items\")\ndef read_items():\n    return []\n"},
}

// requireSemgrep returns the semgrep binary, or skips the test when it is not
// installed. CI's semgrep-enabled job sets FENDIX_REQUIRE_SEMGREP=1 so a
// missing binary fails the job instead of passing it silently.
func requireSemgrep(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("semgrep")
	if err == nil {
		return bin
	}
	if os.Getenv("FENDIX_REQUIRE_SEMGREP") != "" {
		t.Fatalf("FENDIX_REQUIRE_SEMGREP is set but semgrep is not on PATH: %v", err)
	}
	t.Skip("semgrep not on PATH; skipping rule-behaviour test")
	return ""
}

// TestRuleBehaviour_RepairedRulesMatchTheirIntent runs the bundled rule pack
// over the fixtures above and checks each expectation.
func TestRuleBehaviour_RepairedRulesMatchTheirIntent(t *testing.T) {
	bin := requireSemgrep(t)
	resetRulesCacheForTesting()
	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}

	root := t.TempDir()
	for _, f := range ruleBehaviourFixtures {
		if f.body == "" {
			continue // shares another fixture's file
		}
		if err := os.WriteFile(filepath.Join(root, f.file), []byte(f.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command(bin, "scan", "--config", dir, "--json", "--no-git-ignore", "--metrics=off", "--disable-version-check", root)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// semgrep exits 1 when it finds matches; the JSON envelope is still valid.
	out, _ := cmd.Output()
	// A key Semgrep does not recognise is dropped with only a warning: the
	// rule loads and silently loses that clause. A top-level pattern-not and
	// pattern-not-inside sat outside `patterns:` this way until v3.6.3.
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.Contains(line, "Skipping unknown field") {
			t.Errorf("bundled rule has a clause Semgrep ignores: %s", strings.TrimSpace(line))
		}
	}
	var res struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
		} `json:"results"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("parse semgrep json: %v\noutput:\n%s", err, string(out))
	}
	if len(res.Errors) > 0 {
		t.Fatalf("semgrep reported %d rule/parse errors: %s", len(res.Errors), res.Errors[0])
	}

	fired := map[string]map[string]bool{} // file -> rule ids
	for _, r := range res.Results {
		file := filepath.Base(r.Path)
		if fired[file] == nil {
			fired[file] = map[string]bool{}
		}
		fired[file][r.CheckID[strings.LastIndex(r.CheckID, ".")+1:]] = true
	}
	for _, f := range ruleBehaviourFixtures {
		if got := fired[f.file][f.rule]; got != f.fires {
			var rules []string
			for id := range fired[f.file] {
				rules = append(rules, id)
			}
			sort.Strings(rules)
			t.Errorf("%s on %s: fired=%v, want %v (rules that fired: %v)", f.rule, f.file, got, f.fires, rules)
		}
	}
}
