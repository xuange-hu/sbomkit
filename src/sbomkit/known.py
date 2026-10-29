"""Bundled offline knowledge: licenses for popular packages, and the popular
name list used for typosquat distance.

Both tables are *best-effort* and deliberately small. They exist so a fully
offline scan still produces a usable answer for the long tail of boring,
well-known dependencies. Anything not in these tables is reported as unknown
rather than guessed, and any entry can be overridden with ``--license-map``.
"""

from __future__ import annotations

# --------------------------------------------------------------- license table
# ecosystem -> {package name (lower): SPDX expression}
LICENSES: dict[str, dict[str, str]] = {
    "pypi": {
        "anyio": "MIT",
        "attrs": "MIT",
        "boto3": "Apache-2.0",
        "botocore": "Apache-2.0",
        "celery": "BSD-3-Clause",
        "certifi": "MPL-2.0",
        "charset-normalizer": "MIT",
        "click": "BSD-3-Clause",
        "colorama": "BSD-3-Clause",
        "coverage": "Apache-2.0",
        "cryptography": "Apache-2.0 OR BSD-3-Clause",
        "django": "BSD-3-Clause",
        "ecdsa": "MIT",
        "exceptiongroup": "MIT",
        "fastapi": "MIT",
        "flask": "BSD-3-Clause",
        "grpcio": "Apache-2.0",
        "h11": "MIT",
        "httpcore": "BSD-3-Clause",
        "httpx": "BSD-3-Clause",
        "idna": "BSD-3-Clause",
        "itsdangerous": "BSD-3-Clause",
        "jinja2": "BSD-3-Clause",
        "jsonschema": "MIT",
        "lxml": "BSD-3-Clause",
        "markupsafe": "BSD-3-Clause",
        "marshmallow": "MIT",
        "mcp": "MIT",
        "mypy": "MIT",
        "numpy": "BSD-3-Clause",
        "packaging": "Apache-2.0 OR BSD-2-Clause",
        "pandas": "BSD-3-Clause",
        "pillow": "HPND",
        "pip": "MIT",
        "pluggy": "MIT",
        "protobuf": "BSD-3-Clause",
        "pycryptodome": "BSD-2-Clause",
        "pydantic": "MIT",
        "pydantic-core": "MIT",
        "pyopenssl": "Apache-2.0",
        "pytest": "MIT",
        "python-can": "LGPL-3.0-or-later",
        "python-dateutil": "Apache-2.0 OR BSD-3-Clause",
        "python-dotenv": "BSD-3-Clause",
        "pyyaml": "MIT",
        "redis": "MIT",
        "requests": "Apache-2.0",
        "rich": "MIT",
        "ruff": "MIT",
        "scipy": "BSD-3-Clause",
        "setuptools": "MIT",
        "six": "MIT",
        "sniffio": "Apache-2.0 OR MIT",
        "sqlalchemy": "MIT",
        "starlette": "BSD-3-Clause",
        "tomli": "MIT",
        "tqdm": "MPL-2.0",
        "typing-extensions": "PSF-2.0",
        "udsoncan": "MIT",
        "urllib3": "MIT",
        "uvicorn": "BSD-3-Clause",
        "virtualenv": "MIT",
        "werkzeug": "BSD-3-Clause",
        "wheel": "MIT",
    },
    "npm": {
        "@types/node": "MIT",
        "axios": "MIT",
        "bcrypt": "MIT",
        "body-parser": "MIT",
        "bootstrap": "MIT",
        "chalk": "MIT",
        "commander": "MIT",
        "cors": "MIT",
        "d3": "ISC",
        "dayjs": "MIT",
        "debug": "MIT",
        "dotenv": "BSD-2-Clause",
        "electron": "MIT",
        "esbuild": "MIT",
        "eslint": "MIT",
        "express": "MIT",
        "glob": "ISC",
        "graphql": "MIT",
        "helmet": "MIT",
        "jest": "MIT",
        "jquery": "MIT",
        "jsonwebtoken": "MIT",
        "lodash": "MIT",
        "minimatch": "ISC",
        "moment": "MIT",
        "mongoose": "MIT",
        "morgan": "MIT",
        "next": "MIT",
        "pg": "MIT",
        "postcss": "MIT",
        "prettier": "MIT",
        "react": "MIT",
        "react-dom": "MIT",
        "redux": "MIT",
        "rimraf": "ISC",
        "rollup": "MIT",
        "semver": "ISC",
        "socket.io": "MIT",
        "sqlite3": "BSD-3-Clause",
        "svelte": "MIT",
        "tailwindcss": "MIT",
        "three": "MIT",
        "typescript": "Apache-2.0",
        "uuid": "MIT",
        "vite": "MIT",
        "vue": "MIT",
        "webpack": "MIT",
        "ws": "MIT",
        "yaml": "ISC",
        "zod": "MIT",
    },
    "golang": {
        "github.com/gin-gonic/gin": "MIT",
        "github.com/google/uuid": "BSD-3-Clause",
        "github.com/gorilla/mux": "BSD-3-Clause",
        "github.com/joho/godotenv": "MIT",
        "github.com/pkg/errors": "BSD-2-Clause",
        "github.com/prometheus/client_golang": "Apache-2.0",
        "github.com/sirupsen/logrus": "MIT",
        "github.com/spf13/cobra": "Apache-2.0",
        "github.com/spf13/viper": "MIT",
        "github.com/stretchr/testify": "MIT",
        "go.uber.org/zap": "MIT",
        "golang.org/x/crypto": "BSD-3-Clause",
        "golang.org/x/net": "BSD-3-Clause",
        "golang.org/x/sync": "BSD-3-Clause",
        "golang.org/x/sys": "BSD-3-Clause",
        "golang.org/x/text": "BSD-3-Clause",
    },
    "cargo": {
        "anyhow": "MIT OR Apache-2.0",
        "axum": "MIT",
        "bytes": "MIT",
        "chrono": "MIT OR Apache-2.0",
        "clap": "MIT OR Apache-2.0",
        "env_logger": "MIT OR Apache-2.0",
        "futures": "MIT OR Apache-2.0",
        "hyper": "MIT",
        "itertools": "MIT OR Apache-2.0",
        "libc": "MIT OR Apache-2.0",
        "log": "MIT OR Apache-2.0",
        "once_cell": "MIT OR Apache-2.0",
        "rand": "MIT OR Apache-2.0",
        "rayon": "MIT OR Apache-2.0",
        "regex": "MIT OR Apache-2.0",
        "reqwest": "MIT OR Apache-2.0",
        "rustls": "Apache-2.0 OR ISC OR MIT",
        "serde": "MIT OR Apache-2.0",
        "serde_json": "MIT OR Apache-2.0",
        "sqlx": "MIT OR Apache-2.0",
        "thiserror": "MIT OR Apache-2.0",
        "tokio": "MIT",
        "uuid": "Apache-2.0 OR MIT",
    },
}

# ------------------------------------------------------------- popular names
# Used only as the reference set for typosquat distance. Larger is better but
# it must stay a static table to keep the package dependency-free.
POPULAR: dict[str, tuple[str, ...]] = {
    "pypi": (
        "requests", "urllib3", "certifi", "charset-normalizer", "idna", "click", "rich",
        "pyyaml", "pytest", "setuptools", "pip", "wheel", "six", "numpy", "pandas",
        "scipy", "flask", "jinja2", "werkzeug", "markupsafe", "itsdangerous", "django",
        "fastapi", "pydantic", "starlette", "uvicorn", "httpx", "httpcore", "h11",
        "anyio", "sniffio", "sqlalchemy", "alembic", "celery", "redis", "boto3",
        "botocore", "cryptography", "pyopenssl", "lxml", "pillow", "tqdm", "attrs",
        "packaging", "typing-extensions", "tomli", "pluggy", "iniconfig", "coverage",
        "mypy", "ruff", "black", "marshmallow", "python-dateutil", "python-dotenv",
        "jsonschema", "protobuf", "grpcio", "pycryptodome", "ecdsa", "udsoncan",
        "python-can", "colorama", "virtualenv", "tox", "mcp", "uvicorn", "gunicorn",
    ),
    "npm": (
        "react", "react-dom", "vue", "express", "lodash", "axios", "typescript",
        "vite", "esbuild", "rollup", "webpack", "next", "nuxt", "svelte", "tailwindcss",
        "jest", "eslint", "prettier", "chalk", "commander", "debug", "uuid", "moment",
        "dayjs", "zod", "redux", "jquery", "bootstrap", "three", "d3", "ws", "semver",
        "glob", "rimraf", "minimatch", "fs-extra", "dotenv", "cors", "body-parser",
        "helmet", "morgan", "socket.io", "electron", "postcss", "autoprefixer", "sass",
        "graphql", "apollo-server", "mongoose", "pg", "mysql", "sqlite3", "jsonwebtoken",
        "bcrypt", "yaml", "inquirer", "ora", "yargs", "webpack-cli", "babel-loader",
    ),
    "golang": (
        "github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/gorilla/websocket",
        "github.com/spf13/cobra", "github.com/spf13/viper", "github.com/stretchr/testify",
        "github.com/sirupsen/logrus", "github.com/pkg/errors", "github.com/google/uuid",
        "github.com/prometheus/client_golang", "go.uber.org/zap", "golang.org/x/net",
        "golang.org/x/crypto", "golang.org/x/sys", "golang.org/x/sync", "golang.org/x/text",
        "github.com/joho/godotenv", "github.com/golang/protobuf", "google.golang.org/grpc",
        "github.com/go-sql-driver/mysql", "github.com/lib/pq", "github.com/redis/go-redis",
    ),
    "cargo": (
        "serde", "serde_json", "tokio", "reqwest", "clap", "anyhow", "thiserror", "rand",
        "regex", "rayon", "log", "env_logger", "chrono", "bytes", "futures", "hyper",
        "axum", "sqlx", "once_cell", "libc", "itertools", "uuid", "rustls", "actix-web",
        "diesel", "tracing", "async-trait", "crossbeam", "parking_lot", "indexmap",
    ),
}


def known_license(ecosystem: str, name: str) -> str | None:
    if not name:
        return None
    table = LICENSES.get(ecosystem, {})
    hit = table.get(name.lower())
    if hit:
        return hit
    # npm scopes: @scope/pkg may be known without the scope
    if "/" in name and not name.startswith("@"):
        return table.get(name.rsplit("/", 1)[-1].lower())  # golang module paths
    return None


def popular_names(ecosystem: str) -> tuple[str, ...]:
    return POPULAR.get(ecosystem, ())


def all_known_names(ecosystem: str) -> tuple[str, ...]:
    """Popular names + everything we have a license for (both are real packages)."""
    extra = tuple(LICENSES.get(ecosystem, {}).keys())
    return tuple(dict.fromkeys(POPULAR.get(ecosystem, ()) + extra))
