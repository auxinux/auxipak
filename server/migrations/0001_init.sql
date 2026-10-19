-- AuxiPak Server — schéma initial.
-- Les évaluations de conformité (statut AuxiNux) sont stockées séparément des
-- signatures cryptographiques et des publications.

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{1,31}$'),
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'reviewer', 'publisher')),
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    ip          TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

-- Jetons d'API. kind = human (outil d'un administrateur), ci (intégration
-- continue), agent (agent d'automatisation, ex. IA). Un jeton « agent » ne
-- peut jamais approuver une publication, classer une application, gérer des
-- comptes ou des clés, quelle que soit la portée demandée.
CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('human', 'ci', 'agent')),
    provider     TEXT,
    scopes       TEXT[] NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE repositories (
    name        TEXT PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,31}$'),
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    official    BOOLEAN NOT NULL DEFAULT FALSE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    generation  BIGINT NOT NULL DEFAULT 0,
    published_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE apps (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    publisher   TEXT NOT NULL,
    summary     TEXT NOT NULL,
    description TEXT,
    license     TEXT NOT NULL,
    homepage    TEXT,
    categories  TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Classification officielle : uniquement modifiable par un relecteur humain.
CREATE TABLE evaluations (
    app_id       TEXT PRIMARY KEY REFERENCES apps(id) ON DELETE CASCADE,
    status       TEXT NOT NULL CHECK (status IN ('verified', 'compatible', 'unreviewed')),
    note         TEXT,
    criteria     JSONB NOT NULL DEFAULT '{}',
    evaluated_by UUID REFERENCES users(id),
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evaluation_history (
    id           BIGSERIAL PRIMARY KEY,
    app_id       TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    status       TEXT NOT NULL,
    note         TEXT,
    evaluated_by UUID REFERENCES users(id),
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE submissions (
    id             UUID PRIMARY KEY,
    repository     TEXT NOT NULL REFERENCES repositories(name),
    file_name      TEXT NOT NULL,
    size           BIGINT NOT NULL,
    sha256         TEXT NOT NULL,
    app_id         TEXT,
    version        TEXT,
    manifest       JSONB,
    validation     JSONB NOT NULL DEFAULT '{}',
    signature      JSONB,
    status         TEXT NOT NULL CHECK (status IN ('invalid', 'pending', 'approved', 'rejected', 'published', 'failed')),
    submitted_by   UUID REFERENCES users(id),
    token_id       UUID REFERENCES api_tokens(id),
    submitter_kind TEXT NOT NULL CHECK (submitter_kind IN ('human', 'ci', 'agent', 'session')),
    note           TEXT NOT NULL DEFAULT '',
    reviewed_by    UUID REFERENCES users(id),
    reviewed_at    TIMESTAMPTZ,
    review_note    TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX submissions_status ON submissions(status, created_at DESC);

CREATE TABLE releases (
    id               UUID PRIMARY KEY,
    repository       TEXT NOT NULL REFERENCES repositories(name),
    app_id           TEXT NOT NULL REFERENCES apps(id),
    version          TEXT NOT NULL,
    file_name        TEXT NOT NULL,
    languages        TEXT[] NOT NULL,
    size             BIGINT NOT NULL,
    sha256           TEXT NOT NULL,
    signature        JSONB NOT NULL,
    signature_key_id TEXT NOT NULL,
    manifest         JSONB NOT NULL,
    manifest_yaml    TEXT NOT NULL,
    uses_scripts     BOOLEAN NOT NULL,
    submission_id    UUID REFERENCES submissions(id),
    state            TEXT NOT NULL CHECK (state IN ('published', 'unpublished', 'revoked')),
    state_reason     TEXT,
    state_changed_at TIMESTAMPTZ,
    published_by     UUID REFERENCES users(id),
    published_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository, app_id, version, file_name)
);
CREATE INDEX releases_app ON releases(app_id);

CREATE TABLE builder_projects (
    id            UUID PRIMARY KEY,
    name          TEXT NOT NULL,
    owner_user    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_id      UUID REFERENCES api_tokens(id) ON DELETE SET NULL,
    manifest_yaml TEXT NOT NULL,
    last_build    JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user UUID,
    actor_name TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    details    JSONB NOT NULL DEFAULT '{}',
    ip         TEXT
);
CREATE INDEX audit_at ON audit_log(at DESC);

INSERT INTO repositories (name, title, description, official)
VALUES ('official', 'AuxiNux — dépôt officiel', 'Applications distribuées et évaluées par AuxiNux', TRUE);
