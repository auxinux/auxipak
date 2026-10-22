-- Pré-évaluation automatique par une IA (AuxiPak 1.0.9). Indicative : affichée
-- seulement tant qu'aucun relecteur humain n'a évalué l'application (table
-- evaluations), toujours étiquetée « analyse automatique par l'IA ».
CREATE TABLE ai_evaluations (
    app_id       TEXT PRIMARY KEY CHECK (app_id ~ '^[a-z0-9][a-z0-9.+-]{1,63}$'),
    status       TEXT NOT NULL CHECK (status IN ('verified', 'compatible')),
    notes        JSONB NOT NULL DEFAULT '{}',
    criteria     JSONB NOT NULL DEFAULT '{}',
    sources      TEXT[] NOT NULL DEFAULT '{}',
    model        TEXT,
    submitted_by UUID REFERENCES users(id),
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
