-- Textes des applications dans d'autres langues (AuxiPak 1.0.8) : champ
-- « translations » du manifeste ({"en": {"name", "summary", "description"}}).
ALTER TABLE apps ADD COLUMN translations JSONB NOT NULL DEFAULT '{}';
