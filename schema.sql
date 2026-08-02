-- EasyCommunity — schéma de la base D1
-- Exécuter avec : wrangler d1 execute easycommunity --file=./schema.sql --remote

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,          -- administrateur | secretaire | tresorier
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL           -- objet membre complet, au format JSON
);

CREATE TABLE IF NOT EXISTS dues (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL           -- paiement de cotisation, au format JSON
);

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL           -- recette/dépense, au format JSON
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL           -- rapport ou compte rendu, au format JSON
);

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  data TEXT NOT NULL           -- informations de l'association, au format JSON
);

CREATE TABLE IF NOT EXISTS license (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  key_value TEXT,               -- la clé de licence telle que saisie par l'administrateur
  expires TEXT,                 -- date d'expiration AAAA-MM-JJ extraite de la clé
  updated_at TEXT
);

-- Remarque : le compte administrateur par défaut
-- (admin / admin123) est créé automatiquement
-- par le Worker au tout premier appel si la table "users" est vide.
-- Tant qu'aucune ligne n'existe dans "license" (ou qu'elle est expirée),
-- l'application reste bloquée pour tous les comptes.
