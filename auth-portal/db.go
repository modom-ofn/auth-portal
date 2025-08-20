package main

import "log"

func createSchema() error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username   TEXT UNIQUE NOT NULL,
  email      TEXT,
  plex_uuid  TEXT UNIQUE,
  plex_token TEXT
);

CREATE TABLE IF NOT EXISTS pins (
  id SERIAL PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  pin_id INTEGER NOT NULL,
  created_at TIMESTAMP DEFAULT now()
);
`)
	return err
}

func savePin(code string, pinID int) error {
	_, err := db.Exec(`
		INSERT INTO pins (code, pin_id)
		VALUES ($1, $2)
		ON CONFLICT (code) DO UPDATE SET pin_id = EXCLUDED.pin_id;
	`, code, pinID)
	return err
}

func saveUser(tok TokenResponse) {
	_, err := db.Exec(`
		INSERT INTO users (username, email, plex_uuid, plex_token)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (plex_uuid) DO UPDATE SET
		  username = EXCLUDED.username,
		  email    = EXCLUDED.email,
		  plex_token = EXCLUDED.plex_token;
	`, tok.User.Username, tok.User.Email, tok.User.UUID, tok.AuthToken)
	if err != nil {
		log.Printf("Failed to save user: %v", err)
	} else {
		log.Printf("User %s saved to database", tok.User.Username)
	}
}