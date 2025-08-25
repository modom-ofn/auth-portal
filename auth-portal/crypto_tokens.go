package main

// Preferred names
func EncryptToken(raw string) (string, error) { return SealToken(raw) }
func DecryptToken(enc string) (string, error) { return OpenToken(enc) }

func SealPlexToken(raw string) (string, error) { return SealToken(raw) }
func OpenPlexToken(enc string) (string, error) { return OpenToken(enc) }

// Back-compat shims for older code paths (e.g., store.go)
func sealToken(raw string) (string, error)   { return SealToken(raw) }
func unsealToken(enc string) (string, error) { return OpenToken(enc) }