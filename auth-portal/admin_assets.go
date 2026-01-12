package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

type viteManifestEntry struct {
	File    string   `json:"file"`
	CSS     []string `json:"css"`
	IsEntry bool     `json:"isEntry"`
	Src     string   `json:"src"`
}

func adminAssetPaths() (string, string) {
	manifestPath := filepath.Join("static", "react", ".vite", "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		log.Printf("admin assets: manifest read failed: %v", err)
		return "/static/react/admin.js", ""
	}

	var manifest map[string]viteManifestEntry
	if err := json.Unmarshal(raw, &manifest); err != nil {
		log.Printf("admin assets: manifest parse failed: %v", err)
		return "/static/react/admin.js", ""
	}

	entry, ok := manifest["index.html"]
	if !ok {
		for _, item := range manifest {
			if item.IsEntry {
				entry = item
				ok = true
				break
			}
		}
	}
	if !ok || entry.File == "" {
		log.Printf("admin assets: manifest missing entry")
		return "/static/react/admin.js", ""
	}

	jsPath := "/static/react/" + entry.File
	cssPath := ""
	if len(entry.CSS) > 0 {
		cssPath = "/static/react/" + entry.CSS[0]
	}
	return jsPath, cssPath
}
