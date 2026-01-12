import { createRoot } from "react-dom/client";
import App from "./App.jsx";

const root = document.getElementById("admin-root");

if (!root) {
  throw new Error("Missing #admin-root mount element.");
}

createRoot(root).render(<App />);
