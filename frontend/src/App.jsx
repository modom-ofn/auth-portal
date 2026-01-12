import adminShell from "./admin-shell.html?raw";

export default function App() {
  return <div dangerouslySetInnerHTML={{ __html: adminShell }} />;
}
