import { useRef, useState } from "react";
import { Upload } from "lucide-react";
import { request } from "../api";
import { accountSchema } from "../types";
import type { Account } from "../types";
import { ErrorNote, Modal, notify } from "./ui";
const MAX_CACHE_BYTES = 1024 * 1024;
class NativeFileError extends Error {}
function validateFileSize(file: File) {
  if (file.size > MAX_CACHE_BYTES)
    throw new NativeFileError("Choose a JSON file no larger than 1 MiB.");
  if (file.size === 0)
    throw new NativeFileError("Select a nonempty native-session JSON file.");
}
function validateSessionJson(file: File): Promise<void> {
  return new Promise((resolve, reject) => {
    const reader = new window.FileReader();
    reader.onload = () => {
      try {
        if (typeof reader.result !== "string") throw new NativeFileError();
        const value: unknown = JSON.parse(reader.result);
        if (typeof value !== "object" || value === null || Array.isArray(value))
          throw new NativeFileError();
        resolve();
      } catch {
        reject(new NativeFileError("Select a valid native-session JSON file."));
      }
    };
    reader.onerror = () =>
      reject(
        new NativeFileError(
          "The selected file could not be read. Select it again.",
        ),
      );
    reader.onabort = () =>
      reject(
        new NativeFileError(
          "The selected file could not be read. Select it again.",
        ),
      );
    reader.readAsText(file);
  });
}
export function NativeCacheImport({
  account,
  onClose,
  refresh,
}: {
  account: Account;
  onClose: () => void;
  refresh: () => void;
}) {
  const [file, setFile] = useState<File>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const input = useRef<HTMLInputElement>(null);
  function clearFile() {
    setFile(undefined);
    if (input.current) input.current.value = "";
  }
  return (
    <Modal
      title={`${account.label} — import native session`}
      description="Native-session credentials are write-only. The file contents are never previewed."
      onClose={() => {
        if (!busy) onClose();
      }}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          if (!file || busy) return;
          setBusy(true);
          setError(undefined);
          try {
            validateFileSize(file);
            await validateSessionJson(file);
            const body = new FormData();
            body.append("file", file);
            await request(
              `/accounts/${encodeURIComponent(account.id)}/native-cache`,
              accountSchema,
              { method: "POST", body },
            );
            clearFile();
            notify("Native session imported. Run Check to validate access.");
            refresh();
            onClose();
          } catch (cause) {
            clearFile();
            setError(
              cause instanceof NativeFileError
                ? cause.message
                : "The native session could not be imported. Check the file format and try again.",
            );
          } finally {
            setBusy(false);
          }
        }}
      >
        <label>
          Native-session JSON file
          <input
            ref={input}
            type="file"
            accept=".json,application/json"
            disabled={busy}
            onChange={(event) => {
              setError(undefined);
              const selected = event.target.files?.[0];
              if (!selected) {
                clearFile();
                return;
              }
              try {
                validateFileSize(selected);
                setFile(selected);
              } catch (cause) {
                clearFile();
                setError(
                  cause instanceof NativeFileError
                    ? cause.message
                    : "Select a valid native-session JSON file.",
                );
              }
            }}
          />
        </label>
        <p className="hint">
          {account.provider === "claude"
            ? "Select .credentials.json from your native Claude login, or a credentials_json wrapper. The Claude native-login option remains available."
            : account.provider === "commandcode"
              ? "Select auth.json from pi (~/.pi/agent/auth.json) or the Command Code CLI (~/.commandcode/auth.json). The Command Code native-login option remains available."
              : "Select auth.json from your native Codex login, or an auth_json wrapper. The Codex device-login option remains available."}{" "}
          Maximum file size: 1 MiB.
        </p>
        <p className="hint">
          Import saves the session to the protected credential vault. A separate
          Check validates subscription access and refreshes available models.
        </p>
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="form-actions">
          <button
            className="secondary"
            type="button"
            disabled={busy}
            onClick={onClose}
          >
            Cancel
          </button>
          <button className="primary" disabled={!file || busy}>
            <Upload size={15} />
            {busy ? "Importing…" : "Import session"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
