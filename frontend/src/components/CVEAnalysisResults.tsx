import { FileSearch } from "lucide-react";
import type { CVE } from "../types";
import { Callout, date, Empty } from "./ui";
import { AnalysisResult } from "./AnalysisResult";

export function CVEAnalysisResults({
  cve,
  run,
  onRunChange,
}: {
  cve: CVE;
  run: string;
  onRunChange: (run: string) => void;
}) {
  const selected =
    cve.analyses.find((analysis) => analysis.id === run) || cve.analyses[0];
  if (!selected)
    return (
      <Empty
        icon={FileSearch}
        title="No CVE analysis yet"
        description="Choose Analyze CVE, review the execution profile, and start an analysis. The report and generated files will appear here."
      />
    );
  return (
    <div className="cve-results">
      <div className="analysis-run-toolbar">
        <label>
          Analysis run
          <select
            name="analysis_run"
            value={selected.id || "0"}
            onChange={(e) => onRunChange(e.target.value)}
          >
            {cve.analyses.map((analysis, index) => (
              <option
                key={analysis.id || index}
                value={analysis.id || String(index)}
              >
                {index === 0 ? "Latest · " : ""}
                {date(analysis.created_at)}
                {analysis.id
                  ? ` · ${analysis.id.slice(0, 8)}`
                  : ` · Run ${index + 1}`}
              </option>
            ))}
          </select>
        </label>
        <span className="hint">
          {cve.analyses.length}{" "}
          {cve.analyses.length === 1 ? "saved run" : "saved runs"} · Earlier
          output is preserved
        </span>
      </div>
      {run && !cve.analyses.some((analysis) => analysis.id === run) && (
        <Callout tone="warm" title="Requested run is unavailable">
          Showing the latest saved analysis. Refresh the CVE records to check
          for new output.
        </Callout>
      )}
      <AnalysisResult
        key={selected.id || selected.created_at}
        analysis={selected}
      />
    </div>
  );
}
