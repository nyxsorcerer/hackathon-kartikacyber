Audit phases MUST follow the supplied pinned Trail of Bits skill and supporting resources; orientation selects bounded significant functions, function phase analyzes assumptions/invariants/dependencies, synthesis includes missing/failed units.

Orientation lists functions most significant first and selects at most max_functions; Numen analyses them in that order and records any beyond the limit as deferred.
{% if facts.coverage.refresh %}

This synthesis refreshes the context built at revision {{ facts.coverage.refresh.from_revision }}. Orientation was reused, functions whose own file is unchanged keep their earlier documents, functions in changed files were analysed again, and functions whose file was deleted are listed in coverage as removed. {{ facts.coverage.refresh.changed_files_total }} files changed between the two revisions; facts.coverage.refresh.changed_files lists them. Update the dossier for those changes, including changes outside the selected functions, and say which parts may be outdated.
{% endif %}
