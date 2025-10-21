export const rules = [
  {
    id: "wildcard-action",
    severity: "high",
    detect: (policy) => {
      const issues = [];
      const statements = Array.isArray(policy.Statement)
        ? policy.Statement
        : [policy.Statement];
      statements.forEach((st, idx) => {
        const actions = Array.isArray(st.Action) ? st.Action : [st.Action];
        if (actions.some((a) => a === "*" || a.includes(":*"))) {
          issues.push({
            statementIndex: idx,
            message: "Wildcard action found — grants all actions (*).",
            detail: actions,
          });
        }
      });
      return issues;
    },
  },
  {
    id: "wildcard-resource",
    severity: "high",
    detect: (policy) => {
      const issues = [];
      const statements = Array.isArray(policy.Statement)
        ? policy.Statement
        : [policy.Statement];
      statements.forEach((st, idx) => {
        const resources = Array.isArray(st.Resource)
          ? st.Resource
          : [st.Resource];
        if (resources.some((r) => r === "*" || !r)) {
          issues.push({
            statementIndex: idx,
            message:
              "Wildcard resource found — apply resource-level restrictions.",
            detail: resources,
          });
        }
      });
      return issues;
    },
  },
  {
    id: "sensitive-actions",
    severity: "critical",
    detect: (policy) => {
      const issues = [];
      const sensitive = [
        "iam:PassRole",
        "iam:CreatePolicy",
        "iam:AttachRolePolicy",
      ];
      const statements = Array.isArray(policy.Statement)
        ? policy.Statement
        : [policy.Statement];
      statements.forEach((st, idx) => {
        const actions = Array.isArray(st.Action) ? st.Action : [st.Action];
        const found = actions.filter((a) => sensitive.includes(a));
        if (found.length > 0) {
          issues.push({
            statementIndex: idx,
            message: `Sensitive actions found: ${found.join(", ")}`,
            detail: actions,
          });
        }
      });
      return issues;
    },
  },
];
