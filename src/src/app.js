import { rules } from "./rules.js";

document.getElementById("scanBtn").addEventListener("click", () => {
  const text = document.getElementById("policyInput").value;
  const resultsDiv = document.getElementById("results");
  resultsDiv.innerHTML = "";

  let policy;
  try {
    policy = JSON.parse(text);
  } catch (e) {
    resultsDiv.innerHTML = '<p style="color:red;">Invalid JSON.</p>';
    return;
  }

  const findings = [];
  rules.forEach((rule) => {
    const issues = rule.detect(policy);
    issues.forEach((issue) =>
      findings.push({ ...issue, ruleId: rule.id, severity: rule.severity })
    );
  });

  if (findings.length === 0) {
    resultsDiv.innerHTML =
      '<p style="color:green;">✅ No major issues found.</p>';
    return;
  }

  findings.forEach((f) => {
    const div = document.createElement("div");
    div.className = `issue severity-${f.severity}`;
    div.innerHTML = `
      <p><strong>[${f.severity.toUpperCase()}]</strong> ${f.message}</p>
      <pre>${JSON.stringify(f.detail, null, 2)}</pre>
    `;
    resultsDiv.appendChild(div);
  });
});
