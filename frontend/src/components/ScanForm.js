import React, { useState } from "react";

const ScanForm = () => {
  const [inputType, setInputType] = useState("code");
  const [inputContent, setInputContent] = useState("");
  const [results, setResults] = useState([]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch("http://localhost:5000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: inputType, content: inputContent }),
      });
      const data = await response.json();
      setResults(data.results || []);
    } catch (error) {
      console.error("Error:", error);
    }
  };

  return (
    <div>
      <h1>OWASP Top 10 Vulnerability Scanner</h1>
      <form onSubmit={handleSubmit}>
        <label>
          Input Type:
          <select value={inputType} onChange={(e) => setInputType(e.target.value)}>
            <option value="code">Code</option>
            <option value="link">Website Link</option>
          </select>
        </label>
        <br />
        <label>
          Input Content:
          <textarea
            value={inputContent}
            onChange={(e) => setInputContent(e.target.value)}
            rows="5"
            cols="50"
          />
        </label>
        <br />
        <button type="submit">Scan</button>
      </form>
      <h2>Results:</h2>
      <ul>
        {results.map((result, index) => (
          <li key={index}>{result}</li>
        ))}
      </ul>
    </div>
  );
};

export default ScanForm;