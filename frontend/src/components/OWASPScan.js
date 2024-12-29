import React, { useState } from "react";
import axios from "axios";

function OWASPScan() {
  const [targetUrl, setTargetUrl] = useState("");
  const [message, setMessage] = useState("");
  const [report, setReport] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [scanCompleted, setScanCompleted] = useState(false);

  const handleScan = async () => {
    try {
      setIsLoading(true);
      setMessage("Scan started. Please wait...");
      await axios.post("http://localhost:5000/scan", { target_url: targetUrl });
      setScanCompleted(true);
      setMessage("Scan completed! You can now generate the report.");
    } catch (error) {
      setMessage("Error starting the scan.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleGetReport = async () => {
    try {
      setMessage("Fetching the report...");
      const response = await axios.get("http://localhost:5000/report");
      setReport(response.data);
    } catch (error) {
      setMessage("Error fetching the report.");
    }
  };

  return (
    <div className="min-h-screen flex justify-center items-center bg-gradient-to-r from-blue-500 to-green-500 p-6">
      <div className="w-full max-w-2xl bg-white rounded-xl shadow-lg p-8">
        <h1 className="text-4xl font-bold text-gray-800 text-center mb-6">
          OWASP Web Security Scanner
        </h1>

        <div className="mb-6">
          <input
            type="text"
            placeholder="Enter target URL"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="w-full p-4 text-lg border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        <div className="flex items-center justify-center space-x-4">
          <button
            onClick={handleScan}
            disabled={isLoading || scanCompleted}
            className={`relative px-8 py-3 text-lg font-semibold text-white bg-blue-600 rounded-lg shadow-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-300 ${
              isLoading || scanCompleted
                ? "opacity-50 cursor-not-allowed"
                : ""
            }`}
          >
            {isLoading ? (
              <div className="loader absolute inset-0 mx-auto my-auto"></div>
            ) : (
              "Start Scan"
            )}
          </button>

          {scanCompleted && (
            <button
              onClick={handleGetReport}
              className="px-8 py-3 text-lg font-semibold text-white bg-green-600 rounded-lg shadow-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-300"
            >
              Get Report
            </button>
          )}
        </div>

        <p className="mt-4 text-center text-gray-600">{message}</p>

        {report && (
          <div className="mt-8 bg-gray-100 p-6 rounded-lg shadow-inner">
            <h2 className="text-2xl font-bold text-gray-800 mb-4">
              Scan Report
            </h2>
            <pre className="text-sm text-gray-700 overflow-auto">
              {JSON.stringify(report, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

export default OWASPScan;