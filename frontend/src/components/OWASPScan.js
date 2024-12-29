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
      setMessage("Scan started, please wait for the report.");
      
      await axios.post("http://localhost:5000/scan", { target_url: targetUrl });
      
      setScanCompleted(true);  
      setMessage("Scan completed. You can now generate the report.");
    } catch (error) {
      setMessage("Error starting scan.");
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
      console.error("Error fetching report:", error);  
      setMessage("Error fetching report.");
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-8 bg-white rounded-lg shadow-xl">
<h1 className="text-5xl font-extrabold text-center mb-8 text-gradient bg-gradient-to-r from-blue-600 via-teal-500 to-green-600 text-transparent bg-clip-text leading-normal">
  OWASP Web Security Scanner
</h1>

      <div className="mb-6">
        <input
          type="text"
          placeholder="Enter target URL"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="w-full p-4 text-lg border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div className="flex justify-center items-center space-x-6">
        <button
          onClick={handleScan}
          disabled={isLoading || scanCompleted}  
          className={`px-8 py-3 text-lg text-white font-semibold rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-300 
            ${isLoading || scanCompleted ? 'opacity-50 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'}`}
        >
          {isLoading ? 
            <div className="flex justify-center items-center">
              <div className="loader"></div>
              <span className="ml-2">Scanning...</span>
            </div> : "Start Scan"
          }
        </button>

        {scanCompleted && (
          <button
            onClick={handleGetReport}
            className="px-8 py-3 text-lg text-white font-semibold rounded-lg bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-300"
          >
            Get Report
          </button>
        )}
      </div>

      <p className="mt-6 text-center text-gray-600">{message}</p>

      {report && (
        <div className="mt-8 space-y-6">
          <div className="bg-gray-100 p-6 rounded-lg shadow-md">
            <h3 className="text-2xl font-semibold text-gray-800 mb-4">Scan Summary</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-blue-100 rounded-lg shadow-md">
                <h4 className="text-xl font-medium text-blue-600">Critical</h4>
                <p className="text-lg font-bold">{report.summary.critical}</p>
              </div>
              <div className="p-4 bg-red-100 rounded-lg shadow-md">
                <h4 className="text-xl font-medium text-red-600">High</h4>
                <p className="text-lg font-bold">{report.summary.high}</p>
              </div>
              <div className="p-4 bg-yellow-100 rounded-lg shadow-md">
                <h4 className="text-xl font-medium text-yellow-600">Medium</h4>
                <p className="text-lg font-bold">{report.summary.medium}</p>
              </div>
              <div className="p-4 bg-green-100 rounded-lg shadow-md">
                <h4 className="text-xl font-medium text-green-600">Low</h4>
                <p className="text-lg font-bold">{report.summary.low}</p>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-2xl font-semibold text-gray-800 mb-4">Findings</h3>
            {report.findings.map((finding, index) => (
              <div key={index} className="mb-4 p-4 bg-gray-50 rounded-lg shadow-md">
                <h4 className="text-xl font-semibold text-gray-800">{finding.type}</h4>
                <p className="text-sm text-gray-500">Severity: <span className={`font-bold ${finding.severity === 'Critical' ? 'text-red-500' : 'text-yellow-500'}`}>{finding.severity}</span></p>
                <p className="mt-2">{finding.description}</p>
                <p className="mt-2 text-gray-700 font-semibold">Recommendation:</p>
                <p>{finding.recommendation}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default OWASPScan;