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
    <div className="max-w-xl mx-auto p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-3xl font-semibold mb-4 text-center text-gray-800">OWASP Top 10 Web Security Scanner</h2>

      <div className="mb-4">
        <input
          type="text"
          placeholder="Enter target URL"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div className="flex space-x-4 justify-center">
        <button
          onClick={handleScan}
          disabled={isLoading || scanCompleted}  
          className={`px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-300 ${isLoading || scanCompleted ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          {isLoading ? 
          (
            <span className="animate-spin">Loading.....</span> 
          ) 
          : 
          (
            "Start Scan"
          )
          }
        </button>

        {scanCompleted && (
          <button
            onClick={handleGetReport}
            className="px-6 py-2 bg-green-500 text-white rounded-lg hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-300"
          >
            Get Report
          </button>
        )}
      </div>

      <p className="mt-4 text-center text-gray-600">{message}</p>

      {report && (
        <div className="mt-6">
          <h3 className="text-2xl font-semibold text-gray-800 mb-2">Scan Report:</h3>
          <pre className="bg-gray-100 p-4 rounded-lg overflow-auto">{JSON.stringify(report, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

export default OWASPScan;