import React from "react";
import OWASPScan from "./components/OWASPScan";
import './index.css'; 

function App() {
  return (
    <div className="bg-gradient-to-br from-blue-600 via-teal-400 to-green-500 min-h-screen flex justify-center items-center">
      <OWASPScan />
    </div>
  );
}

export default App;