import React from "react";
import OWASPScan from "./components/OWASPScan";  

function App() {
  return (
    <div className="min-h-screen flex justify-center items-center bg-gray-200">
      <div className="w-full max-w-3xl p-8">
        <OWASPScan /> 
      </div>
    </div>
  );
}

export default App;