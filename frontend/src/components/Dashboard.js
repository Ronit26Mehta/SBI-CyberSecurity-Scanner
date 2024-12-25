import React, { useState } from 'react';

const Dashboard = () => {
    const [code, setCode] = useState('');
    const [results, setResults] = useState([]);

    const handleAnalyze = async () => {
        try {
            const response = await fetch('http://localhost:5000/dynamic-analysis', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: code }), 
            });
    
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
    
            const data = await response.json();
            setResults(data.results);
        } catch (error) {
            console.error('Error during fetch:', error);
            alert('Error during analysis. Check the console for details.');
        }
    };    

    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-100 p-6">
            <div className="w-full max-w-4xl bg-white rounded-lg shadow-xl p-8">
                <h1 className="text-4xl font-semibold text-gray-800 mb-6 text-center">Dynamic Code Analysis</h1>
                <textarea 
                    rows="10" 
                    cols="50" 
                    value={code} 
                    onChange={(e) => setCode(e.target.value)} 
                    placeholder="Paste your code here..."
                    className="w-full p-4 mb-6 border border-gray-300 rounded-lg text-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent"
                ></textarea>
                <div className="flex justify-center">
                    <button 
                        onClick={handleAnalyze} 
                        className="px-8 py-3 bg-green-500 text-white rounded-lg text-lg cursor-pointer hover:bg-green-600 transition duration-300 ease-in-out transform hover:scale-105"
                    >
                        Analyze
                    </button>
                </div>
                {results.length > 0 && (
                    <div className="mt-12">
                        <h2 className="text-3xl font-semibold text-gray-700 mb-4">Results:</h2>
                        <ul className="list-none p-0">
                            {results.map((issue, index) => (
                                <li key={index} className="mb-6 p-4 bg-gray-50 border-l-4 border-green-500 rounded-lg shadow-sm">
                                    <span className="font-semibold text-lg text-gray-800">Line {issue.line}: </span>
                                    <span className="font-medium text-green-600">{issue.type}</span> - {issue.description}
                                </li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Dashboard;