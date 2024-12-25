import React, { useState } from 'react';

const Dashboard = () => {
    const [code, setCode] = useState('');
    const [results, setResults] = useState([]);

    const handleAnalyze = async () => {
        const response = await fetch('http://localhost:5000/static-analysis', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code }),
        });
        const data = await response.json();
        setResults(data.results);
    };

    return (
        <div style={styles.container}>
            <h1 style={styles.title}>Static Code Analysis</h1>
            <textarea 
                rows="10" 
                cols="50" 
                value={code} 
                onChange={(e) => setCode(e.target.value)} 
                placeholder="Paste your code here..."
                style={styles.textarea}
            ></textarea>
            <button onClick={handleAnalyze} style={styles.button}>Analyze</button>
            <h2 style={styles.resultsTitle}>Results:</h2>
            <ul style={styles.resultsList}>
                {results.map((issue, index) => (
                    <li key={index} style={styles.issueItem}>
                        Line {issue.line}: {issue.type} - {issue.description}
                    </li>
                ))}
            </ul>
        </div>
    );
};

const styles = {
    container: {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        textAlign: 'center',
    },
    title: {
        marginBottom: '20px',
        fontSize: '2rem',
    },
    textarea: {
        marginBottom: '20px',
        padding: '10px',
        fontSize: '1rem',
        width: '80%',
        maxWidth: '600px',
        borderRadius: '5px',
        border: '1px solid #ccc',
    },
    button: {
        padding: '10px 20px',
        backgroundColor: '#4CAF50',
        color: 'white',
        border: 'none',
        borderRadius: '5px',
        cursor: 'pointer',
        fontSize: '1rem',
    },
    resultsTitle: {
        marginTop: '30px',
        fontSize: '1.5rem',
    },
    resultsList: {
        listStyleType: 'none',
        paddingLeft: '0',
    },
    issueItem: {
        margin: '10px 0',
        fontSize: '1rem',
    },
};

export default Dashboard;