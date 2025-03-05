import { Line } from "react-chartjs-2"  ;
import { useState, useEffect } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

type Dataset = {
  label: string;
  data: number[];
  borderColor: string;
  fill: boolean;
};

const Dashboard = () => {
  const [data, setData] = useState<{ labels: string[]; datasets: Dataset[] }>({
    labels: [],
    datasets: [],
  });

  useEffect(() => {
    // Fetch data from API
    fetch('/api/data')
      .then(response => response.json())
      .then(data => {
        setData({
          labels: data.labels,
          datasets: [
            {
              label: 'Blocked',
              data: data.blocked,
              borderColor: 'rgba(75,192,192,1)',
              fill: false,
            },
            {
              label: 'Allowed',
              data: data.allowed,
              borderColor: 'rgba(153,102,255,1)',
              fill: false,
            },
            // Add more datasets as needed
          ],
        });
      });
  }, []);

  return (
    <div>
      <h2>Dashboard</h2>
      <Line data={data} />
    </div>
  );
};

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
      <div>
        <a href="https://vite.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
      <Dashboard />
    </>
  )
}

export default App
