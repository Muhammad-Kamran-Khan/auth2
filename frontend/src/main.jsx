import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { UserContextProvider } from '../src/context/userContext';
import './index.css';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
      <App />
);
