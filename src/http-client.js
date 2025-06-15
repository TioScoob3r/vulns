import axios from 'axios';
import { HEADERS, TIMEOUT_MS } from './config.js';

// Create axios instance with default configuration
export const axiosInstance = axios.create({
  timeout: TIMEOUT_MS,
  headers: HEADERS,
  validateStatus: status => status < 500, // Accept all status codes < 500
  maxRedirects: 5
});