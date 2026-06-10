import axios from 'axios';

const API_URL = 'http://localhost:8080/api/v1';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add a request interceptor to add the auth token to requests
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add a response interceptor to handle common errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 || error.response?.status === 403) {
      // Clear local storage and redirect to login if token is invalid/expired
      localStorage.clear();
      window.location.href = '/';
    }
    return Promise.reject(error);
  }
);

// Auth APIs
export const login = (credentials) => api.post('/auth/login', credentials);
export const signup = (userData) => api.post('/auth/signup', userData);
export const forgotPassword = (email) => api.post('/auth/forgetP', { email });
export const changePassword = (data) => api.put('/auth/changeP', data);

// User APIs
export const getUserByEmail = (email) => api.get(`/user/email?email=${email}`);
export const updateUser = (userData) => api.put('/user', userData);

// News APIs
export const getNews = (page = 0, size = 10) => 
  api.get(`/news/all?pageNum=${page}&pageSize=${size}`);
export const getNewsByTitle = (title, page = 0, size = 10) => 
  api.get(`/news/title?title=${encodeURIComponent(title)}&pageNum=${page}&pageSize=${size}`);
export const getNewsByCategory = (category, page = 0, size = 10) => 
  api.get(`/news/category?category=${category}&pageNum=${page}&pageSize=${size}`);
export const getNewsById = (id) => api.get(`/news/id?id=${id}`);
export const createNews = (newsData) => api.post('/news', newsData);
export const updateNews = (newsData) => api.put('/news', newsData);
export const updateNewsList = (newsList) => api.put('/news/list', newsList);
export const deleteNews = (id) => api.delete(`/news?id=${id}`);

// Planes APIs
export const getPlanes = (page = 0, size = 10) => 
  api.get(`/plane/all?pageNum=${page}&pageSize=${size}`);
export const getPlaneByName = (name, page = 0, size = 10) => 
  api.get(`/plane/name?name=${encodeURIComponent(name)}&pageNum=${page}&pageSize=${size}`);
export const getPlaneById = (id) => api.get(`/plane/id?id=${id}`);
export const createPlane = (planeData) => api.post('/plane', planeData);
export const updatePlane = (planeData) => api.put('/plane', planeData);
export const deletePlane = (id) => api.delete(`/plane?id=${id}`);

// Seats APIs
export const getSeatsByPlane = (planeId) => api.get(`/seat/plane?planeId=${planeId}`);
export const getSeatById = (id) => api.get(`/seat/id?id=${id}`);
export const createSeat = (seatData) => api.post('/seat', seatData);
export const updateSeat = (seatData) => api.put('/seat', seatData);
export const deleteSeat = (id) => api.delete(`/seat?id=${id}`);

// Flights APIs
export const getFlights = (page = 0, size = 10) => 
  api.get(`/flight/all?pageNum=${page}&pageSize=${size}`);
export const getFlightById = (id) => api.get(`/flight/id?id=${id}`);
export const createFlight = (flightData) => api.post('/flight', flightData);
export const updateFlight = (flightData) => api.put('/flight', flightData);
export const deleteFlight = (id) => api.delete(`/flight?id=${id}`);
export const searchFlights = (searchTerm, dateFrom, dateTo, departure, arrival, page = 0, size = 10) => 
  api.get(`/flight/conditions?flightName=${encodeURIComponent(searchTerm)}&dateFrom=${dateFrom}&dateTo=${dateTo}&departure=${encodeURIComponent(departure)}&arrival=${encodeURIComponent(arrival)}&pageNum=${page}&pageSize=${size}`);
export const updateFlightDelay = (flightId, delayData) => 
  api.put(`/flight/${flightId}/delay`, delayData);
export const getFlightDelayHistory = (flightId) => 
  api.get(`/flight/${flightId}/delay-history`);
export const getFlightByConditions = (flightName, dateFrom, dateTo, departure, arrival, page = 0, size = 10 ) => 
  api.get(`/flight/conditions?flightName=${flightName}&dateFrom=${dateFrom}&dateTo=${dateTo}&departure=${departure}&arrival=${arrival}&pageNum=${page}&pageSize=${size}`);
// Transactions APIs
export const getTransactions = (page = 0, size = 10) => 
  api.get(`/transaction/all?pageNum=${page}&pageSize=${size}`);
export const getTransactionById = (id) => 
  api.get(`/transaction/id?id=${id}`);
export const getTransactionsByConditions = (flightName, dateFrom, dateTo, status, page = 0, size = 10) => 
  api.get(`/transaction/conditions?flightName=${encodeURIComponent(flightName)}&dateFrom=${dateFrom}&dateTo=${dateTo}&status=${status}&pageNum=${page}&pageSize=${size}`);
export const getTransactionsByStatus = (status) => 
  api.get(`/transaction/status?statusEnum=${status}`);
export const createTransaction = (transactionData) => 
  api.post('/transaction', transactionData);
export const updateTransaction = (transactionData) => 
  api.put('/transaction', transactionData);
export const updateTransactions = (transactionList) => 
  api.put('/transaction/list', transactionList);
export const deleteTransaction = (id) => 
  api.delete(`/transaction?id=${id}`);
export const getTransactionsByFlight = (flightId) => 
  api.get(`/transaction/flight?flightId=${flightId}`);

export const getUserById = (userId) => 
  api.get(`/user/id?id=${userId}`);

export default api; 