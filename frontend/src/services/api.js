import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:8000',
    headers: {
        'Content-Type': 'application/json'
    }
});

export const arbiterApi = {
    createRound: () => api.post('/round/new'),
    getRoundStatus: (id) => api.get(`/round/${id}/status`),
    getPubKey: () => api.get('/arbiter/pubkey')
};

export default api;