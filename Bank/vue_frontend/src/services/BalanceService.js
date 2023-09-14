import axios from 'axios';

const BALANCE_API_BASE_URL = '/api/v1/balance';

class BalanceService {

    getBalance() {
        return axios.get(BALANCE_API_BASE_URL);
    }
    getBalanceByAccountId(accountId) {
        return axios.get(`${BALANCE_API_BASE_URL}/${accountId}`);
    }
    createBalance(balance) {
        console.log('Balance object before sending:', balance);

        return axios.post(BALANCE_API_BASE_URL, balance);
    }

}

export default new BalanceService();