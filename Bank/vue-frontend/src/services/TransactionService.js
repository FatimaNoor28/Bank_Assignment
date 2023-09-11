import axios from 'axios';

const TRANSACTION_API_BASE_URL = '/api/v1/transaction';

class TransactionService{

    getTransactions(){
        return axios.get(TRANSACTION_API_BASE_URL);
    }
    getTransactionByAccountId(accountId){
        return axios.get(`${TRANSACTION_API_BASE_URL}/${accountId}`);
    }
    makeTransaction(transactionData){
        return axios.post(TRANSACTION_API_BASE_URL, transactionData);
    }
}

export default new TransactionService();