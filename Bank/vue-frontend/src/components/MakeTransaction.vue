<template>
    <div class="container">
        <h1 class="text-center">Make Transaction</h1>
        <form @submit.prevent="MakeTransaction">
            <!-- Form fields here -->
            <div class="form-group">
                <label for="id">Transaction ID</label>
                <input type="text" id="id" v-model="transaction.id" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="account_id">Account ID</label>
                <input type="text" id="account_id" v-model="transaction.account_id" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="description">Description</label>
                <input type="text" id="description" v-model="transaction.description" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="amount">Amount</label>
                <input type="text" id="amount" v-model="transaction.amount" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="db_CR">DB/CR</label>
                <input type="text" id="db_CR" v-model="transaction.db_CR" class="form-control" required>
            </div>
            <!-- Other form fields -->
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
</template>

<script>
import TransactionService from '../services/TransactionService';

export default {
    name: 'MakeTransaction',
    data() {
        return {
            transaction: {
                id: '9999',
                account_id: '',
                description: '',
                amount: '',
                db_CR: '',
                date: '2000-01-01'
            }
        };
    },
    // created() {
    //     this.MakeTransaction();
    //     // this.editAccounts();
    // },
    methods: {
        MakeTransaction() {
            // Call your backend service to make the transaction
            TransactionService.makeTransaction(this.transaction)
            
                .then((response) => {
                    // Handle the response, e.g., show a success message
                    console.log('Transaction successful:', response.data);
                    // Clear the form
                    this.transaction = {
                        account_id: '',
                        description: '',
                        amount: '',
                        db_CR: '',
                        date: ''
                    };
                })
                .catch((error) => {
                    // Handle errors, e.g., show an error message
                    console.error('Transaction failed:', error);
                });
        }
    }
};
</script>


<style scoped>
/* AddBalanceForm.css */

.container {
    max-width: 400px;
    margin: 0 auto;
    padding: 20px;
    border: 1px solid #ccc;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    background-color:lightgrey;
}

h1 {
    text-align: center;
    margin-bottom: 20px;
    font-weight: bold;
    color: #333;
}

.form-group {
    margin-bottom: 20px;
}

label {
    font-weight: bold; /* Make the label text bold */
    color: #333; /* Change the label text color */
}

.form-control {
    width: 100%;
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
    font-size: 16px;
}

.btn-primary {
    background-color:#333;
    color: #fff;
    border: none;
    border-radius: 5px;
    padding: 10px 20px;
    font-size: 16px;
    cursor: pointer;
}

.btn-primary:hover {
    background-color: darkseagreen;
}

</style>