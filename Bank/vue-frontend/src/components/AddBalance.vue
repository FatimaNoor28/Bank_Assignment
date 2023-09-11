<template>
    <div class="container">
        <h1 class="text-center">Add Balance</h1>
        <form @submit.prevent="addBalance">
            <!-- Form fields here -->
            <div class="form-group">
                <label for="id">Balance ID</label>
                <input type="text" id="id" v-model="balance.id" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="account_id">Account ID</label>
                <input type="text" id="account_id" v-model="balance.account_id" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="amount">Amount</label>
                <input type="text" id="amount" v-model="balance.amount" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="db_CR">DB/CR</label>
                <input type="text" id="db_CR" v-model="balance.db_CR" class="form-control" required>
            </div>
            <!-- Other form fields -->
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
</template>

<script>
import BalanceService from '@/services/BalanceService';

export default {
    name: 'AddBalance',
    data() {
        return {
            balance: {
                account_id: '',
                id: '9999',
                amount: '',
                db_CR: '',
                date: ''
            }
        };
    },
    // created() {
    //     this.addBalance();
    //     // this.editAccounts();
    // },
    methods: {
        addBalance() {
            console.log("balance: ", this.balance)
            // Call your backend service to make the transaction
            BalanceService.createBalance(this.balance)
                .then((response) => {
                    // Handle the response, e.g., show a success message
                    console.log('Balance Added:', response.data);
                    // Clear the form
                    this.balance = {
                        account_id: '',
                        amount: '',
                        db_CR: '',
                        date: ''
                    };
                })
                .catch((error) => {
                    // Handle errors, e.g., show an error message
                    console.error('Balance failed:', error);
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
    background-color: #0056b3;
}

</style>