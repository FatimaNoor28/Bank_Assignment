<template>
    <div class="container">
        <h1 class="text-center">View Account</h1>
        <div v-if="Account" class="card">
            <div class="card-body container" style="height:9cm;">
                <h5 class="card-title" style="font-family: 'Times New Roman', Times, serif; font-size: 27px;">Account
                    Information</h5>
                <p class="card-text"><strong>Account ID:</strong> {{ Account.id }}</p>
                <p class="card-text"><strong>Name:</strong> {{ Account.name }}</p>
                <p class="card-text"><strong>Email:</strong> {{ Account.email }}</p>
                <p class="card-text"><strong>Address:</strong> {{ Account.address }}</p>

                <div style=" margin-top:-1.4cm;">

                    <button @click="viewBalance" class="btn btn-primary"
                        style=" outline-color: rgb(82, 54, 20);  margin-left:1cm; margin-top:2cm; height:1.5cm; width:5cm; background-color: darkseagreen; font-size:21px; font-family:'Times New Roman', Times, serif">View
                        Balance</button>
                    <button @click="viewTransactions" class="btn btn-primary"
                        style="margin-left:1cm;margin-top:2cm; height:1.5cm; width:5cm;  background-color: darkseagreen;font-size:21px; font-family:'Times New Roman', Times, serif">View
                        Transactions</button>
                </div>
            </div>
            <!-- Display balance card when showBalance is true -->
            <div v-if="showBalance" class="container mt-3">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title" style=" font-family: 'Times New Roman', Times, serif; ">Balance</h2>
                        <!-- Display balance information here -->
                        <p class="card-text"><strong>Balance ID:</strong> {{ Balance.id }}</p>
                        <p class="card-text"><strong>Amount:</strong> {{ Balance.amount }}</p>
                        <p class="card-text"><strong>DB/CR:</strong> {{ Balance.db_CR }}</p>
                        <p class="card-text"><strong>Date:</strong> {{ Balance.date }}</p>
                    </div>
                </div>
            </div>

            <!-- Display transaction card when showTransactions is true -->
            <div v-if="showTransactions" class="container mt-3">
                <div class="card">
                    <div class="card-body">
                        <h2 class="card-title" style=" font-family: 'Times New Roman', Times, serif; ">Transactions</h2>
                        <!-- Display transaction details here -->
                        <!-- <p class="card-text"><strong>Transaction ID:</strong> {{ Transaction.id }}</p>
                        <p class="card-text"><strong>Description:</strong> {{ Transaction.description }}</p>
                        <p class="card-text"><strong>Amount:</strong> {{ Transaction.amount }}</p>
                        <p class="card-text"><strong>DB/CR:</strong> {{ Transaction.db_cr }}</p>
                        <p class="card-text"><strong>Date:</strong> {{ Transaction.date }}</p> -->
                        <table class="table table-striped table-dark">
                            <thead>
                                <tr>
                                    <th class="card-text"> Transaction Id</th>
                                    <th class="card-text"> Description</th>
                                    <th class="card-text"> Amount</th>
                                    <th class="card-text"> DB/CR</th>
                                    <th class="card-text"> Date</th>
                                </tr>

                            </thead>
                            <tbody>
                                <tr v-for="Transaction in Transactions" v-bind:key="Transaction.id">
                                    <td class="card-text"> {{ Transaction.id }}</td>
                                    <td class="card-text"> {{ Transaction.description }}</td>
                                    <td class="card-text"> {{ Transaction.amount }}</td>
                                    <td class="card-text"> {{ Transaction.db_CR }}</td>
                                    <td class="card-text"> {{ Transaction.date }}</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        <div v-else>
            <p>Loading account information...</p>
        </div>

        <!-- Display balance and transaction details here when clicked -->
        <div v-if="showBalance" class="card mt-3">
            <div class="card-body">
                <h5 class="card-title">Balance</h5>
                <!-- Add code to display balance information -->
            </div>
        </div>

        <div v-if="showTransactions" class="card mt-3">
            <div class="card-body">
                <h5 class="card-title">Transactions</h5>
                <!-- Add code to display transaction details -->
            </div>
        </div>
    </div>
</template>

  
<script>
import BalanceService from '@/services/BalanceService';
import AccountService from '../services/AccountService';
import TransactionService from '@/services/TransactionService';

export default {
    name: 'ViewAccount',
    computed: {
        userName() {
            return this.$store.state.userName; // Access userName from the store
        },
        password() {
            return this.$store.state.password; // Access password from the store
        },
    },
    data() {
        return {
            Account: {
                id: '',
                name: '',
                password: '',
                email: '',
                address: ''
            },
            Balance: {
                id: '',
                account_id: '',
                amount: '',
                db_CR: '',
                date: ''
            },
            Transactions: {},
            Transaction: {
                id: '',
                account_id: '',
                description: '',
                amount: '',
                db_CR: '',
                date: ''
            },
            User: {
                userName: '',
                password: ''
            },
            // userName: null,
            showBalance: false,
            showTransactions: false,
        };
    },
    created() {
        this.getAccount();
    },
    methods: {
        getAccount() {
            // Retrieve the account ID from the route parameter
            // const userName = this.$route.params.userName;
            this.User.userName = this.userName;
            this.User.password = this.password;
            // const userName = this.$store.state.userName;
            // const password = this.$store.state.password;
            console.log("VIEW ACCOUNT BY ", this.User.userName)
            console.log(`User Name: ${this.User.userName}`);
            console.log(`Password: ${this.User.password}`);
            // Fetch account details based on the account ID
            AccountService.getAccountByNameAndPassword(this.User).then((response) => {
                this.Account = response.data;
            }).catch((error) => {
                console.error("Error fetching account details:", error);
                // You can display an error message to the user or take appropriate action.
            });
        },
        viewBalance() {
            // Toggle the balance view
            BalanceService.getBalanceByAccountId(this.Account.id)
                .then((response) => {
                    this.Balance = response.data; // Update Balance data
                })
                .catch((error) => {
                    console.error("Error fetching balance details:", error);
                });
            this.showBalance = !this.showBalance;
            this.showTransactions = false; // Hide transaction details
        },
        viewTransactions() {
            // Toggle the transaction view
            TransactionService.getTransactionByAccountId(this.Account.id)
                .then((response) => {
                    this.Transactions = response.data; // Update Transaction data
                })
                .catch((error) => {
                    console.error("Error fetching transaction details:", error);
                });
            this.showTransactions = !this.showTransactions;
            this.showBalance = false; // Hide balance
        },
    },
};
</script>

<style>
.card-text,
card-title {
    font-family: 'Times New Roman', Times, serif;
    font-size: 21px;
}

button:hover {
    background-color: #555;
    
  }
</style>