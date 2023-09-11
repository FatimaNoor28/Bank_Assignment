<template>
    <div class="container">

        <h1 class="text-center"> Transactions List</h1>

        <table class="table table-striped table-dark">
            <thead>
                <tr>
                    <th> Transaction Id</th>
                    <th> Account Id</th>
                    <th> Description</th>
                    <th> Amount</th>
                    <th> DB/CR</th>
                    <th> Date</th>
                </tr>

            </thead>
            <tbody>
                <tr v-for="Transaction in Transactions" v-bind:key="Transaction.id">
                    <td> {{ Transaction.id }}</td>
                    <td> {{ Transaction.account_id }}</td>
                    <td> {{ Transaction.description }}</td>
                    <td> {{ Transaction.amount }}</td>
                    <td> {{ Transaction.db_cr }}</td>
                    <td> {{ Transaction.date }}</td>
                </tr>
            </tbody>
        </table>
    </div>
</template>

<script>
import TransactionService from '../services/TransactionService';

export default {
    name: 'TransactionsList',
    data() {
        return {
            Transactions: {},
            Transaction: {
                id: '',
                account_id: '',
                description: '',
                amount: '',
                db_cr: '',
                date: ''
            }
        }
    },
    created() {
        this.getTransactions();
        // this.editAccounts();
    },
    mounted() {
        console.log("mounted() called.......");

    },
    methods: {
        getTransactions() {
            TransactionService.getTransactions().then((response) => {
                this.Transactions = response.data;
            });
        },
        
    }
}
</script>