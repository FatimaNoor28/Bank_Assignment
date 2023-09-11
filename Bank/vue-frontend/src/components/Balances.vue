<template>
    <div class="container">

        <h1 class="text-center"> Balance List</h1>

        <table class="table table-striped table-dark">
            <thead>
                <tr>
                    <th> Balance Id</th>
                    <th> Account Id</th>
                    <th> Amount</th>
                    <th> DB/CR</th>
                    <th> Date</th>
                </tr>

            </thead>
            <tbody>
                <tr v-for="Balance in Balances" v-bind:key="Balance.id">
                    <td> {{ Balance.id }}</td>
                    <td> {{ Balance.account_id }}</td>
                    <td> {{ Balance.amount }}</td>
                    <td> {{ Balance.db_CR }}</td>
                    <td> {{ Balance.date }}</td>
                </tr>
            </tbody>
        </table>
    </div>
</template>

<script>
import BalanceService from '../services/BalanceService';

export default {
    name: 'BalanceList',
    data() {
        return {
            Balances: {},
            Balance: {
                id: '',
                account_id: '',
                amount: '',
                db_CR: '',
                date: ''
            }
        }
    },
    created() {
        this.getBalance();
        // this.editAccounts();
    },
    mounted() {
        console.log("mounted() called.......");

    },
    methods: {
        getBalance() {
            BalanceService.getBalance().then((response) => {
                this.Balances = response.data;
            });
        },
        
    }
}
</script>