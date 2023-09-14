<template>
    <nav class="navbar navbar-expand-lg navbar-light fixed-top" style="   background-color: #7da4ad;">
        <a class="navbar-brand" href="#">Mouri</a> <button aria-controls="navbarSupportedContent" aria-expanded="false"
          aria-label="Toggle navigation" class="navbar-toggler" data-target="#navbarSupportedContent"
          data-toggle="collapse" type="button"><span class="navbar-toggler-icon"></span></button>
        <div class="collapse navbar-collapse" id="navbarSupportedContent">
          <ul class="navbar-nav ml-auto">
            <li class="nav-item active">
              <router-link to="/" class="nav-link">Home</router-link>           
            </li>
            <li class="nav-item">
              <router-link to="/about" class="nav-link">About</router-link>           
            </li>
            <li class="nav-item">
              <a class="nav-link" href="#">Portfolio</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="#">Services</a>
            </li>
            <li class="nav-item">
              <router-link to="/contact" class="nav-link">Contact</router-link>
            </li>
          </ul>
        </div>
    </nav>
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