<template>
    <nav class="navbar navbar-expand-lg navbar-light fixed-top">
      <div class="container-fluid" style="   background-color: #7da4ad;">
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
      </div>
    </nav>
    <div class="container">

        <h1 class="text-center"> Accounts List</h1>

        <table class="table table-striped table-dark">
            <thead>
                <tr>
                    <th> Account Id</th>
                    <th> Name</th>
                    <th> Password</th>
                    <th> Email</th>
                    <th> Address</th>
                </tr>

            </thead>
            <tbody>
                <tr v-for="Account in Accounts" v-bind:key="Account.id">
                    <td> {{ Account.id }}</td>
                    <td> {{ Account.name }}</td>
                    <td> {{ Account.password }}</td>
                    <td> {{ Account.email }}</td>
                    <td> {{ Account.address }}</td>
                </tr>
            </tbody>
        </table>
    </div>
</template>

<script>
import AccountService from '../services/AccountService';

export default {
    name: 'AccountsList',
    data() {
        return {
            Accounts: {},
            Account: {
                id: '',
                name: '',
                password: '',
                email: '',
                address: ''
            }
        }
    },
    created() {
        this.getAccounts();
        // this.editAccounts();
    },
    mounted() {
        console.log("mounted() called.......");

    },
    methods: {
        getAccounts() {
            AccountService.getAccounts().then((response) => {
                console.log("response obtained: ", response);
                this.Accounts = response.data;
            });
        },
        
    }
}
</script>

<style scoped>
 .container {
    padding: 20px;
    padding-top: 70px;
  }
.navbar-light .navbar-brand {
  color: #fff;
  font-size: 25px;
  text-transform: uppercase;
  font-weight: bold;
  letter-spacing: 2px;
}

.navbar-light .navbar-nav .active>.nav-link,
.navbar-light .navbar-nav .nav-link.active,
.navbar-light .navbar-nav .nav-link.show,
.navbar-light .navbar-nav .show>.nav-link {
  color: #fff;

}

.navbar-light .navbar-nav .nav-link {
  color: #fff;
}

.navbar-toggler {
  color: #7da4ad;
}

.navbar-nav {
  text-align: center;
}

.nav-link {
  padding: .2rem 1rem;
}

.nav-link.active,
.nav-link:focus {
  color: #7da4ad;

}

.navbar-toggler {
  padding: 1px 5px;
  font-size: 18px;
  line-height: 0.3;
}

.navbar-light .navbar-nav .nav-link:focus,
.navbar-light .navbar-nav .nav-link:hover {
  color: #7da4ad;
}
</style>