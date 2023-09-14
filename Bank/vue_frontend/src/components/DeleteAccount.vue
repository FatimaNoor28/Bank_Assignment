<template>
  <div class="main">
    <nav class="navbar navbar-expand-lg navbar-light fixed-top"  style="   background-color: #7da4ad;">
      <router-link to="/homeAdmin" class="navbar-brand">XYZ Bank</router-link> <button aria-controls="navbarSupportedContent" aria-expanded="false"
          aria-label="Toggle navigation" class="navbar-toggler" data-target="#navbarSupportedContent"
          data-toggle="collapse" type="button"><span class="navbar-toggler-icon"></span></button>
        <div class="collapse navbar-collapse" id="navbarSupportedContent">
          <ul class="navbar-nav ml-auto">
            <li class="nav-item active">
              <router-link to="/homeAdmin" class="nav-link">Home</router-link>           
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
        <h1 class="text-center">Delete Account</h1>
        <form @submit.prevent="deleteAccount">
            <!-- Form fields here -->
            
            <div class="form-group">
                <label for="id">Enter Account ID:</label>
                <input type="text" id="id" v-model="id" class="form-control" required>
            </div>
            
            <!-- Other form fields -->
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
  </div>
</template>

<script>
import AccountService from '@/services/AccountService';

export default {
    name: 'DeleteAccount',
    data() {
        return {
            id: ''
        };
    },
    created() {
        this.deleteAccount();
        // this.editAccounts();
    },
    methods: {
        deleteAccount() {
            // const accountId = Number(this.id);
            // Call your backend service to make the transaction
            AccountService.deleteAccount(this.id)
                .then((response) => {
                    // Handle the response, e.g., show a success message
                    console.log('Account deleted:', response.data);
                    // Clear the form
                    this.id = ''
                })
                .catch((error) => {
                    // Handle errors, e.g., show an error message
                    console.error('Delete failed:', error);
                });
        }
    }
};
</script>


<style scoped>

.main{
  background-image: url('./images/money.jpg'); /* Specify the path to your background image */
  background-size: cover;
  background-position: center;
  color: #333; /* Text color on top of the background image */
  padding-top: 100px; 
}
.container {
    max-width: 30vw;
    margin: 0 auto;
    margin-top: 10vh;
    max-height: 60vh;
    border: 1px solid #ccc;
    border-radius: 2vw;
    box-shadow: 0 2vw 5vw rgba(0, 0, 0, 0.1);
    background-color: lightgrey;
    margin-bottom: 20vw;
}
/* .container {
    max-width: 400px;
    margin: 0 auto;
    margin-top: 70px;
    padding: 20px;
    border: 1px solid #ccc;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    background-color:lightgrey;
} */

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