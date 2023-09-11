<template>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bank XYZ</title>
        <link rel="stylesheet" href="styles.css">
    </head>

    <body>
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
        <div class="row container">
            <div class="col-sm-4" id="formLogin">
                <h2 align="center"> Login</h2>

                <form @submit.prevent="LoginData">


                    <div class="form-group" align="left">
                        <label>User Name</label>
                        <input type="name" v-model="user.userName" class="form-control" placeholder="User Name"
                            align="center">
                    </div>


                    <div class="form-group" align="left">
                        <label>Password</label>
                        <input type="password" v-model="user.password" class="form-control" placeholder="Password"
                            align="center">
                    </div>
                    <br />

                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </div>

    </body>
</template>
   
<script>
//    import Vue from 'vue';
//    import axios from 'axios';
import LoginService from '../services/LoginService';

//  Vue.use(axios)
export default {
    name: 'LoginDetail',
    data() {
        return {
            roles: '',
            result: {
                message: '',
                status: false
            },
            user: {
                userName: '',
                password: ''
            }
        }
    },
    methods: {
        async LoginData() {

            // const userName = this.user.userName;
            // const password = this.user.password;

            //     // Set userName and password in the store
            // this.$store.commit("setUserName", userName);
            // this.$store.commit("setPassword", password);
            try {
                const response = await LoginService.getLogin(this.user);
                this.$store.commit("setUserName", this.user.userName); // Set userName in the store
                this.$store.commit("setPassword", this.user.password); // Set userName in the store
                
                console.log("Response from server:", response);
                this.roles = await LoginService.getRoles(this.user.userName).then(response => {return response.data;  }).catch(error => { throw error; });
                console.log(this.user.userName);
                console.log(this.user.password);
                console.log(this.roles);
                if (this.roles === "ADMIN"){
                    console.log('Role is ADMIN');
                    this.$router.push({ name: "HomeAdmin" }) //, params: { userName: this.user.userName } 
                } 
                else if (this.roles === "ACCOUNT_HOLDER"){
                    console.log('Role is ACCOUNT_HOLDER');
                    this.$router.push({ name: "HomeUser" }) //, params: { userName: this.user.userName }
                }
                else {
                    console.error('Role is neither ADMIN nor ACCOUNT_HOLDER');
                    console.error('Error! Status:', response.status);
                    alert("Username or password incorrect! Not Authenticated!!");
                    this.result.status = false;
                }
            }
            catch (error) {
                console.error("An error occurred:", error);
                alert("Error: Unable to complete the request. Please try again later.");
                this.result.status = false;
            }
        },
        created() {
            this.LoginData();
        },
    }
}
</script>


<style scoped>
/* styles.css */

h2 {
    text-align: center;
    margin-bottom: 20px;
    font-weight: bold;
    color: #333;
}

#formLogin {
    background-color: lightgrey;

}

label {
    font-weight: bold;
    /* Make the label text bold */
    color: #333;
    /* Change the label text color */
}

/* Center the form horizontally */
.col-sm-4 {
    margin: 0 auto;
    text-align: center;
    padding-top: 50px;
    padding-bottom: 50px;
}

.container {
    max-width: 400px;
    margin: 0 auto;
    /* padding: 20px; */
    border: 1px solid #ccc;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    background-color: lightgrey;
    margin-bottom: 50px;
}

/* Style the form container */
.form-group {
    margin-bottom: 20px;

}

/* Style the labels */
label {
    font-weight: bold;
}

/* Style the input fields */
.form-control {
    width: 100%;
    padding: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
    font-size: 16px;
}

/* Style the login button */

.btn-primary {
    background-color: #333;
    color: #fff;
    border: none;
    border-radius: 5px;
    padding: 10px 20px;
    font-size: 16px;
    cursor: pointer;
}

/* Add hover effect to the login button */
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