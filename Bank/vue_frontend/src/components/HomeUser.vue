  <template>
    <div class="main">
    <nav class="navbar navbar-expand-lg navbar-light fixed-top" style="   background-color: #7da4ad;">
      <router-link to="/" class="navbar-brand">XYZ Bank</router-link><button aria-controls="navbarSupportedContent" aria-expanded="false"
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
      <h2>Account Actions</h2>
      <div class="action-buttons">
        <button @click="viewAccount">View Account</button>
        <!-- <button @click="addAccount">Add Balance</button> -->
        <button @click="updateAccount">Make Transaction</button>
        <!-- <button @click="deleteAccount">Delete Account</button> -->
      </div>
    </div>
    </div>
  </template>
  
  <script>
  export default {
    // props: {
    //   userName: String, // Define the 'userName' prop
    // }, 
    name: 'HomeUser',
    methods: {
      viewAccount() {
        // const userName =  this.$route.params.userName;
        const userName = this.$store.state.userName;
        // const password = this.$store.state.password;
        // console.log(`User Name: ${userName}`);
        // console.log(`User Name: ${password}`);


        // Implement the logic for viewing accounts
        console.log("View Account by userName clicked", userName);
        this.$router.push({name: 'ViewAccount'});
        // this.$router.push({ name: 'viewAccount', params: { userName: userName } });

      },
      addAccount() {
        // Implement the logic for adding an account
        console.log("Add Balance clicked");
        this.$router.push({name:'AddBalance'});
      },
      updateAccount() {
        // Implement the logic for updating an account
        console.log("Make Transaction clicked");
        this.$router.push({name:"MakeTransaction"});
      },
    
    },
  };
  </script>
  
  <style scoped>

.main{
  background-image: url('./images/bank.jpg'); /* Specify the path to your background image */
  background-size: cover;
  background-position: center;
  color: #333; /* Text color on top of the background image */
  padding-top: 10vw;
  padding-bottom: 10vw; 
  
}
.container {
    max-width: 40vw;
    margin: 0 auto;
    margin-top: 10vh;
    margin-bottom: 15vh;
    padding: 5vh;
    border: 1vw solid #ccc;
    border-radius: 2vw;
    box-shadow: 0 2pw 5pw rgba(0, 0, 0, 0.1);
    background-color:lightgrey;
}

h1 {
    text-align: center;
    margin-bottom: 20px;
    font-weight: bold;
    color: #333;
}
/* Style for the container div */
div {
  text-align: center;
  margin: 20px;
}

/* Style for the heading */
h2 {
  text-align: center;
    margin-bottom: 20px;
    font-weight: bold;
    color: #333;
  font-size: 24px;
  margin-bottom: 10px;
}

/* Style for the action buttons container */
.action-buttons {
  display: flex;
  flex-direction: column;
  align-items: center;
}

/* Style for each action button */
button {
  background-color: #7da4ad;
  color: #fff;
  padding: 10px 20px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  margin: 10px 0;
  font-weight: bold;
  transition: background-color 0.3s ease;
}

button:hover {
  background-color: #555;
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
  