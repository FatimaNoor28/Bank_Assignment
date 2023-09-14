<!-- <template>
    <div>
      <h1>Logged In Successfully</h1>
    </div>
  </template>
  
  <script>
  export default {
    name: 'HomePage',
    data () {
        return {
            msg: 'Welcome to your Vue.js App'
        }
    }
  }
  </script> -->
  
  <template>
    <div>
      <h2>Account Actions</h2>
      <div class="action-buttons">
        <button @click="viewAccounts">View Accounts</button>
        <button @click="addAccount">Add Account</button>
        <button @click="updateAccount">Update Account</button>
        <button @click="deleteAccount">Delete Account</button>
      </div>
    </div>
  </template>
  
  <script>
  export default {
    name: 'HomePage',
    methods: {
      viewAccounts() {
        // Implement the logic for viewing accounts
        console.log("View Accounts clicked");
        this.$router.push({name:'AccountsList'});
      },
      addAccount() {
        // Implement the logic for adding an account
        console.log("Add Account clicked");
        this.$router.push({name:'AddAccount'});
      },
      updateAccount() {
        // Implement the logic for updating an account
        console.log("Update Account clicked");
        this.$router.push({name:"EditAccount"});
      },
      deleteAccount() {
        // Implement the logic for deleting an account
        console.log("Delete Account clicked");
        this.$routr.push({name:"DeleteAccount"});
      },
    },
  };
  </script>
  
  <style scoped>
  .action-buttons {
    display: flex;
    justify-content: space-between;
    margin-top: 20px;
  }
  
  button {
    padding: 10px;
  }
  </style>
  




  <!-- Add "scoped" attribute to limit CSS to this component only -->
  <style scoped>
  h3 {
    margin: 40px 0 0;
  }
  ul {
    list-style-type: none;
    padding: 0;
  }
  li {
    display: inline-block;
    margin: 0 10px;
  }
  a {
    color: #42b983;
  }
  </style>
  