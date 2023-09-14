import axios from "axios";
// import router from "./router";


const LOGOUT_API_URL = "/logout";

class logoutService{
    logout() {
        axios.post(LOGOUT_API_URL)
          .then(() => {
            this.$router.push({ name: 'LoginDetail' });
          })
          .catch(error => {
            console.error('Logout failed:', error);
          });
      }
}

export default new logoutService();
