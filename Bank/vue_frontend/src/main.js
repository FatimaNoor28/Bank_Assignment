import { createApp } from "vue";
import App from "./App.vue";
import router from "./router";
import store from "./store"; // Import your Vuex store
// import Vue from 'vue';
import "bootstrap/dist/css/bootstrap.min.css";

createApp(App).use(router).use(store).mount("#app");
