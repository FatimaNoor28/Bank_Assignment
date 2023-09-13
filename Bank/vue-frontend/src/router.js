import HomeAdmin from "./components/HomeAdmin.vue";
import HomeUser from "./components/HomeUser";
import Login from "./components/Login.vue";
import Accounts from "./components/Accounts";
import AddAccount from "./components/AddAccount.vue";
import AddBalance from "./components/AddBalance" 
import DeleteAccount from "./components/DeleteAccount";
import UpdateAccount from "./components/UpdateAccount";
import Transactions from "./components/Transactions";
import MakeTransaction from "./components/MakeTransaction";
import Balances from "./components/Balances";
import viewAccount from "./components/viewAccount";
import HomeView from "./components/HomeView";
import ContactPage from "./components/ContactPage";
import About from "./components/About";

import { createRouter, createWebHistory } from "vue-router";

const routes = [
  {
    name: "HomeUser",
    component: HomeUser,
    path: "/homeUser",
  }, 
  {
    name: "ViewAccount",
    component: viewAccount,
    path: "/viewAccount",
  },
  {
    name: "viewAccounts",
    component: Accounts,
    path: "/viewAccounts",
  }, 
  {
    name: "transactionsList",
    component: Transactions,
    path: "/viewTransactions",
  }, 
  {
    name: "viewBalance",
    component: Balances,
    path: "/viewBalance",
  }, 
    
  {
    name: "MakeTransaction",
    component: MakeTransaction,
    path: "/makeTransaction",
  },  
  {
    name: "deleteAccount",
    component: DeleteAccount,
    path: "/deleteAccount",
  },  
    
  {
    name: "updateAccount",
    component: UpdateAccount,
    path: "/editAccount",
  }, 
  {
    name: "AddBalance",
    component: AddBalance,
    path: "/addBalance",
  },  
  {
    name: "AddAccount",
    component: AddAccount,
    path: "/addAccount",
  },
  {
    name: "LoginDetail",
    component: Login,
    path: "/login",
  },
  {
    name: "HomeView",
    component: HomeView,
    path: "/",
  },
  {
    name: "HomeAdmin",
    component: HomeAdmin,
    path: "/homeAdmin",
  },
  {
    name: "ContactPage",
    component: ContactPage,
    path: "/contact"
  },
  {
    name: "AboutPage",
    component: About,
    path: "/about"
  }
  
  
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});


export default router;
