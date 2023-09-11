import { createStore } from "vuex";

export default createStore({
  state: {
    userName: null, // Initialize to null or an initial value
    password: null
  },
  mutations: {
    setUserName(state, userName) {
      state.userName = userName;
    },
    setPassword(state, password) {
        state.password = password;
    },
  },
  actions: {
    // Add actions if needed
  },
  getters: {
    // Add getters if needed
  },
});
