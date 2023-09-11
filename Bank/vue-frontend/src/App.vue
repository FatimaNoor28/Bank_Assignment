<template>
  <body>
    
  <main>
  <!-- <img alt="Vue logo" src="./assets/logo.png"> -->
  <div id="app">
    <router-view />
  </div>
</main>

  <footer>
        &copy; 2023 XYZ Bank. All rights reserved.
    </footer>
  </body>
</template>

<script>



export default {
  name: 'App',

}
</script>

<style>

#app {
  display: flex;
  flex-direction: column;
  min-height: 100vh; /* Ensures the page takes at least the full viewport height. */
}

header {
  background-color: darkseagreen;
  color: #fff;
  text-align: center;
  padding: 20px 0;
}

main {
  flex-grow: 1; /* Allows the main content to grow and fill available space. */
  text-align: center;
  background-color:#fff;
  padding-top: 60px; /* Adjust this value to create space below the fixed header. */
}

footer {
  background-color: #7da4ad;
  color: #fff;
  text-align: center;
  padding: 10px 0;
  position: fixed;
  bottom: 0;
  width: 100%;
}
</style>