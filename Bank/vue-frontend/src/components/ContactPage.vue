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
    <div class="container mt-5">
      <h1 class="mb-4">Contact Us</h1>
      <p class="mb-4">Feel free to contact us for any inquiries or feedback.</p>

      <!-- Contact Info -->
      <div class="contact-info">
        <div class="row">
          <div class="col-md-6">
            <div class="bold-text">Contact Information:</div>
            <p><strong>Email:</strong> contact@example.com</p>
            <p><strong>Phone:</strong> +123 456 789</p>
            <p><strong>Address:</strong> 123 Main Street, City, Country</p>
          </div>
          <div class="col-md-6">
            <img src="./images/3608.avif" alt="Contact Image" class="img-fluid rounded">
          </div>
        </div>
      </div>

      <!-- Contact Form -->
      <div class="row mt-4">
        <div class="col-md-6">
          <form>
            <!-- Your Form Fields Here -->
          </form>
        </div>
      </div>
    </div>

  </template>
  
  <script>
  export default {
    name: 'ContactPage',
  };
  </script>
  
  <style scoped>
  /* Add styles for your contact page here */
  /* Example: */
  .container {
    padding: 20px;
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
  
  
  /* You can add more custom styles as needed */
  </style>
  