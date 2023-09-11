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
  
      <!-- Contact Form -->
      <div class="row">
        <div class="col-md-6">
          <form>
            <div class="form-group">
              <label for="name">Name</label>
              <input type="text" class="form-control" id="name" placeholder="Your Name">
            </div>
            <div class="form-group">
              <label for="email">Email</label>
              <input type="email" class="form-control" id="email" placeholder="Your Email">
            </div>
            <div class="form-group">
              <label for="message">Message</label>
              <textarea class="form-control" id="message" rows="4" placeholder="Your Message"></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
          </form>
        </div>
        
        <!-- Contact Image -->
        <div class="col-md-6">
          <img src="/path/to/your/image.jpg" alt="Contact Image" class="img-fluid rounded">
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
  