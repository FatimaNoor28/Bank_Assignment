<template>
  <div class="about-page">
    <nav class="navbar navbar-expand-lg navbar-light fixed-top" style="   background-color: #7da4ad;">
        <a class="navbar-brand" href="#">  XYZ Bank</a> <button aria-controls="navbarSupportedContent" aria-expanded="false"
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
    <div class="container mt-5">
      <h1 class="mb-4">About Our Bank</h1>
      <p class="mb-4">
        Welcome to Bank XYZ, where we are dedicated to providing exceptional financial services to our customers.
        Lorem ipsum dolor sit amet, consectetur adipiscing elit. 
        Nullam vehicula libero eu est interdum congue. 
        Nulla nec arcu nec odio interdum iaculis id id turpis.
      </p>
  
      <!-- Bank History Section -->
      <div class="mb-5">
        <h2>Our History</h2>
        <p>
          Our bank has a rich history dating back to [year], when it was founded by [founder's name]. 
          Since then, we have been serving the community with integrity and commitment.
        </p>
      </div>
  
      <!-- Mission and Values Section -->
      <div>
        <h2>Our Mission and Values</h2>
        <p>
          At Bank XYZ, our mission is to [describe your mission statement]. 
          We are guided by the following core values: [list your core values].
        </p>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'AboutPage',
};
</script>

<style scoped>
/* Add styles for your About page here */
.about-page {
  background-image: url('./images/bank1.avif'); /* Specify the path to your background image */
  background-size: cover;
  background-position: center;
  color: #333; /* Text color on top of the background image */
  padding: 15vw; /* Adjust padding as needed */
  /* padding-bottom: 20vh; */
}

.container {
  background-color: rgba(255, 255, 255, 0.8); /* Semi-transparent white background for content */
  padding: 20px;
  border-radius: 10px; /* Rounded corners for content container */
  box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.2); /* Drop shadow for content container */
}

/* Your existing navbar styles here */

/* You can add more custom styles as needed */
</style>
