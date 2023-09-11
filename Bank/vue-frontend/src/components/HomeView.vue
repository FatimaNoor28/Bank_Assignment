
<template><!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Bootstrap 4 Homepage with navbar and slider</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" rel="stylesheet">
        <link href="style.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light fixed-top">
            <div class="container-fluid" style="   background-color: #7da4ad;
">
                <a class="navbar-brand" href="#">Mouri</a> <button aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation" class="navbar-toggler" data-target="#navbarSupportedContent" data-toggle="collapse" type="button"><span class="navbar-toggler-icon"></span></button>
                <div class="collapse navbar-collapse" id="navbarSupportedContent">
                    <ul class="navbar-nav ml-auto">
                        <li class="nav-item active">
                            <a class="nav-link" href="#">Home</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#">About</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#">Portfolio</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#">Services</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#">Contact</a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>
        <div class="carousel slide" data-ride="carousel" id="carouselExampleIndicators">
            <ol class="carousel-indicators">
                <li class="active" data-slide-to="0" data-target="#carouselExampleIndicators"></li>
                <!-- <li data-slide-to="1" data-target="#carouselExampleIndicators"></li>
                <li data-slide-to="2" data-target="#carouselExampleIndicators"></li> -->
            </ol>
            <div class="carousel-inner">
                <div class="carousel-item active">
                    <img alt="First slide" class="d-block w-100" src="./3608.avif">
                    <div class="carousel-caption d-none d-md-block">
                        <h5>Slider One Item</h5>
                        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit. Maxime, nulla, tempore. Deserunt excepturi quas vero.</p>
                    </div>
                </div>
                <!-- <div class="carousel-item">
                    <img alt="Second slide" class="d-block w-100" src="https://i.postimg.cc/pL0V5BVg/2.jpg">
                    <div class="carousel-caption d-none d-md-block">
                        <h5>Slider One Item</h5>
                        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit. Maxime, nulla, tempore. Deserunt excepturi quas vero.</p>
                    </div>
                </div>
                <div class="carousel-item">
                    <img alt="Third slide" class="d-block w-100" src="https://i.postimg.cc/NF7Bs6PC/3.jpg">
                    <div class="carousel-caption d-none d-md-block">
                        <h5>Slider One Item</h5>
                        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit. Maxime, nulla, tempore. Deserunt excepturi quas vero.</p>
                    </div>
                </div> -->
            </div><a class="carousel-control-prev" data-slide="prev" href="#carouselExampleIndicators" role="button"><span aria-hidden="true" class="carousel-control-prev-icon"></span> <span class="sr-only">Previous</span></a> <a class="carousel-control-next" data-slide="next" href="#carouselExampleIndicators" role="button"><span aria-hidden="true" class="carousel-control-next-icon"></span> <span class="sr-only">Next</span></a>
        </div>
        <!-- <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js">
        </script> 
        <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.3/umd/popper.min.js">
        </script> 
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.min.js">
        </script> -->
    </body>
    </html>
    
</template>

<script>
export default {
    name: 'HomeView'}
</script>

<style scoped>
.carousel-item {
	height: 100vh;
	min-height: 300px;
	background: no-repeat center center scroll;
	-webkit-background-size: cover;
	-moz-background-size: cover;
	-o-background-size: cover;
	background-size: cover;
}
.carousel-caption {
	bottom: 270px;
}
.carousel-caption h5 {
	font-size: 45px;
	text-transform: uppercase;
	letter-spacing: 2px;
	margin-top: 25px;
}
.carousel-caption p {
	width: 75%;
	margin: auto;
	font-size: 18px;
	line-height: 1.9;
}
.navbar-light .navbar-brand {
	color: #fff;
	font-size: 25px;
	text-transform: uppercase;
	font-weight: bold;
	letter-spacing: 2px;
}
.navbar-light .navbar-nav .active>.nav-link, .navbar-light .navbar-nav .nav-link.active, .navbar-light .navbar-nav .nav-link.show, .navbar-light .navbar-nav .show>.nav-link {
    color: #7da4ad;

}
.navbar-light .navbar-nav .nav-link {
    color: #7da4ad;
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
.nav-link.active, .nav-link:focus {
    color: #7da4ad;

}
.navbar-toggler {
	padding: 1px 5px;
	font-size: 18px;
	line-height: 0.3;
}
.navbar-light .navbar-nav .nav-link:focus, .navbar-light .navbar-nav .nav-link:hover {
    color: #7da4ad;
}

</style>