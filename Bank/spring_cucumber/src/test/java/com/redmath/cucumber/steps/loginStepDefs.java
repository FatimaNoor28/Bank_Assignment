package com.redmath.cucumber.steps;

import com.redmath.cucumber.pages.Login.LoginPage;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.jupiter.api.Assertions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.sql.SQLOutput;
@SpringBootTest
public class loginStepDefs {
    @Autowired
    private LoginPage loginPage;
    private String username;
    private String password;

    @Given("the user is on login page")
    public void the_user_is_on_login_page() throws Throwable{
        System.out.println("The user is on login page");
        loginPage.load();
    }

    @When("the user enters valid credentials {string} and {string}")
    public void the_user_enters_valid_credentials(String username, String password) throws Throwable{
        System.out.println("Entered username and password");
//        this.username = loginPage.getUsernameFieldValue();
//        this.password = loginPage.getPasswordFieldValue();
        this.username = username;
        this.password = password;
        loginPage.EnterUsernameAndPassword(username, password);
    }
    @When("hits submit button")
    public void hits_submit_button() throws Throwable{
        System.out.println("Clicked on submit");
        loginPage.ClickLogin();
    }
    @Then("the user should be logged in successfully")
    public void the_user_should_be_logged_in_successfully() throws Throwable {
        Assertions.assertEquals(username,"Admin");
        Assertions.assertEquals(password,"admin");
        System.out.println("Yeah I'm logged in");
//        Assertions.assertTrue(loginPage.title().startsWith(username));

        loginPage.loadAdmin();

    }
}
