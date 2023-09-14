package com.redmath.cucumber.steps;

import com.redmath.cucumber.pages.Login.AdminPage;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.jupiter.api.Assertions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class ActionAStepDefs {
    @Autowired
    private AdminPage adminPage;
//    private final String result;

    @When("the user clicks on {string} button")
    public void the_user_clicks_on_button(String actionButton) {
        adminPage.load();
        adminPage.clickAccountsButton(actionButton); // Implement this method in your page class to click the button
    }

    @Then("the user should see the result of view Accounts")
    public void the_user_should_see_the_result_of_view_Accounts() {
        String result = adminPage.getAccountsAResult(); // Implement this method in your page class to get the result
        Assertions.assertEquals("Account Id Name Password Email Address", result); // Replace with the expected result
    }
}
