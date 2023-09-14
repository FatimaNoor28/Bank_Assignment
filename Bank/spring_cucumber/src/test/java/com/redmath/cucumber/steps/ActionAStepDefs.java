package com.redmath.cucumber.steps;

import com.redmath.cucumber.pages.Login.AdminPage;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Assertions;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.restassured.response.Response;

import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;

@SpringBootTest
public class ActionAStepDefs {
    @Autowired
    private AdminPage adminPage;
    @Autowired
    private WebDriver driver;
    private Response response;
    private String endpoint = "http://localhost:8081/viewAccounts";
    @When("the user is on home page")
    public void the_user_is_on_home_page() {
        adminPage.load();
    }
    @When("the user clicks on {string} button")
    public void the_user_clicks_on_button(String actionButton) {
        adminPage.clickAccountsButton(actionButton); // Implement this method in your page class to click the button
        driver.get("http://localhost:8081/viewAccounts");
        response = given().contentType(ContentType.JSON)
                .when().get(endpoint);
        System.out.println("Response :" + response.getBody().asPrettyString());
    }

    @Then("^the user should see the result (\\d+) of view Accounts:$")
    public void the_user_should_see_the_result_of_view_Accounts(int statusCode, List<Map<String, String>> dataRows) {
        String result = adminPage.getAccountsAResult(); // Implement this method in your page class to get the result
        Assertions.assertEquals("Account Id Name Password Email Address", result); // Replace with the expected result
    }
}
