package com.redmath.cucumber.pages.Login;

import com.redmath.cucumber.pages.Page;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AdminPage extends Page {
    @Value("${page.login.Adminhome-url}")
    private String adminUrl;

    public void load(){
        load(adminUrl);
//        visible(By.xpath(txtUsernameXpath));
//        visible(By.xpath(txtPasswordXpath));
    }
    public void clickAccountsButton(String actionButton) {
        // Locate the password input element and extract its value
//        WebElement passwordInput = webDriver().findElement(By.id("password-input"));
        WebElement button = webDriver().findElement(By.xpath("//button[contains(text(), '" + actionButton + "')]"));
        button.click();
    }
    public String getAccountsAResult() {
        // Implement the logic to retrieve and return the result of action A
        WebElement resultElement = webDriver().findElement(By.id("AccountTable")); // Replace with the actual element locator
        return resultElement.getText();
    }
}
