package com.redmath.cucumber.pages.Login;

import com.redmath.cucumber.pages.Page;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class LoginPage extends Page {
    @Value("${page.login.url}")
    private String url;
    @Value("${page.login.Adminhome-url}")
    private String adminUrl;
    @Value("${page.login.txt-username.xpath}")
    private String txtUsernameXpath;
    @Value("${page.login.txt-password.xpath}")
    private String txtPasswordXpath;
    @Value("${page.login.btn-login.xpath}")
    private String btnLoginXpath;
    public String getUsernameFieldValue() {
        return getAttribute(By.xpath(txtUsernameXpath), "value");
    }

    public String getPasswordFieldValue() {
        return getAttribute(By.xpath(txtPasswordXpath), "value");
    }
    public void load(){
        load(url);
        visible(By.xpath(txtUsernameXpath));
        visible(By.xpath(txtPasswordXpath));
    }
    public void loadAdmin(){
        load(adminUrl);
    }
    public void EnterUsernameAndPassword(String username, String password){
        input(username, By.xpath(txtUsernameXpath));
        input(password, By.xpath(txtPasswordXpath));
    }
    public String getUsernameFromFrontend() {
        // Locate the username input element and extract its value
        WebElement usernameInput = webDriver().findElement(By.id("username-input"));
        return usernameInput.getAttribute("value");
    }

    public String getPasswordFromFrontend() {
        // Locate the password input element and extract its value
        WebElement passwordInput = webDriver().findElement(By.id("password-input"));
        return passwordInput.getAttribute("value");
    }

    public void ClickLogin(){
        click(By.xpath(btnLoginXpath));
    }

}
