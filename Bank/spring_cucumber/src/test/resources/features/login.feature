Feature: Web Login
  Scenario: User should be able to login with valid credentials
    Given the user is on login page
    When the user enters valid credentials "Admin" and "admin"
    And hits submit button
    Then the user should be logged in successfully