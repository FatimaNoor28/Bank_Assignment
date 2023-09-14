Feature: Admin Performs Multiple Actions
  Background:
    Given the user is on login page
    When the user enters valid credentials "Admin" and "admin"
    And hits submit button

  Scenario: User performs view Accounts
    When the user clicks on "View Accounts" button
    Then the user should see the result of view Accounts