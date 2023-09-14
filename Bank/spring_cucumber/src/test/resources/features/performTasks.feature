Feature: Admin Performs Multiple Actions
  Background:
    Given the user is on login page
    When the user enters valid credentials "Admin" and "admin"
    And hits submit button

  Scenario Outline: User performs view Accounts
    When the user is on home page
    And the user clicks on "View Accounts" button
    Then the user should see the result of view Accounts
      | Id | Name   | Address      | Email             | Password    |
      | <Id> | <Name> | <Address> | <Email> | <Password> |
    Examples:
      | StatusCode | Id | Name       | Address    | Email                   | Password      |
      | 200        | 1  | Laiba      | Lahore cantt | ali@gmail.com           | {noop}laiba   |