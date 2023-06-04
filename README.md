# LoginManager
C#/Visual Studio library to manage logins and registrations.

A small component/library created for an assignment.

The component is designed to allow a system that needs to allow access to various users based on entered credentials and to encrypt and store the credentials securely. Currently, the component allows you to register, log in and change your password. Data can be stored locally or via SQL. In the future, additional functions will be added (for example, the ability to change the password after providing a generated code, the ability to assign parameters to users) and other ways to save data. If the current options aren't acceptable, but you still want to use this specifically, you can assign your own function to a method, download and edit according to the GNU-GPL license or leave a message and/or issue report.

**Changelog**

Version 0.01: The creation of the starting variant.

**Details**

The PasswordHasher static class is used for hashing and checking passwords so that a person cannot immediately discover the password after gaining access to the data.

The FileEncryptor class has file encryption and decryption functions used to encrypt and temporarily decrypt a file if the local storage method is used. It needs both source and destination file locations, as well as a provider of the AesCryptoServiceProvider class. The one created on initialization in the main class is not publically accessible.

LoginManager is the base class that contains all public functions. There are 3 possible initializers for each data storage method:

• SQL storage requires ConnectionString (database connection data), Users table name, column names of Username, Password, ID and Role,

• Local method requires file location, key and IV for AES (Advanced Encryption Standard) encryption,

• Although I don't know what the component would be used for if the main functions are not useful, the Custom method allows the function to assign its own functions as function variables. Just add the function after the other variables.

There are also 3 functions:

• Login(string username, string password) – Tries to login according to the given data, returns null if login failed or LoginVm class with data if successful.

• Register(string username, string password, string role) – Checks if there is already a user with the entered username and if not found, creates one. Returns a bool value based on success status.

• ChangePassword(string username, string password, string oldPassword) – Checks whether the old password matches, and if it matches, changes it to a new one. Returns a bool value based on success status.

LoginVm class has only 3 variables: UserName, UserId and UserRole.

AccountStorageType is an enumerator whose values correspond to the possible ways to use the component: SQL, Local, Custom.

To use the component, you need to download it and add it to your project, then create a LoginManager.LoginManager class variable with the desired parameters.
Simple usage examples can be found in the unit tests.