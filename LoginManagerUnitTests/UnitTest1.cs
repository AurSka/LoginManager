using LoginManager;
using LoginManager.Classes;
using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace LoginManagerUnitTests
{
    public class UnitTest1
    {
        public static string FileLocation = "debug.txt";
        public static string ConnectionString = "Server=localhost\\SQLEXPRESS;Database=Test;User Id=aurska;Password=A456852a;";
        public static string Table = "dbo.Users";
        public static string UserNameColumn = "Username";
        public static string PasswordColumn = "Password";
        public static string IdColumn = "Id";
        public static string RoleColumn = "Role";

        /// <summary>
        /// Tests functionality on SQL saving method.
        /// </summary>
        [Fact]
        public void SqlTest()
        {
            LoginManager.LoginManager manager = new LoginManager.LoginManager(LoginManager.Classes.AccountStorageType.SQL, ConnectionString, Table, UserNameColumn, PasswordColumn, IdColumn, RoleColumn);

            string username = "test";
            string password = "111";
            string role = "User";
            string newPassword = "112";

            var login = manager.AttemptLogin(username, password);
            Assert.Null(login);
            Assert.False(manager.ChangePassword(username, newPassword, password));

            Assert.True(manager.Register(username, password, role));
            Assert.False(manager.Register(username, password, role));

            login = manager.AttemptLogin(username, password);
            Assert.Equal(username, login.UserName);
            Assert.Equal(role, login.UserRole);
            login = manager.AttemptLogin(username, newPassword);
            Assert.Null(login);


            Assert.True(manager.ChangePassword(username, newPassword, password));
            Assert.False(manager.ChangePassword(username, newPassword, password));

            SqlConnection connection = new SqlConnection(ConnectionString);
            SqlCommand command = new SqlCommand(string.Format("DELETE FROM {0} WHERE {1} = '{2}'", Table, UserNameColumn, username.Replace("'", "''")), connection);
            connection.Open();
            int status = command.ExecuteNonQuery();
            connection.Close();
            Assert.Equal(1, status);

            manager = new LoginManager.LoginManager(LoginManager.Classes.AccountStorageType.SQL, "", "");
            login = manager.AttemptLogin(username, password);
            Assert.Null(login);
            Assert.False(manager.Register(username, password, role));
            Assert.False(manager.ChangePassword(username, newPassword, password));    
        }
        /// <summary>
        /// Tests functionality on local saving method.
        /// </summary>
        [Fact]
        public void LocalTest()
        {
            var provider = new AesCryptoServiceProvider();
            byte[] key = provider.Key;
            byte[] iv = provider.IV;
            LoginManager.LoginManager manager = new LoginManager.LoginManager(LoginManager.Classes.AccountStorageType.Local, FileLocation, key, iv);
            string username = "test";
            string password = "111";
            string newPassword = "112";
            string role = "User";

            var login = manager.AttemptLogin(username, password);
            Assert.Null(login);
            Assert.False(manager.ChangePassword(username, newPassword, password));

            Assert.True(manager.Register(username, password, role));
            Assert.False(manager.Register(username, password, role));

            login = manager.AttemptLogin(username, password);
            Assert.Equal(username, login.UserName);
            Assert.Equal(role, login.UserRole);
            login = manager.AttemptLogin(username, newPassword);
            Assert.Null(login);


            Assert.True(manager.ChangePassword(username, newPassword, password));
            Assert.False(manager.ChangePassword(username, newPassword, password));

            File.Delete(FileLocation);
            Assert.False(File.Exists(FileLocation));
        }

        /// <summary>
        /// Tests functionality on custom method.
        /// </summary>
        [Fact]
        public void CustomTest()
        {
            LoginManager.LoginManager manager = new LoginManager.LoginManager(LoginManager.Classes.AccountStorageType.Custom);

            LoginVm ReturnNullLogin(string username, string password)
            {
                return null;
            }
            bool ReturnTrue(string username, string password, string role)
            {
                return true;
            }
            string username = "test";
            string password = "111";
            string newPassword = "112";
            string role = "User";
            var login = manager.AttemptLogin(username, password, ReturnNullLogin);
            Assert.Null(login);
            login = manager.AttemptLogin(username, password);

            Assert.True(manager.Register(username, password, role, ReturnTrue));
            Assert.False(manager.Register(username, password, role));

            Assert.True(manager.ChangePassword(username, newPassword, password, ReturnTrue));
            Assert.False(manager.ChangePassword(username, newPassword, password));
        }
        /// <summary>
        /// Tests functionality on custom method.
        /// </summary>
        [Fact]
        public void UndefinedTest()
        {
            LoginManager.LoginManager manager = new LoginManager.LoginManager((AccountStorageType)99);
            string username = "test";
            string password = "111";
            string newPassword = "112";
            string role = "User";
            var login = manager.AttemptLogin(username, password);
            Assert.Null(login);
            Assert.False(manager.Register(username, password, role));
            Assert.False(manager.ChangePassword(username, newPassword, password));
        }
    }
}
