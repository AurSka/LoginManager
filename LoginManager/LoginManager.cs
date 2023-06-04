using System;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;
using LoginManager.Classes;

namespace LoginManager
{
    public class LoginManager
    {
        AccountStorageType StorageType;
        string ConnectionString;
        string FileLocation;
        string Table;
        string UserNameColumn;
        string PasswordColumn;
        string IdColumn;
        string RoleColumn;
        readonly AesCryptoServiceProvider Provider = new AesCryptoServiceProvider();

        /// <summary>
        /// Initializes the LoginManager, method for SQL storage type
        /// </summary>
        /// <param name="storageType">How the logins are going to be stored. Current values are Custom (for if you want to define your own functions), Local (if you are, for instance, storing it on a tablet or computer without a connection which is running an app that people shouldn't exit out of) and SQL (if the data is stored on an SQL database).</param>
        /// <param name="connectionString">Connection string, if storage type is SQL.</param>
        /// <param name="table">The table housing the users.</param>
        /// <param name="userNameColumn">Column that holds the usernames. Default value is "UserName".</param>
        /// <param name="passwordColumn">Column that holds the passwords, which should be encrypted. Never leave your sensitive data unencrypted if you can help it. Default value is "Password".</param>
        /// <param name="emailColumn">Column that holds emails. Default value is "Email".</param>
        /// <param name="idColumn">Column that holds user IDs, if you want ID to be returned. Optional.</param>
        /// <param name="roleColumn">Column that holds user roles, if you want roles to be returned. Optional.</param>

        public LoginManager(AccountStorageType storageType, string connectionString, string table, string userNameColumn = "UserName", string passwordColumn = "Password", string idColumn = "", string roleColumn = "")
        {
            this.StorageType = storageType;
            this.ConnectionString = connectionString;
            this.Table = table;
            this.UserNameColumn = userNameColumn;
            this.PasswordColumn = passwordColumn;
            this.IdColumn = idColumn;
            this.RoleColumn = roleColumn;

        }
        /// <summary>
        /// Initializes the LoginManager, method for Local storage type
        /// </summary>
        /// <param name="storageType">How the logins are going to be stored. Current values are Custom (for if you want to define your own functions), Local (if you are, for instance, storing it on a tablet or computer without a connection which is running an app that people shouldn't exit out of) and SQL (if the data is stored on an SQL database).</param>
        /// <param name="location">The location and name of the file which will contain the login data.</param>
        /// <param name="key">The symmetric key used to encrypt and decrypt the file in the AesCryptoServiceProvider. Absolutely vital to retain after the app is closed, or you won't be able to decode your files afterwards. I also suggest making regular copies of your data somewhere regardless to ensure it is not all lost in the event of an error.</param>
        /// <param name="iv">The IV (initialization vector) used to encrypt and decrypt the file in the AesCryptoServiceProvider. Absolutely vital to retain after the app is closed, or you won't be able to decode your files afterwards. I also suggest making regular copies of your data somewhere regardless to ensure it is not all lost in the event of an error.</param>
        public LoginManager(AccountStorageType storageType, string fileLocation, byte[] key, byte[] iv)
        {
            this.StorageType = storageType;
            this.FileLocation = fileLocation;
            this.Provider.Key = key;
            this.Provider.IV = iv;
        }

        /// <summary>
        /// Initializes the LoginManager, method for Custom type
        /// </summary>
        /// <param name="storageType">How the logins are going to be stored. Current values are Custom (for if you want to define your own functions), Local (if you are, for instance, storing it on a tablet or computer without a connection which is running an app that people shouldn't exit out of) and SQL (if the data is stored on an SQL database).</param>
        public LoginManager(AccountStorageType storageType)
        {
            this.StorageType = storageType;
        }

        /// <summary>
        /// Attempts to login. If found, returns username, role and ID via LoginVm class. If not, returns null.
        /// </summary>
        /// <param name="username">The username of the account.</param>
        /// <param name="password">The password of the account.</param>
        /// <param name="function">Custom function, if using Custom method.</param>
        /// <returns></returns>
        public LoginVm AttemptLogin(string username, string password, Func<string, string, LoginVm> function = null)
        {
            bool encrypted = true;
            try
            {
                switch (StorageType)
                {
                    case AccountStorageType.SQL:
                        if (string.IsNullOrEmpty(ConnectionString) || string.IsNullOrEmpty(Table))
                            throw new Exception("ConnectionString or Table are not defined, please assign the correct ConnectionString and Table.");
                        SqlDataAdapter sql = new SqlDataAdapter(string.Format("SELECT * FROM {0} WHERE {1} = '{2}'", Table, UserNameColumn, username.Replace("'", "''")), ConnectionString);
                        DataTable table = new DataTable();
                        sql.Fill(table);
                        if (table == null || table.Rows.Count == 0)
                            throw new Exception("Authorization failed. Ensure that there are no spelling mistakes in either username or password."); 
                        bool verified = PasswordHasher.Check(table.Rows[0][PasswordColumn].ToString(), password);
                        if (!verified)
                        {
                            throw new Exception("Authorization failed. Ensure that there are no spelling mistakes in either username or password.");
                        }
                        int? userId = null;
                        if (!string.IsNullOrEmpty(IdColumn))
                        {
                            userId = int.Parse(table.Rows[0][IdColumn].ToString());
                        }
                        return new LoginVm
                        {
                            UserName = username,
                            UserId = userId,
                            UserRole = !string.IsNullOrEmpty(RoleColumn) ? table.Rows[0][RoleColumn].ToString() : ""
                        };
                    case AccountStorageType.Local:
                        if (!File.Exists(FileLocation) || string.IsNullOrWhiteSpace(FileLocation)) //If there is no file, there are no users.
                            throw new Exception("Authorization failed. Ensure that there are no spelling mistakes in either username or password.");
                        FileEncryptor.DecryptFile(FileLocation, FileLocation + "temp", Provider);
                        encrypted = false;
                            string line = "";
                        using (StreamReader reader = new StreamReader(FileLocation + "temp"))
                        {
                            while (!reader.EndOfStream && !line.StartsWith(username.Replace(";", "{semicolon}") + ";"))
                            {
                                line = reader.ReadLine();
                            }
                        }
                            FileEncryptor.EncryptFile(FileLocation + "temp", FileLocation, Provider);
                            encrypted = true;
                            File.Delete(FileLocation + "temp");
                            if (line.StartsWith(username.Replace(";", "{semicolon}") + ";"))
                            {
                                var vars = line.Split(';');
                                verified = PasswordHasher.Check(vars[3].ToString(), password);
                                if (!verified)
                                {
                                    throw new Exception("Authorization failed. Ensure that there are no spelling mistakes in either username or password.");
                                }
                                return new LoginVm
                                {
                                    UserName = vars[0].Replace("{semicolon}", ";"),
                                    UserId = int.Parse(vars[1]),
                                    UserRole = vars[2].Replace("{semicolon}", ";")
                                };
                            }
                            else
                            {
                                throw new Exception("Authorization failed. Ensure that there are no spelling mistakes in either username or password.");
                            }
                    case AccountStorageType.Custom:
                        if (function != null)
                            return function(username, password);
                        else
                            throw new Exception("Custom function is not defined.");
                    default:
                        throw new Exception("Storage type not defined. Current options are: Custom, SQL and Local.");
                }
            }
            catch (Exception E)
            {
                try 
                {
                    if (StorageType == AccountStorageType.Local && !encrypted)
                    {
                        FileEncryptor.EncryptFile(FileLocation + "temp", FileLocation, Provider);
                        File.Delete(FileLocation + "temp");
                    }
                }
                catch
                {
                    Console.Write(E.Message);
                    return null;
                }
                Console.Write(E.Message);
                return null;
            }
        }

        /// <summary>
        /// Attempts to register a new account.
        /// </summary>
        /// <param name="username">The username of the new account.</param>
        /// <param name="password">The password of the new account.</param>
        /// <param name="role">The role of the new account.</param>
        /// <param name="function">Custom function, if using Custom method.</param>
        /// <returns></returns>
        public bool Register(string username, string password, string role, Func<string, string, string, bool> function = null)
        {
            bool encrypted = true;
            try
            {
                switch (StorageType)
                {
                    case AccountStorageType.SQL:
                        if (string.IsNullOrEmpty(ConnectionString) || string.IsNullOrEmpty(Table))
                            throw new Exception("ConnectionString or Table are not defined, please assign the correct ConnectionString and Table.");
                        string query = string.Format("SELECT * FROM {0} WHERE {1} = '{2}'", Table, UserNameColumn, username.Replace("'", "''"));
                        SqlDataAdapter sql = new SqlDataAdapter(string.Format("SELECT * FROM {0} WHERE {1} = '{2}'", Table, UserNameColumn, username.Replace("'", "''")), ConnectionString);
                        DataTable table = new DataTable();
                        sql.Fill(table);
                        if (table == null || table.Rows.Count == 0)
                        {
                            SqlConnection connection = new SqlConnection(ConnectionString);
                            SqlCommand command = new SqlCommand(string.Format("INSERT INTO {0}({1},{2}{3}) VALUES ('{4}','{5}'{6})", Table, UserNameColumn, PasswordColumn,
                                string.IsNullOrEmpty(RoleColumn) ? "" : "," + RoleColumn, username.Replace("'", "''"), PasswordHasher.Hash(password),
                                string.IsNullOrEmpty(RoleColumn) ? "" : "," + "'" + role.Replace("'", "''") + "'"), connection);
                            connection.Open();
                            int status = command.ExecuteNonQuery();
                            connection.Close();
                            return status == 1;
                        }
                        else
                        {
                            throw new Exception("User with username already exists. Please choose another username.");
                        }
                    case AccountStorageType.Local:
                        string line = "";
                        if (File.Exists(FileLocation))
                        {
                            FileEncryptor.DecryptFile(FileLocation, FileLocation + "temp", Provider);
                            encrypted = false;
                            using (StreamReader reader = new StreamReader(FileLocation + "temp"))
                            {
                                while (!reader.EndOfStream && !line.StartsWith(username.Replace(";", "{semicolon}") + ";"))
                                {
                                    string tempLine = reader.ReadLine();
                                    if (!string.IsNullOrWhiteSpace(tempLine))
                                        line = tempLine;
                                }
                            }
                        }
                        //else
                            //File.Create(FileLocation + "temp");
                        if (line.StartsWith(username.Replace(";", "{semicolon}") + ";"))
                        {
                            throw new Exception("User with username already exists. Please choose another username.");
                        }
                        else
                        {
                            var vars = line.Split(';');
                            using (StreamWriter writer = new StreamWriter(FileLocation + "temp", File.Exists(FileLocation + "temp")))
                                writer.WriteLine(string.Format("{0};{1};{2};{3}", username.Replace(";", "{semicolon}"), vars.Length == 4 ? int.Parse(vars[1]) + 1 : 1, role.Replace(";", "{semicolon}"), PasswordHasher.Hash(password)));
                            FileEncryptor.EncryptFile(FileLocation + "temp", FileLocation, Provider);
                            encrypted = true;
                            File.Delete(FileLocation + "temp");
                            return true;
                        }

                    case AccountStorageType.Custom:
                        if (function != null)
                            return function(username, password, role);
                        else
                            throw new Exception("Custom function is not defined.");
                    default:
                        throw new Exception("Storage type not defined. Current options are: Custom, SQL and Local.");
                }
            }
            catch (Exception E)
            {
                try
                {
                    if (StorageType == AccountStorageType.Local && !encrypted)
                    {
                        FileEncryptor.EncryptFile(FileLocation + "temp", FileLocation, Provider);
                        File.Delete(FileLocation + "temp");
                    }
                }
                catch
                {
                    Console.Write(E.Message);
                    return false;
                }
                Console.Write(E.Message);
                return false;
            }
        }

        /// <summary>
        /// Attempts to find an account and change its password.
        /// </summary>
        /// <param name="username">The username of the account.</param>
        /// <param name="password">The password of the account.</param>
        /// <param name="oldPassword">The old password of the account.</param>
        /// <param name="function">Custom function, if using Custom method.</param>
        /// <returns></returns>
        public bool ChangePassword(string username, string password, string oldPassword = "", Func<string, string, string, bool> function = null)
        {
            bool encrypted = true;
            try
            {
                switch (StorageType)
                {
                    case AccountStorageType.SQL:
                        if (string.IsNullOrEmpty(ConnectionString) || string.IsNullOrEmpty(Table))
                            throw new Exception("ConnectionString or Table are not defined, please assign the correct ConnectionString and Table.");
                        SqlDataAdapter sql = new SqlDataAdapter(string.Format("SELECT * FROM {0} WHERE {1} = '{2}'", Table, UserNameColumn, username.Replace("'", "''")), ConnectionString);
                        DataTable table = new DataTable();
                        sql.Fill(table);
                        if (table == null || table.Rows.Count == 0)
                        {
                            throw new Exception("User not found. Ensure that there are no spelling mistakes.");
                        }
                        else
                        {
                            if (!PasswordHasher.Check(table.Rows[0][PasswordColumn].ToString(), oldPassword))
                                throw new Exception("Incorrect password.");
                            SqlConnection connection = new SqlConnection(ConnectionString);
                            SqlCommand command = new SqlCommand(string.Format("UPDATE {0} SET {1} = '{2}' WHERE {3} = '{4}'", Table, PasswordColumn, PasswordHasher.Hash(password), UserNameColumn, username.Replace("'", "''")), connection);
                            connection.Open();
                            int status = command.ExecuteNonQuery();
                            connection.Close();
                            return status == 1;
                        }
                    case AccountStorageType.Local:
                        if(!File.Exists(FileLocation) || string.IsNullOrWhiteSpace(FileLocation)) //If there is no file, there are no users.
                            throw new Exception("User file not found.");
                        FileEncryptor.DecryptFile(FileLocation, FileLocation + "temp", Provider);

                        string line = "";
                        string[] arrLine = File.ReadAllLines(FileLocation + "temp"); int t = -1;
                        while (!line.StartsWith(username.Replace(";", "{semicolon}") + ";") && ++t < arrLine.Length)
                        {
                            line = arrLine[t];
                        }
                        if (line.StartsWith(username.Replace(";", "{semicolon}") + ";"))
                        {
                            var vars = line.Split(';');
                            if (PasswordHasher.Check(vars[3].ToString(), password))
                                throw new Exception("Incorrect password.");
                            arrLine[t] = string.Format("{0};{1};{2};{3}", vars[0], vars[1], vars[2], PasswordHasher.Hash(password));
                            File.WriteAllLines(FileLocation + "temp", arrLine);
                            FileEncryptor.EncryptFile(FileLocation + "temp", FileLocation, Provider);
                            File.Delete(FileLocation + "temp");
                            return true;
                        }
                        else
                        {
                            throw new Exception("User not found. Ensure that there are no spelling mistakes.");
                        }
                    case AccountStorageType.Custom:
                        if (function != null)
                            return function(username, password, oldPassword);
                        else
                            throw new Exception("Custom function is not defined.");
                    default:
                        throw new Exception("Storage type not defined. Current options are: Custom, SQL and Local.");
                }
            }
            catch (Exception E)
            {
                try
                {
                    if (StorageType == AccountStorageType.Local && !encrypted)
                    {
                        FileEncryptor.EncryptFile(FileLocation + "temp", FileLocation, Provider);
                        File.Delete(FileLocation + "temp");
                    }
                }
                catch
                {
                    Console.Write(E.Message);
                    return false;
                }
                Console.Write(E.Message);
                return false;
            }
        }
    }
}
