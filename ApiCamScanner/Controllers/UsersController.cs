using ApiCamScanner.Entities;
using ApiCamScanner.Token;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using MySqlConnector;
using System;

namespace ApiCamScanner.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly TokenGen _token;

        public UsersController(IConfiguration config, TokenGen token)
        {
            _config = config;
            _token = token;
        }

        [HttpGet("listUser")]
        public async Task<IActionResult> GetAllUsers()
        {
            try
            {
                // khởi tạo kết nối tới DB MySQL
                string connectionString = _config.GetConnectionString("MyConnection");
                var mySqlConnection = new MySqlConnection(connectionString);

                // chuẩn bị câu lệnh truy vấn

                string getAllEmployeesCommand = "SELECT * FROM users;";

                // thực hiện gọi vào DB để chạy câu lệnh truy vấn ở trên
                // trả về danh sách department
                var users = mySqlConnection.Query<User>(getAllEmployeesCommand);

                // xử lý dữ liệu trả về

                if (users != null)
                {
                    return StatusCode(StatusCodes.Status200OK, users);
                }
                else
                {
                    return StatusCode(StatusCodes.Status400BadRequest, "e002");

                }
            }
            catch (Exception exception)
            {

                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status400BadRequest, exception.Message);

            }

        }

        [HttpGet("{username}")]
        public async Task<IActionResult> GetuserIdByUserName([FromRoute] string username)
        {
            try
            {
                // khởi tạo kết nối tới DB MySQL
                string connectionString = _config.GetConnectionString("MyConnection");
                var mySqlConnection = new MySqlConnection(connectionString);

                // chuẩn bị câu lệnh truy vấn

                string getUser = "SELECT * FROM users WHERE username = @username";


                // chuẩn bị tham số đầu vào cho câu lệnh truy vấn
                var paramenter = new DynamicParameters();
                paramenter.Add("@username", username);

                // thực hiện gọi vào DB để chạy câu lệnh truy vấn ở trên
                // trả về danh sách department
                var users = mySqlConnection.QueryFirstOrDefault<User>(getUser, paramenter);

                // xử lý dữ liệu trả về

                if (users != null)
                {
                    return StatusCode(StatusCodes.Status200OK, users);
                }
                else
                {
                    return StatusCode(StatusCodes.Status400BadRequest, "e002");

                }
            }
            catch (Exception exception)
            {

                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status400BadRequest, exception.Message);

            }

        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] User user)
        {
            try
            {
                var authenticatedUser = AuthenticateUser(user);

                if (authenticatedUser != null)
                {
                    // Successful login, return the user object

                    var token = _token.GenerateToken(authenticatedUser);
                    Response.Headers.Add("AccessToken", "Bearer " + token.AccessToken);   // add head
                    Response.Headers.Add("RefreshToken", "Bearer " + token.RefreshToken);   // add head
                    await Console.Out.WriteLineAsync(token.AccessToken);
                    return Ok(authenticatedUser);
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized, "Invalid username or password");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }

        private User AuthenticateUser(User user)
        {
            string connectionString = _config.GetConnectionString("MyConnection");

            using (var mySqlConnection = new MySqlConnection(connectionString))
            {
                string selectUserByUsername = "SELECT * FROM users WHERE username = @username AND password = @password";
                string selectUserByEmail = "SELECT * FROM users WHERE email = @email AND password = @password";
                string selectUserByPhoneNumber = "SELECT * FROM users WHERE phoneNumber = @phoneNumber AND password = @password";


                var param = new
                {
                    username = user.username,
                    password = user.password,
                    email = user.email,
                    phoneNumber = user.phoneNumber,
                    pin = user.pin
                };

                mySqlConnection.Open();


                var authenticatedUser = mySqlConnection.QueryFirstOrDefault<User>(selectUserByUsername, param);
                if (authenticatedUser == null)
                {
                    authenticatedUser = mySqlConnection.QueryFirstOrDefault<User>(selectUserByEmail, param);
                }
                if (authenticatedUser == null)
                {
                    authenticatedUser = mySqlConnection.QueryFirstOrDefault<User>(selectUserByPhoneNumber, param);
                }
                return authenticatedUser;
            }
        }


        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] User user)
        {
            try
            {
                // Kiểm tra xem người dùng đã tồn tại hay chưa
                if (IsUserExists(user))
                {
                    return StatusCode(StatusCodes.Status409Conflict, "User already exists");
                }
                string connectionString = _config.GetConnectionString("MyConnection");

                var mySqlConnection = new MySqlConnection(connectionString);

                string insertUser = "INSERT INTO users (username, password, email, phoneNumber,pin) VALUES (@username, @password, @email,@phoneNumber,@pin); SELECT LAST_INSERT_ID()";

                var parameters = new DynamicParameters();
                parameters.Add("@username", user.username);
                parameters.Add("@password", user.password);
                parameters.Add("@email", user.email);
                parameters.Add("@phoneNumber", user.phoneNumber);
                parameters.Add("@pin", user.pin);

                int userId = mySqlConnection.ExecuteScalar<int>(insertUser, parameters);
                user.userId = userId;
                return StatusCode(StatusCodes.Status200OK, user);

            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, exception.Message);
            }
        }


        private bool IsUserExists(User user)
        {
            // Kiểm tra xem người dùng đã tồn tại trong cơ sở dữ liệu hay chưa
            // Ví dụ: Kiểm tra theo tên người dùng hoặc email
            //string connectionString = "Server=localhost;Port=3306;Database=camscanner;Uid=root;Pwd=12345678;";
            string connectionString = _config.GetConnectionString("MyConnection");

            var mySqlConnection = new MySqlConnection(connectionString);

            string selectUser = "SELECT COUNT(*) FROM users WHERE username = @username OR email = @email";

            var parameters = new DynamicParameters();
            parameters.Add("@username", user.username);
            parameters.Add("@email", user.email);

            int count = mySqlConnection.ExecuteScalar<int>(selectUser, parameters);

            return count > 0;
        }
        /// <summary>
        ///     
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>

        [HttpPost("ChangePassword")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            try
            {
                var authenticatedUser = AuthenticateUserChangePass(request);

                if (authenticatedUser != null)
                {
                    // Thực hiện logic thay đổi mật khẩu và cập nhật vào cơ sở dữ liệu
                    bool isPasswordChanged = ChangeUserPassword(authenticatedUser, request.NewPassword);

                    if (isPasswordChanged)
                    {
                        return Ok("Password changed successfully");
                    }
                    else
                    {
                        return StatusCode(StatusCodes.Status500InternalServerError, "Failed to change password");
                    }
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized, "Invalid username or password");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }
        [HttpPost("ChangePin")]
        public async Task<IActionResult> ChangePin([FromBody] ChangePinRequest request)
        {
            try
            {
                var authenticatedUser = AuthenticateUserChangePin(request);

                if (authenticatedUser != null)
                {
                    // Thực hiện logic thay đổi pin và cập nhật vào cơ sở dữ liệu
                    bool isPinChanged = ChangeUserPin(authenticatedUser, request.NewPin);

                    if (isPinChanged)
                    {
                        return Ok("Pin changed successfully");
                    }
                    else
                    {
                        return StatusCode(StatusCodes.Status500InternalServerError, "Failed to change pin");
                    }
                }
                else
                {
                    return StatusCode(StatusCodes.Status401Unauthorized, "Invalid username or pin");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }
        private User AuthenticateUserChangePass(ChangePasswordRequest request)
        {
            string connectionString = _config.GetConnectionString("MyConnection");

            using (var mySqlConnection = new MySqlConnection(connectionString))
            {
                string selectUserByUsername = "SELECT * FROM users WHERE username = @username AND password = @password";

                var param = new
                {
                    username = request.Username,
                    password = request.CurrentPassword
                };

                mySqlConnection.Open();

                var authenticatedUser = mySqlConnection.QueryFirstOrDefault<User>(selectUserByUsername, param);
                return authenticatedUser;
            }
        }
        private User AuthenticateUserChangePin(ChangePinRequest request)
        {
            string connectionString = _config.GetConnectionString("MyConnection");

            using (var mySqlConnection = new MySqlConnection(connectionString))
            {
                string selectUserByUsername = "SELECT * FROM users WHERE username = @username AND pin = @pin";

                var param = new
                {
                    username = request.Username,
                    pin = request.CurrentPin
                };

                mySqlConnection.Open();

                var authenticatedUser = mySqlConnection.QueryFirstOrDefault<User>(selectUserByUsername, param);
                return authenticatedUser;
            }
        }
        private bool ChangeUserPassword(User user, string newPassword)
        {
            string connectionString = _config.GetConnectionString("MyConnection");

            using (var mySqlConnection = new MySqlConnection(connectionString))
            {
                string updatePasswordQuery = "UPDATE users SET password = @newPassword WHERE userId = @userId";

                var param = new
                {
                    newPassword = newPassword,
                    userId = user.userId
                };

                mySqlConnection.Open();

                int rowsAffected = mySqlConnection.Execute(updatePasswordQuery, param);
                return rowsAffected > 0;
            }
        }
        private bool ChangeUserPin(User user, string newPin)
        {
            string connectionString = _config.GetConnectionString("MyConnection");

            using (var mySqlConnection = new MySqlConnection(connectionString))
            {
                string updatePinQuery = "UPDATE users SET pin = @newPin WHERE userId = @userId";

                var param = new
                {
                    newPin = newPin,
                    userId = user.userId
                };

                mySqlConnection.Open();

                int rowsAffected = mySqlConnection.Execute(updatePinQuery, param);
                return rowsAffected > 0;
            }
        }

    }

}
