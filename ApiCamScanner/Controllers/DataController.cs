using ApiCamScanner.Entities;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using MySqlConnector;

namespace ApiCamScanner.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DatasController : ControllerBase
    {
        private readonly IConfiguration _config;

        public DatasController(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost("InsertData")]
        public async Task<IActionResult> InsertData([FromBody] Data Data)
        {
            try
            {
                string connectionString = _config.GetConnectionString("MyConnection");

                var mySqlConnection = new MySqlConnection(connectionString);

                string insertData = "INSERT INTO data (dataName, dataTypeId, dataValue, date) VALUES (@dataName, @dataTypeId, @dataValue , @date); SELECT LAST_INSERT_ID()";

                var parameters = new DynamicParameters();
                parameters.Add("@dataName", Data.dataName);
                parameters.Add("@dataValue", Data.dataValue);
                parameters.Add("@dataTypeId", Data.dataTypeId);
                parameters.Add("@date", Data.date);


                // Execute the SQL query to insert the image and retrieve the last inserted ID
                int dataId = mySqlConnection.ExecuteScalar<int>(insertData, parameters);

                Data.dataId = dataId;

                return StatusCode(StatusCodes.Status200OK, Data);

            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status400BadRequest, exception.Message);
            }
        }


        [HttpGet]
        [Route("getAllData/{dataTypeId}")]
        public async Task<IActionResult> GetAllData(int dataTypeId)
        {
            try
            {
                // Lấy tất cả các nhóm dựa trên userId
                List<Data> datas = GetAllDataByDataTypeId(dataTypeId);

                return StatusCode(StatusCodes.Status200OK, datas);
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, exception.Message);
            }
        }

        private List<Data> GetAllDataByDataTypeId(int dataTypeId)
        {
            // Lấy tất cả các nhóm từ cơ sở dữ liệu dựa trên userId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectData = "SELECT * FROM data WHERE dataTypeId = @dataTypeId";

            var parameters = new DynamicParameters();
            parameters.Add("@dataTypeId", dataTypeId);

            List<Data> groups = mySqlConnection.Query<Data>(selectData, parameters).ToList();

            return groups;
        }


        /// <summary>
        /// Update
        /// </summary>
        /// <param name="group"></param>
        /// <returns></returns>
        [HttpPut("updateData")]
        public async Task<IActionResult> UpdateData([FromBody] Data Data)
        {
            try
            {
                // Kiểm tra trùng tên nhóm
                bool isDuplicate = CheckDuplicateDataName(Data.dataId, Data.dataName);
                if (isDuplicate)
                {
                    return StatusCode(StatusCodes.Status400BadRequest, "File name already exists");
                }

                // Thực hiện cập nhật tên nhóm trong cơ sở dữ liệu
                bool isSuccess = UpdateDataName(Data);
                if (isSuccess)
                {
                    return StatusCode(StatusCodes.Status200OK, "Data updated successfully");
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Failed to update group");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }

        private bool CheckDuplicateDataName(int DataId, string DataName)
        {
            // Kiểm tra trùng tên nhóm trong cơ sở dữ liệu, trừ nhóm hiện tại đang được sửa
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectGroup = "SELECT COUNT(*) FROM data WHERE dataName = @dataName AND dataId != @dataId";

            var parameters = new DynamicParameters();
            parameters.Add("@dataName", DataName);
            parameters.Add("@dataId", DataId);

            int count = mySqlConnection.ExecuteScalar<int>(selectGroup, parameters);

            return count > 0;
        }

        private bool UpdateDataName(Data data)
        {
            // Cập nhật tên nhóm trong cơ sở dữ liệu
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện cập nhật trong MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string updateDataQuery = "UPDATE data SET dataName = @dataName, dataValue = @dataValue WHERE dataId = @dataId";

            var parameters = new DynamicParameters();
            parameters.Add("@dataName", data.dataName);
            parameters.Add("@dataValue", data.dataValue);
            parameters.Add("@dataId", data.dataId);

            int rowsAffected = mySqlConnection.Execute(updateDataQuery, parameters);

            return rowsAffected > 0;
        }



        /// <summary>
        /// 
        /// 
        /// </summary>
        /// <param name="groupId"></param>
        /// <returns></returns>

        [HttpDelete("deleteData/{DataId}")]
        public async Task<IActionResult> DeleteData(int dataId)
        {
            try
            {
                // Kiểm tra sự tồn tại của Data dựa trên GroupId
                bool DataExists = CheckDataExists(dataId);
                if (!DataExists)
                {
                    return StatusCode(StatusCodes.Status404NotFound, "Data not found");
                }
                // Thực hiện xóa Data trong cơ sở dữ liệu
                bool deleteDataSuccess = DeleteDataFromDatabase(dataId);
                if (deleteDataSuccess)
                {
                    return StatusCode(StatusCodes.Status200OK, "Data deleted successfully");
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Failed to delete Data");
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
            }
        }


        private bool CheckDataExists(int dataId)
        {
            // Kiểm tra sự tồn tại của Data dựa trên GroupId trong cơ sở dữ liệu
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectData = "SELECT COUNT(*) FROM data WHERE dataId = @dataId";

            var parameters = new DynamicParameters();
            parameters.Add("@dataId", dataId);

            int count = mySqlConnection.ExecuteScalar<int>(selectData, parameters);

            return count > 0;
        }

        private bool DeleteDataFromDatabase(int dataId)
        {
            // Xóa Data từ cơ sở dữ liệu dựa trên GroupId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện xóa trong MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string deleteData = "DELETE FROM data WHERE dataId = @dataId";

            var parameters = new DynamicParameters();
            parameters.Add("@dataId", dataId);

            int rowsAffected = mySqlConnection.Execute(deleteData, parameters);

            return rowsAffected > 0;
        }
    }



}
