using ApiCamScanner.Entities;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using MySqlConnector;

namespace ApiCamScanner.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DataTypesController : ControllerBase
    {
        private readonly IConfiguration _config;

        public DataTypesController(IConfiguration config)
        {
            _config = config;
        }

        [HttpPost("InsertDataType")]
        public async Task<IActionResult> InsertDataType([FromBody] DataTypes datatype)
        {
            try
            {
                string connectionString = _config.GetConnectionString("MyConnection");

                var mySqlConnection = new MySqlConnection(connectionString);

                string insertDataType = "INSERT INTO datatype (dataTypeName, documentId) VALUES (@dataTypeName, @documentId); SELECT LAST_INSERT_ID()";

                    var parameters = new DynamicParameters();
                    parameters.Add("@dataTypeName", datatype.dataTypeName);
                    parameters.Add("@documentId", datatype.documentId);
                  

                    // Execute the SQL query to insert the image and retrieve the last inserted ID
                    int datatypeId = mySqlConnection.ExecuteScalar<int>(insertDataType, parameters);

                     datatype.dataTypeId = datatypeId;

                    return StatusCode(StatusCodes.Status200OK, datatype );
                
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status400BadRequest, exception.Message);
            }
        }


        [HttpGet]
        [Route("getAllDataType/{documentId}")]
        public async Task<IActionResult> GetAllDataType(int documentId)
        {
            try
            {   
                // Lấy tất cả các nhóm dựa trên userId
                List<DataTypes> dataTypes = GetAllDataTypeByDocumentId(documentId);

                return StatusCode(StatusCodes.Status200OK, dataTypes);
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, exception.Message);
            }
        }

        private List<DataTypes> GetAllDataTypeByDocumentId(int documentId)
        {
            // Lấy tất cả các nhóm từ cơ sở dữ liệu dựa trên userId
            // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

            string connectionString = _config.GetConnectionString("MyConnection");

            MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

            string selectDataType = "SELECT * FROM datatype WHERE documentId = @documentId";

            var parameters = new DynamicParameters();
            parameters.Add("@documentId", documentId);

            List<DataTypes> groups = mySqlConnection.Query<DataTypes>(selectDataType, parameters).ToList();

            return groups;
        }


        ///// <summary>
        ///// Update
        ///// </summary>
        ///// <param name="group"></param>
        ///// <returns></returns>
        //[HttpPut("updateGroup")]
        //public async Task<IActionResult> UpdateGroup([FromBody] GroupImage group)
        //{
        //    try
        //    {
        //        // Kiểm tra trùng tên nhóm
        //        bool isDuplicate = CheckDuplicateGroupName(group.groupId, group.groupName);
        //        if (isDuplicate)
        //        {
        //            return StatusCode(StatusCodes.Status400BadRequest, "Group name already exists");
        //        }

        //        // Thực hiện cập nhật tên nhóm trong cơ sở dữ liệu
        //        bool isSuccess = UpdateGroupName(group.groupId, group.groupName);
        //        if (isSuccess)
        //        {
        //            return StatusCode(StatusCodes.Status200OK, "Group updated successfully");
        //        }
        //        else
        //        {
        //            return StatusCode(StatusCodes.Status500InternalServerError, "Failed to update group");
        //        }
        //    }
        //    catch (Exception exception)
        //    {
        //        Console.WriteLine(exception.Message);
        //        return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
        //    }
        //}

        //private bool CheckDuplicateGroupName(int groupId, string groupName)
        //{
        //    // Kiểm tra trùng tên nhóm trong cơ sở dữ liệu, trừ nhóm hiện tại đang được sửa
        //    // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

        //    string connectionString = _config.GetConnectionString("MyConnection");

        //    MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

        //    string selectGroup = "SELECT COUNT(*) FROM groupimages WHERE groupName = @groupName AND groupId != @groupId";

        //    var parameters = new DynamicParameters();
        //    parameters.Add("@groupName", groupName);
        //    parameters.Add("@groupId", groupId);

        //    int count = mySqlConnection.ExecuteScalar<int>(selectGroup, parameters);

        //    return count > 0;
        //}

        //private bool UpdateGroupName(int groupId, string groupName)
        //{
        //    // Cập nhật tên nhóm trong cơ sở dữ liệu
        //    // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện cập nhật trong MySQL

        //    string connectionString = _config.GetConnectionString("MyConnection");

        //    MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

        //    string updateGroup = "UPDATE groupimages SET groupName = @groupName WHERE groupId = @groupId";

        //    var parameters = new DynamicParameters();
        //    parameters.Add("@groupName", groupName);
        //    parameters.Add("@groupId", groupId);

        //    int rowsAffected = mySqlConnection.Execute(updateGroup, parameters);

        //    return rowsAffected > 0;
        //}



        ///// <summary>
        ///// 
        ///// 
        ///// </summary>
        ///// <param name="groupId"></param>
        ///// <returns></returns>

        //[HttpDelete("deleteGroupImage/{groupId}")]
        //public async Task<IActionResult> DeleteGroupImage(int groupId)
        //{
        //    try
        //    {
        //        // Kiểm tra sự tồn tại của GroupImage dựa trên GroupId
        //        bool groupImageExists = CheckGroupImageExists(groupId);
        //        if (!groupImageExists)
        //        {
        //            return StatusCode(StatusCodes.Status404NotFound, "GroupImage not found");
        //        }

        //        // Xóa tất cả các Image trong GroupImage trước
        //        DeleteAllImagesInGroup(groupId);


        //        // Thực hiện xóa GroupImage trong cơ sở dữ liệu
        //        bool deleteGroupImageSuccess = DeleteGroupImageFromDatabase(groupId);
        //        if (deleteGroupImageSuccess)
        //        {
        //            return StatusCode(StatusCodes.Status200OK, "GroupImage deleted successfully");
        //        }
        //        else
        //        {
        //            return StatusCode(StatusCodes.Status500InternalServerError, "Failed to delete GroupImage");
        //        }
        //    }
        //    catch (Exception exception)
        //    {
        //        Console.WriteLine(exception.Message);
        //        return StatusCode(StatusCodes.Status500InternalServerError, "An error occurred");
        //    }
        //}


        //private bool CheckGroupImageExists(int groupId)
        //{
        //    // Kiểm tra sự tồn tại của GroupImage dựa trên GroupId trong cơ sở dữ liệu
        //    // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để truy vấn dữ liệu từ MySQL

        //    string connectionString = _config.GetConnectionString("MyConnection");

        //    MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

        //    string selectGroupImage = "SELECT COUNT(*) FROM groupimages WHERE groupId = @groupId";

        //    var parameters = new DynamicParameters();
        //    parameters.Add("@groupId", groupId);

        //    int count = mySqlConnection.ExecuteScalar<int>(selectGroupImage, parameters);

        //    return count > 0;
        //}

        //private bool DeleteGroupImageFromDatabase(int groupId)
        //{
        //    // Xóa GroupImage từ cơ sở dữ liệu dựa trên GroupId
        //    // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện xóa trong MySQL

        //    string connectionString = _config.GetConnectionString("MyConnection");

        //    MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

        //    string deleteGroupImage = "DELETE FROM groupimages WHERE groupId = @groupId";

        //    var parameters = new DynamicParameters();
        //    parameters.Add("@groupId", groupId);

        //    int rowsAffected = mySqlConnection.Execute(deleteGroupImage, parameters);

        //    return rowsAffected > 0;
        //}
        //private void DeleteAllImagesInGroup(int groupId)
        //{
        //    // Xóa tất cả các Image trong GroupImage từ cơ sở dữ liệu dựa trên GroupId
        //    // Ví dụ: Sử dụng ORM (Entity Framework, Dapper) để thực hiện xóa trong MySQL

        //    string connectionString = _config.GetConnectionString("MyConnection");

        //    MySqlConnection mySqlConnection = new MySqlConnection(connectionString);

        //    string deleteImages = "DELETE FROM images WHERE groupId = @groupId";

        //    var parameters = new DynamicParameters();
        //    parameters.Add("@groupId", groupId);

        //    int rowsAffected = mySqlConnection.Execute(deleteImages, parameters);

        //}


    }



}
