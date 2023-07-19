using Microsoft.AspNetCore.Mvc;
using authorization_module.API.Data;

namespace authorization_module.API.Controllers;

[ApiController]
public class ApiController : ControllerBase
{
    public ApiController(DataContext dataContext)
    {
        DataContext = dataContext;
    }

    public readonly DataContext DataContext;
}