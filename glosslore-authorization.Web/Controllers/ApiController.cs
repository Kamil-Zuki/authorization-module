using Microsoft.AspNetCore.Mvc;
using Glosslore_authorization.Web.Data;

namespace Glosslore_authorization.Web.Controllers;

[ApiController]
public class ApiController : ControllerBase
{
    public ApiController(DataContext dataContext)
    {
        DataContext = dataContext;
    }

    public readonly DataContext DataContext;
}