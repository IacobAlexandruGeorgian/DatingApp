using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Entities;
using System.ServiceModel;

namespace API.interfaces
{
    public interface ITokenService
    {
        string CreateToken(AppUser user);
    }
}