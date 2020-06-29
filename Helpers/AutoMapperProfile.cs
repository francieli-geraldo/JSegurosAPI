using AutoMapper;
using JSegurosAPI.Entities;
using JSegurosAPI.Models.Users;

namespace JSegurosAPI.Helpers
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<User, UserModel>();
            CreateMap<RegisterModel, User>();
            CreateMap<UpdateModel, User>();
        }
    }
}