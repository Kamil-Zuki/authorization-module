using authorization_module.API.Dtos;
using AutoMapper;
using Pvs.Auth.Grpc;
using DtoConfirmEmailRequest = authorization_module.API.Dtos.ConfirmEmailRequest;
using DtoRefreshTokenRequest = authorization_module.API.Dtos.RefreshTokenRequest;
using GrpcConfirmEmailRequest = Pvs.Auth.Grpc.ConfirmEmailRequest;
using GrpcRefreshTokenRequest = Pvs.Auth.Grpc.RefreshTokenRequest;

namespace authorization_module.API.Mappers.AutoMapperProfiles;

/// <summary>
/// AutoMapper профиль для маппинга авторизации
/// </summary>
public class AuthMappingProfile : Profile
{
    public AuthMappingProfile()
    {
        // RegisterUserRequest (gRPC) -> UserRegistrationRequest (DTO)
        CreateMap<RegisterUserRequest, UserRegistrationRequest>();

        // StringResultDto (DTO) -> RegisterUserResponse (gRPC)
        CreateMap<StringResultDto, RegisterUserResponse>()
            .ForMember(dest => dest.Message, opt => opt.MapFrom(src => src.Data));

        // LoginUserRequest (gRPC) -> UserLoginRequest (DTO)
        CreateMap<LoginUserRequest, UserLoginRequest>();

        // TokenDto (DTO) -> TokenResponse (gRPC)
        CreateMap<TokenDto, TokenResponse>();

        // RefreshTokenRequest (gRPC) -> RefreshTokenRequest (DTO)
        CreateMap<GrpcRefreshTokenRequest, DtoRefreshTokenRequest>();

        // ConfirmEmailRequest (gRPC) -> ConfirmEmailRequest (DTO)
        CreateMap<GrpcConfirmEmailRequest, DtoConfirmEmailRequest>();

        // StringResultDto (DTO) -> MessageResponse (gRPC)
        CreateMap<StringResultDto, MessageResponse>()
            .ForMember(dest => dest.Message, opt => opt.MapFrom(src => src.Data));

        // UserInfoDto (DTO) -> UserInfoResponse (gRPC)
        CreateMap<UserInfoDto, UserInfoResponse>();
    }
}
