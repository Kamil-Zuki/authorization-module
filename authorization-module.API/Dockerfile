#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER app
WORKDIR /app
EXPOSE 80
<<<<<<< HEAD
=======
EXPOSE 43
>>>>>>> d41bd98a72a2bb3a39e73655f4d908f75ecfe9eb

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["authorization-module.API/authorization-module.API.csproj", "authorization-module.API/"]
RUN dotnet restore "./authorization-module.API/./authorization-module.API.csproj"
COPY . .
WORKDIR "/src/authorization-module.API"
RUN dotnet build "./authorization-module.API.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./authorization-module.API.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "authorization-module.API.dll"]