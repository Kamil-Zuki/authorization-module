#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.
#
#FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
#USER app
#WORKDIR /app
#EXPOSE 8080
#EXPOSE 8081
#
#FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
#ARG BUILD_CONFIGURATION=Release
#WORKDIR /src
#COPY ["authorization-module.API/authorization-module.API.csproj", "authorization-module.API/"]
#RUN dotnet restore "./authorization-module.API/./authorization-module.API.csproj"
#COPY . .
#WORKDIR "/src/authorization-module.API"
#RUN dotnet build "./authorization-module.API.csproj" -c $BUILD_CONFIGURATION -o /app/build
#
#FROM build AS publish
#ARG BUILD_CONFIGURATION=Release
#RUN dotnet publish "./authorization-module.API.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false
#
#FROM base AS final
#WORKDIR /app
#COPY --from=publish /app/publish .
#ENTRYPOINT ["dotnet", "authorization-module.API.dll"]

# Assuming the Docker build context is set to the api-gateway directory

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
<<<<<<< HEAD:authorization-module.API/Dockerfile
EXPOSE 80
=======
EXPOSE 8080
EXPOSE 8081
>>>>>>> da72d652bfff2dcd0eed73a9cc757b7c44b5f994:Dockerfile

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Adjust the path to correctly reference the .csproj file from the Docker build context
COPY ["../authorization-module/authorization-module.API/authorization-module.API.csproj", "authorization-module.API/"]
RUN dotnet restore "authorization-module.API/authorization-module.API.csproj"

# Copy everything else and build
COPY . .
WORKDIR "/src/authorization-module.API"
RUN dotnet build "authorization-module.API.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "authorization-module.API.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "authorization-module.API.dll"]
