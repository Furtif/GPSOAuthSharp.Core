# GPSOAuthSharp.NetStandard1 [![Build status](https://ci.appveyor.com/api/projects/status/0qh74gd1gmyanmxb/branch/master?svg=true)](https://ci.appveyor.com/project/RocketBot/gpsoauthsharp-core/branch/master) [![NuGet](https://img.shields.io/nuget/v/GPSOAuthSharp.Core.svg?maxAge=60)](https://www.nuget.org/packages/GPSOAuthSharp.Core)

A .NET client library for Google Play Services OAuth written in C#.

This is a C# port of https://github.com/simon-weber/gpsoauth

# Installation

## Supported Platforms

* .NET Standard 1.1 ([Specific platforms](https://github.com/dotnet/corefx/blob/master/Documentation/architecture/net-platform-standard.md#mapping-the-net-platform-standard-to-platforms))

## Installation

Installation is done via NuGet:

    PM> Install-Package GPSOAuthSharp.Core
    
https://www.nuget.org/packages/GPSOAuthSharp.Core/

# Usage
Construct a `GPSOAuthSharp.GPSOAuthClient(email, password)`.

Use `PerformMasterLogin()` or `PerformOAuth()` to retrieve a `Dictionary<string, string>` of response values. 
