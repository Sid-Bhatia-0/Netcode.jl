# Netcode

A Julia implemenation of the awesome netcode protocol: https://github.com/mas-bandwidth/netcode/blob/main/STANDARD.md

**NOTE: This package is under heavy development and is NOT complete**

## Getting started

Go to the `examples` directory and run the following commands in separate shell instances.

To start an authentication server instance:

```
julia --project=. examples/simulate.jl --auth_server
```

To start an application (game) server instance:

```
julia --project=. examples/simulate.jl --app_server
```

To start a client instance (run after the authentication and application server instances have started listening):

```
julia --project=. examples/simulate.jl --client
```
