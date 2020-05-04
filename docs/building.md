## Building from source

Ensure you have Golang 1.11 (or newer) and Git installed

    go version
    git --version
    
First clone the Louketo Proxy repository:
    
    git clone https://github.com/louketo/louketo-proxy.git
    cd louketo
    
To build Louketo Proxy run:

    make && make test
    
This will compile Go files and package the results into a binary file inside `bin/louketo-proxy` and run the testsuite. 

To build a distribution run:

    make release
    
Once completed you will find distribution archives in the `release` folder.

## Starting Louketo

To start Louketo Proxy during development first build as specified above, then run:

    bin/louketo-proxy

## Working with the codebase

We don't currently enforce a code style in Louketo, because Go already have tools to ensure that code is properly formatted. Before submitting any pull request, please run:

    make format && make lint

If your changes require introducing new dependencies or updating dependency versions please discuss this first on the mailing list. We do not accept new dependencies to be added lightly, so try to use what is available.
