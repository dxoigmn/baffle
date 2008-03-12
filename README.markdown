Baffle
======

Baffle is a tool for actively fingerprinting and identifying wireless devices.
See ./tool --help for options.

Compiling
---------

Because we need to be able to sniff and inject arbitrary 802.11 packets, we
need help from a few C-libraries (see Depedencies). Before running Baffle,
you must compile the Ruby extensions wrapping these libraries. Generally, it
it done in the following manner:

>  $ ruby extconf
>  $ make
  
You will need to run these commands in the following directories:
  
  - ./lib/capture/
  - ./lib/ruby-lorcon/

Linalg depends on LAPACK, a fortran linear algebra package, and on f2c, a 
fortran to C bridge. These can typically be installed from package management
systems or compiled from source.
The ruby linalg library itself is compiled with the following commands:

>  $ ruby install.rb configure
>  $ ruby install.rb make
>  $ sudo ruby install.rb install

Once those dependencies are met, everything should work fine.

Depedencies
-----------

  + C-libraries
    - lorcon
    - libpcap
  
  + Fortran libraries
    - LAPACK

  + Ruby libraries
    - linalg (depends on the LAPACK fortran library and f2c library)

