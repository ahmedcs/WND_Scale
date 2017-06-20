# Makefile update
If the source file has been changed, you need to update the name of the object file to match the new source file containing the module init_module and exit_module macros and the definition functions. SEE Makefile for more information.

Notice, you can include other source and header files but under the condition that there is a single source file containing the neccessary init_module and exit_module macros and their function.

# Installation steps

change your current directory to to where the source and Makefile is located then issue:

```
git clone https://github.com/ahmedcs/IncastGuard.git
cd endhost_wndscale
make
```

Now the output files is as follows:
```
endhost_wndscale.o and endhost_wndscale.ko
```
The file ending with .o is the object file while the one ending in .ko is the module file


# Run
To install the module into the kernel
```
sudo insmode endhost_wndscale.ko
```

Note that there are no parameters involved in this module.
```

# Stop

To stop the loss_probe module and free the resources issue the following command:

```
sudo rmmod -f endhost_wndscale;
```
