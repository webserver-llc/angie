#!/bin/sh

# Copyright (C) 2024 Web Server LLC

# Example script for configuring cross-build targets
#
# Arguments are:
#
# $1 - autotest binary
# $2 - test type
# $3 - test arguments (for example, type name for sizeof)

# the real life scenarios will either invoke binary on remote/VM
# or provide platform-specific values for each test

case "$2" in

    "feature")

        case "$3" in
            "NGX_HAVE_SENDFILE")
                # pretend feature is missing
                exit 1
            ;;
            *)
                # pretend success
                exit 0
            ;;
        esac

        ;;

    "sizeof")

        # report platform-specific values
        case "$3" in
            "int") echo 4 ;;
            "long") echo 8 ;;
            "long long") echo 8;;
            "void *") echo 8 ;;
            "size_t") echo 8 ;;
            "off_t") echo 8 ;;
            "time_t") echo 8 ;;
            "sig_atomic_t") echo 4 ;;
            "*")
                echo "unknown type"
                exit 1
                ;;
        esac
        ;;

    "endianness")
            # 0 -> LE, 1 -> BE
            exit 0
        ;;

    *)
        echo "unknown test"
        exit 1 ;;
esac
