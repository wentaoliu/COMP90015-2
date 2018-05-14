# ActivityStreamer

COMP90015 Distributed Systems __Project 2__

The compiled `.jar` files are located in the `target` directory.

Requires JRE 8 or above.

## ActivityStreamerServer

* Run as the root (first server):

    ```
    java -jar ActivityStreamerServer.jar [-lh <localhost>] [-lp <local port>] [-a <activity interval>]
    ```

* Connect to an existing server:

    ```
    java -jar ActivityStreamerServer.jar -s <secret> -rh <remote host> [-rp <remote port>] [-lh <localhost>] [-lp <local port>] [-a <activity interval>]
    ```

## ActivityStreamerClient

* Login as `anonymous`:

    ```
    java -jar ActivityStreamerClient.jar -rp <remote host> [-rp <remote port>]
    ```

* Login with username and password:

    ```
    java -jar ActivityStreamerClient.jar -u <username> -s <secret> -rp <remote host> [-rp <remote port>]
    ```

* Register a username:

    ```
    java -jar ActivityStreamerClient.jar -u <username> -rp <remote host> [-rp <remote port>]
    ```