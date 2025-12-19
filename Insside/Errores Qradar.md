#test
 QRadar: Upgrade failed on Managed Host due to a tomcat error

https://www.ibm.com/support/pages/node/7234008


## Resolving The Problem

Administrators can perform the next steps to resolve this issue:

  

1. Use SSH to log in as root user to the QRadar Console.
2. Use SSH to log in to the Affected QRadar Host as the root user
3. Stop hostcontext service:
    
    ```shell
    systemctl stop hostcontext
    ```
    
4. Create the below flag file:
    
    ```bash
    touch /opt/qradar/conf/hostcontext.STOP
    ```
    
    **Note:** The purpose of this flag is for the hostcontext service remain stopped during the process.
5. Then re-ran the installer:
    
    ```bash
    /media/updates/installer
    ```
    
6. Once the installer finishes, remove the flag:
    
    ```bash
    rm -rf /opt/qradar/conf/hostcontext.STOP
    ```
    
7. Start hostcontext service:
    
    ```bash
    systemctl start hostcontext
    ```

------

Error SAML 2.0 "Minimum"

vi store/configservices/staging/globalconfig/login.conf

Add this:

`authContextComparisonType=exact`

Save and deploy.

The new SAML request should have value as exact.

---------

Restore login system:

## Restore system login for investigation[](https://www.ibm.com/docs/en/qsip/7.5?topic=authentication-troubleshooting-saml#t_qradar_saml_troubleshoot__title__5 "Copy to clipboard")

To investigate issues with SAML 2.0, you can restore QRadar to use the default system login.

Copy the content of the
**/opt/qradar/conf/templates/login.conf into /opt/qradar/conf/login.conf**

Alternatively, edit the /opt/qradar/conf/login.conf file and change

```bash
ModuleClass=com.q1labs.uiframeworks.auth.configuration.SamlLoginConfiguration
```

to

```bash
ModuleClass=com.q1labs.uiframeworks.auth.configuration.LocalPasswordLoginConfiguration
```

---------------

Arreglar error "# "AADSTS75011" ERROR RECEIVED WHEN USING SAML PASSWORDLESS AUTHENTICATION"

1. Use SSH to log in to the QRadar Console as the root user.
2. Create a directory for backups:
    
    ```bash
    mkdir -pv /store/ibm_support/7229812/ 
    ```
    
3. Backup the nva.conf file:
    
    ```bash
    cp -pv /store/configservices/staging/globalconfig/nva.conf /store/ibm_support/7229812/nva.conf_bkp
    ```
    
4. Add the following parameter to the nva.conf configuration file by running this command`:`
    
    ```bash
    echo 'CHECK_SAML_AUTHCONTEXT=false' >> /store/configservices/staging/globalconfig/nva.conf
    ```
    
5. The administrator runs a Deploy Configuration Changes from the console GUI.
    
6. Restart the Tomcat service by running the following command:  
    **Note:** Restarting Tomcat ends all active user sessions and logs out all users. When the Tomcat service is stopped or restarting, the QRadar user interface is not available.
    
    ```bash
    systemctl restart tomcat
    ```