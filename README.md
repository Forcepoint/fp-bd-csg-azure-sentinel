# Forcepoint Cloud Security Gateway with Azure Sentinel

This integration provides step by step instructions to configure an
event-driven pipeline to export Forcepoint Cloud Security Gateway
web/email logs to Azure Sentinel. for the guide visit: <https://forcepoint.github.io/docs/csg_and_sentinel/>


Note:
The integration uses compiled code, if you need to recompile the code, an encryption key with size 16, 24 or 32 needs
to be passed to the compile command. The encryption key is used to encrypt Forcepoint CSG credentials and save
the encrypted credentials in the integration's host-machine.

- for docker implementation: open the Dockerfile, in the compile command, add your encryption key as value for **main.encryptionKey** parameter to the compile command.
  for example:

   ```
   RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -a -installsuffix cgo -ldflags "-X 'main.encryptionKey=MyEncryptionKey1' -extldflags '-static'" -o csg-sentinel .
   ```
- for traditional implementation: add your encryption key as value for **main.encryptionKey** parameter.
  for example:

  ```
  CGO_ENABLED=0 GOOS=linux go build -mod=vendor -a -installsuffix cgo -ldflags "-X 'main.encryptionKey=MyEncryptionKey1' -extldflags '-static'" -o csg-sentinel .
  ```
  