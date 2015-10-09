# zfsbackup

This perl module installs an executable script zfsonaws which allows users to upload zfs snapshots directly an Amazon S3 bucket of his/her choosing.

Conversely, if the user would like to recover one of the snapshots uploaded to Amazon S3, he/she first downloads the checksum file and the snapshot.

As of 2015-10-08, only full zfs snapshots backups have been implemented.

## Backing up

To run backups, execute the following in bash:
```bash
zfsonaws backup

```

This command will do the following:

1. Look for all snapshots that are of the following format: tank/example@20151001, ie filesystempath@YYYYMMDD.
2. Check to see if that snapshot is in the s3 bucket.
3. If not, then do the following:
  1. Run zfs send tank/example
  2. Compress with bzip2 -c
  3. Encrypt it using [Crypt::CBC](http://search.cpan.org/~lds/Crypt-CBC-2.33/CBC.pm) with the backend module being Crypt::OpenSSL::AES.
  4. Using the aws cli from Amazon, copy the snapshot into the s3 bucket
   
## Restoring   

To recover, just do step 3 inversely like the following:

1. Download the snapshot from the s3 bucket to, say, /var/tmpbackup/snapshot.crypt
2. Download the checksum file from s3, decrypt it somewhere and store the clear text file at, say, /var/tmpbackup/snapshot.checksum
3. Run the following in bash:
```bash
zfsonaws recover /var/tmpbackup/snapshot.checksum /var/tmpbackup/snapshot.crypt | bzcat - | zfs receive -F tank/newexample
```

## Prereqs

For software requirements, the following are required:

1. [aws cli](http://aws.amazon.com/documentation/cli/)
  1. Please configure a user with the proper Access Keys
  2. Have a bucket set up on S3
2. bzcat and bzip2 to handle compression
3. Have a location on which to temporarily store backup data. For example:
  1. Create a file system for storing data temporarily 
```bash
zfs create -o mountpoint=/var/tmpbackup tank/tmpbackup
```
  1. Make /var/tmpbackup unreadable to outside users 
```bash
chmod 0700 /var/tmpbackup
```
4. Create a gpg keyring for the backup user (ie root) to encrypt the checksum file.
```bash
gpg --list-keys
gpg --import /tmp/pubkeys_of_specialuser
gpg --edit-key 844FBC00
```
  * When editing the gpg key, set trust to ultimate by typing trust at the prompt and typing 5


For configuration, create a file at /etc/zfsbackup/backup.conf that looks like:
```json
{
    "bucket": "backups-bucket",
    "tmppath": "/var/tmpbackup",
    "tmpfs": "tank/tmpbackup",
    "recipient": "backupuser@example.com"
}
```
  * For the recipient, make sure the email address matches the gpg key imported in step 4.