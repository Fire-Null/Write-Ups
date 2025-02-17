# Challenge: Cat
## Rate: Easy

This challenge gives us only a file named `cat.ab`. `.ab` files are Android Backup files created by the `adb backup` command, part of the Android Debug Bridge (ADB) toolkit. They are used to back up application data, settings, and, sometimes, parts of the Android system.
Let's extract the backup:
```bash
java -jar abe.jar unpack cat.ab cat.tar
```
The `abe.jar` Converts the Android backup file `cat.ab` into a tar archive `cat.tar`.
Now.

Now extract the `cat.tar` which is an **unprotected backup file**.
```bash
tar -xvf cat.tar
```
```bash
➜ tree
.
└── cat
   ├── apps
   └── shared
       └── 0
           ├── Alarms
           ├── DCIM
           ├── Download
           ├── Movies
           ├── Music
           ├── Notifications
           ├── Pictures
           │   ├── IMAG0001.jpg
           │   ├── IMAG0002.jpg
           │   ├── IMAG0003.jpg
           │   ├── **IMAG0004.jpg**
           │   ├── IMAG0005.jpg
           │   └── IMAG0006.jpg
           ├── Podcasts
           └── Ringtones
```

- `IMAG0004.jpg`
    
    ![flag.png](flag.png)
    

**Flag**: `HTP{ThisBackupIsUnprotected}`
