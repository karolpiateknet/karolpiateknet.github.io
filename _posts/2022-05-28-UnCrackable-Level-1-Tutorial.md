---
layout: single
title: UnCrackable Level 1 tutorial
author_profile: true
---

Uncrakable apps are one of the most popular mobile reverse engineering challenges.
You will find here complete tutorial on how to solve UnCrackable Level 1 in different ways to get the hidden key, but we will also bypass checks just to get the success Alert.

Task: A secret string is hidden somewhere in this app. Find a way to extract it.


# Recon

Before writing script to extract the key or bypass checks, we will perform recon to understand app login.

## Playing with app

On the main screen of the application, we can see a single text field with the button to enter secret string.
After entering random value and pressing the verify button, we will see an error message saying it is a wrong value.
Let's see how we can find this value.

Main screen                |  Failed Verification
:-------------------------:|:-------------------------:
![Main screen](/assets/images/posts/UnCrackable1/uncrackable1-main-screen.png)  |  ![Failed Verification](/assets/images/posts/UnCrackable1/uncrackable1-failed-verification.png)

## Understanding Android app with Jadx

Easiest way to understand Android application code is to decompile Dalvik bytecode to java classes from APK. 
You can use the jadx tool for this. Keep in mind that it might not work with all APK files, as they may be protected with different obfuscation techniques or use not compatible Java versions. So sometimes it is worth trying multiple versions of jadx in order to decompile Dalvik code.

### Installation

```console
brew install jadx
```

### Running Jadx

```console
jadx UnCrackable-Level1.apk
```

### Understanding app logic

After decompilation of UnCrackable-Level1, we can see structure of the project . 
We would like to find the MainActivity.java file, which is the app starting point in Android applications.

File is present in the directory:

```console
UnCrackable-Level1/sources/sg/vantagepoint/uncrackable1/MainActivity.java
```

and if statement responsible for showing adequate alert message is present in this file:

```java
if (a.a(obj)) {
  create.setTitle("Success!");
  str = "This is the correct secret.";
} else {
  create.setTitle("Nope...");
  str = "That's not it. Try again.";
}
```

Success alert will be presented when function *a* from *a* class will return true. 
Let’s find out what’s inside *a* class. 

*a* class file Path: 

```console 
UnCrackable-Level1/sources/sg/vantagepoint/a/a.java
```

*a* class:

```java
public static boolean a(String str) {
    byte[] bArr;
    byte[] bArr2 = new byte[0];
    try {
        bArr = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
    } catch (Exception e) {
        Log.d("CodeCheck", "AES error:" + e.getMessage());
        bArr = bArr2;
    }
    return str.equals(new String(bArr));
}
```

Function is comparing two strings and returns the value of this comparison as a result. 
Secret string is retrieved using the *sg.vantagepoint.a.a.a* function with two String arguments. 
One is the result of `"5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="` Base64 decoding and 
the second one is the result of the function call: `b("8d127684cbc37c17616d806cf50473cc")`. Which performs some operations to change String to byte array.

Inside *sg.vantagepoint.a.a.a* function those two byte arrays are being encrypted using AES algorithm and the result is the secret key that we are looking for.

*sg.vantagepoint.a.a* class:

```java
public class a {
   public static byte[] a(byte[] bArr, byte[] bArr2) {
       SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES/ECB/PKCS7Padding");
       Cipher instance = Cipher.getInstance("AES");
       instance.init(2, secretKeySpec);
       return instance.doFinal(bArr2);
   }
}
```

## Recon Pro tip

When working with obfuscated code, it is good practice to rename obfuscated methods to meaningful names.
Gradually renaming functions will make your code more and more readable.

Obfuscated code:

```java
public class a {
    public static boolean a(String str) {
        byte[] bArr;
        byte[] bArr2 = new byte[0];
        try {
            bArr = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
        } catch (Exception e) {
            Log.d("CodeCheck", "AES error:" + e.getMessage());
            bArr = bArr2;
        }
        return str.equals(new String(bArr));
    }

    public static byte[] b(String str) {
        int length = str.length();
        byte[] bArr = new byte[(length / 2)];
        for (int i = 0; i < length; i += 2) {
            bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return bArr;
    }
}
```

Code after renames:

```java
/// Class is responsible for managing the hidden secret.
public class SecretManager {

    /// Function compares passed string with secret.
    /// - Parameter userInput: String entered by the user inside the textField.
    public static boolean compareSecret(String userInput) {
        byte[] bArr;
        byte[] bArr2 = new byte[0];
        try {
            bArr = sg.vantagepoint.a.a.a(transformToByteArray("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
        } catch (Exception e) {
            Log.d("CodeCheck", "AES error:" + e.getMessage());
            bArr = bArr2;
        }
        return str.equals(new String(bArr));
    }

    /// Function transforms string into byte array.
    /// - Parameter str: String to be transformed to byte array.
    public static byte[] transformToByteArray(String str) {
        int length = str.length();
        byte[] bArr = new byte[(length / 2)];
        for (int i = 0; i < length; i += 2) {
            bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return bArr;
    }
}

```

# Solutions

## Solution 1: Find the keys comparison method and print out the secret key

First solution to retrieve a hidden key is to copy / paste methods that are responsible for decryption of the secret key and print out decrypted value.
We can change *compareSecret* function to return the value instead of comparing it to userInput.

*Note: As it is Android code, it is not possible to run it in the same way using just Java, it has to be run on Android device or adjusted to normal Java code.*

```java
/// Function compares passed string with secret.
/// - Parameter userInput: String entered by the user inside the textField.
public static String compareSecret(String userInput) {
    byte[] bArr;
    byte[] bArr2 = new byte[0];
    try {
        bArr = decryptHiddenKey(transformToByteArray("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
    } catch (Exception e) {
        Log.d("CodeCheck", "AES error:" + e.getMessage());
        bArr = bArr2;
    }
    return new String(bArr);
}

/// Function transforms string into byte array.
/// - Parameter str: String to be transformed to byte array.
public static byte[] transformToByteArray(String str) {
    int length = str.length();
    byte[] bArr = new byte[(length / 2)];
    for (int i = 0; i < length; i += 2) {
        bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
    }
    return bArr;
}

/// Decrypts hidden key encrypted by AES algorithm.
/// - Parameter aesSecretKey: secret key for AES algorithm.
/// - Parameter keyToDecrypt: Key to decrypt data.
public static byte[] decryptHiddenKey(byte[] aesSecretKey, byte[] keyToDecrypt) throws Exception {
    SecretKeySpec secretKeySpec = new SecretKeySpec(aesSecretKey, "AES/ECB/PKCS7Padding");
    try {
        Cipher instance = Cipher.getInstance("AES");
        instance.init(2, secretKeySpec);
        return instance.doFinal(keyToDecrypt);
    } catch (Exception e) {
        return null;
    }
}
```

Above you can find copy / pasted code from the app to get the secret, to get the hidden secret just call `print(compareSecret("some thing"))` it will print out the hidden secret.
Result:

*I want to believe*

After entering this value, we will get success message 🥳

![Success message](/assets/images/posts/UnCrackable1/uncrackable1-success.png)


## Solution 2: Frida script

Let's start with what is Frida?
In short simple words Frida allows to change applications behaviour without modifying application code, but change it while app code is being loaded.
You can read more about Frida [here](https://frida.re/docs/home/).

### [How to run Frida](https://frida.re/docs/android/)

Install frida following [tutorial](https://frida.re/docs/android/).

Run Frida with command, to run Frida server in the background:

```console
adb shell "/data/local/tmp/frida-server &"
```

When Frida is running, script can be attached to the app and modify its behaviour.
App identifier is needed to attach frida to specific app, app identifiers can be listed with command:

```console
MacBook-Pro:~ macbook$ frida-ps -Ua
 PID  Name          Identifier             
----  ------------  -----------------------
8337  Calendar      com.android.calendar   
8363  Clock         com.android.deskclock  
8909  Uncrackable1  owasp.mstg.uncrackable1
```

Then Frida could be attached with command:

```console
frida -U -l UncrackableLevel1.js  -f owasp.mstg.uncrackable1
```

Where `UncrackableLevel1.js` is a file which contains frida script.
It will be created in [section](#frida-code)

#### Pro tips

If you are using Android emulator remenber to use Android version without google API and google play.
As some of Android emulators may not allow adb root access, [see stackOverFlow thread](https://stackoverflow.com/questions/43923996/adb-root-is-not-working-on-emulator-cannot-run-as-root-in-production-builds).
I'm working on Nexus 6 API 29 without any problems.

If you got some problem with Frida, you can restart it using commands:
```console
adb shell 
ps -e | grep frida-server 
kill -9 PID_of_frida_process_from_previous_command
```

### Root detection bypass

After running the application on Rooted devices, app will detect root access and closie the app.
In order to be able to run the app without closing it we need to bypass those detections.

There are three checks that detects root, if even single one will return true our app will be closed.

```javascript
if (c.a() || c.b() || c.c()) {
  a("Root detected!");
}
```

Preventing app from closing can be achieved here in multiple ways, we can either override returned values by root checks to always return false or override `System.exit(0);` function to do not close the app.

#### Overriding root detection checks

Code for bypassing root detection functions and returning always false:

```javascript
/// Bypass root detection in UncracableLevel1.
function bypassRootDetection () {
    /// Class that has Root detection checks.
    var Runtime = Java.use('sg.vantagepoint.a.c');

    Runtime.a.overload().implementation = function(savedInstanceState) {
        return false;
    };

    Runtime.b.overload().implementation = function(savedInstanceState) {
        return false;
    };

    Runtime.c.overload().implementation = function(savedInstanceState) {
        return false;
    };
};
```

#### Overriding system exit function

Code for overriding system exit function to do not close app:

```javascript
/// Overrides system exit function to do nothing.
function overrideExit () {
    /// Class that has function which closes the app.
    var systemClass = Java.use("java.lang.System");

    systemClass.exit.overload("int").implementation = function(argument) {
      console.log("Do nothing");
    };
};
```

### Decryption function

The hidden secret can be decrypted in the same way as it is done in [Solution 1](#solution-1-find-the-comparison-method-and-print-out-the-key).
Script has to run all decrypting methods as it is done in the orginal code and return the hidden value.

Decryption script:

```javascript
function decryptSecret() {
    var base64 = Java.use('android.util.Base64');
    /// Decode hardcoded base64 secret from g.vantagepoint.uncrackable1.a.java class
    var aesSecret = base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0)

    /// Class contains method to change string to byte array.
    var cryptoClass = Java.use('sg.vantagepoint.uncrackable1.a');
    var aesKey = cryptoClass.b("8d127684cbc37c17616d806cf50473cc")

    /// Class contains a method to decrypt sekret encrypted by AES.
    var aesDecryptionClass = Java.use('sg.vantagepoint.a.a');
    var buffer = aesDecryptionClass.a(aesKey, aesSecret)

    return String.fromCharCode.apply(String, buffer);
};
```

### Bypass value check function

Other solution using Frida to get success alert would be to override check of the secret value to always return false.
It won't solve the challenge which is to find the hidden secret, but it will be an interesting way to get success alert.

```javascript
function bypassSecretCheck() {
    var secretCheckClass = Java.use('sg.vantagepoint.uncrackable1.a');
    secretCheckClass.a.overload('java.lang.String').implementation = function(a) {
        return true;
    };
};
```

### Complete Frida code - UncrackableLevel1.js

Complete frida code to solve the challenge in different ways:

```javascript
Java.perform(function() {

    /// Overrides system exit function to do nothing.
    function overrideExit () {
        /// Class that has function which closes the app.
        var systemClass = Java.use("java.lang.System");

        systemClass.exit.overload("int").implementation = function(argument) {
          console.log("Do nothing");
        };
    };

    /// Bypass root detection in UncracableLevel1.
    function bypassRootDetection () {
        /// Class that has Root detection checks.
        var Runtime = Java.use('sg.vantagepoint.a.c');

        Runtime.a.overload().implementation = function(savedInstanceState) {
            return false;
        };

        Runtime.b.overload().implementation = function(savedInstanceState) {
            return false;
        };

        Runtime.c.overload().implementation = function(savedInstanceState) {
            return false;
        };
    };

    function bypassSecretCheck() {
        var secretCheckClass = Java.use('sg.vantagepoint.uncrackable1.a');
        secretCheckClass.a.overload('java.lang.String').implementation = function(a) {
            return true;
        };
    };

    function decryptSecret() {
        var base64 = Java.use('android.util.Base64');
        /// Decode hardcoded base64 secret from g.vantagepoint.uncrackable1.a.java class
        var aesSecret = base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0)

        /// Class contains method to change string to byte array.
        var cryptoClass = Java.use('sg.vantagepoint.uncrackable1.a');
        var aesKey = cryptoClass.b("8d127684cbc37c17616d806cf50473cc")
        
        /// Class contains a method to decrypt sekret encrypted by AES.
        var aesDecryptionClass = Java.use('sg.vantagepoint.a.a');
        var buffer = aesDecryptionClass.a(aesKey, aesSecret)

        return String.fromCharCode.apply(String, buffer);
    };

    overrideExit();
    bypassRootDetection();
    bypassSecretCheck();
    console.log(decryptSecret());
});
```

## Solution 3: Changing static code using apktool

### What is Apktool?

Apktool decodes the application code to [smali](https://github.com/JesusFreke/smali), which can be modified and rebuild to working application with modified code.

[Installation doc](https://ibotpeaches.github.io/Apktool/install/)

### Solution

similarly to [Frida solution](### Bypass value check function) apktool can change code and bypass root detection and secret check function to get the success alert.

1. Firstly apk file have to be decompiled with command:

    ```console
    apktool d UnCrackable-Level1.apk
    ```

    It will generate the application smali code with project structure:

    ![Project structure](/assets/images/posts/UnCrackable1/uncrackable1-project-structure.png)

    Strcture is the same as it was with Jadx tool.

2. Find proper smali *a.smali* file

    As previously, root detection functions and secret check function needs to be bypassed and return false.
    Inside uncrakable1 directory the a.smali file contains the secret check function, but the method is quite long comparing to Java code:

    ```
    .method public static a(Ljava/lang/String;)Z
        .locals 5

        const-string v0, "8d127684cbc37c17616d806cf50473cc"

        const-string v1, "5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="

        const/4 v2, 0x0

        invoke-static {v1, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B
    ...
    ...
    ...
        return p0
    .end method
    ```

    Nevertheless change will be small, function just needs to return true.

3. Changing comparison to always return true

    After changing behaviour to always return true the function will look like this:

    ```
    .method public static a(Ljava/lang/String;)Z
        .locals 5

        /// Create true value.
        const/4 v0, 0x1

        /// Return created value.
        return v0
    .end method
    ```

    In the same way other functions need to be adjusted.
    The root detection and debuggable detection should return `0x0` instead of `0x1`.

4. Repackaging app using command:

    The smali code must be packed in an apk file, it should be done with command:

    ```console
    apktool b -f -d UnCrackable-Level1
    ```

5. After repackaging new build is available inside dist directory

    Path: 
    ```console
    /UnCrackable-Level1/dist/UnCrackable-Level1.apk
    ```

6. Installing the app with new Certificate

    Inorder to be able to install app again, the app need to re-signed it with new certificate.

    - Create new Certificate 
        ```console
        keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000
        ```
    - Sign app with certificate
        ```console
        jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore UnCrackable-Level1.apk alias_name
        ```
    - Install app to emulators
        ```console
        adb install UnCrackable-Level1.apk
        ```
      
7. App should be displaying always success alert, after pressing the verify button.
