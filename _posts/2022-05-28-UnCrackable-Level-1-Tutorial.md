---
layout: single
title: UnCrackable Level 1 tutorial
author_profile: true
---

# Introduction

This repository contains a complete tutorial on how to solve UnCrackable Level 1 in different ways to get the hidden key, but we will also bypass checks just to get the success Alert in different ways.

Objective: A secret string is hidden somewhere in this app. Find a way to extract it.


# Recon

This section contains all information on how to understand CrackMe Level1 logic.

## Running the app

After running the application we can see that we got a single text field with the button to verify provided value.
Entering some example value and pressing verify button will result error message saying it's wrong value.
Let's see how we can find this value.

Main screen                |  Failed Verification
:-------------------------:|:-------------------------:
![Main screen](/assets/images/posts/UnCrackable1/uncrackable1-main-screen.png)  |  ![Failed Verification](/assets/images/posts/UnCrackable1/uncrackable1-failed-verification.png)

## Jadx

Easiest way to understand Android application code is to decompile Dalvik bytecode to java classes from APK. You can use for example the jadx tool for that. Keep in mind that it might not work with all APK files, as they may be protected with different obfuscation techniques or use not compatible Java versions. So sometimes it is worth trying multiple versions of jadx in order to decompile Dalvik.

### Installation

`brew install jadx`

### Run

`jadx UnCrackable-Level1.apk`

### Logic

After decompilation of UnCrackable-Level1, we can see the project structure. 
If you would like to learn more about Android project structure you can check out this hack one article. We would like to find the MainActivity.java file which is the app starting point in Android.

`UnCrackable-Level1/sources/sg/vantagepoint/uncrackable1/MainActivity.java`

```Java
if (a.a(obj)) {
  create.setTitle("Success!");
  str = "This is the correct secret.";
} else {
  create.setTitle("Nope...");
  str = "That's not it. Try again.";
}
```

We can find you there that success alert will be presented when function a from a class will return true. Let’s find out what’s inside a class. 
Path: `UnCrackable-Level1/sources/sg/vantagepoint/a/a.java`

```
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

We can see that this function is comparing two strings and returns the value of this comparison as a result. Secret string is retrieved using the sg.vantagepoint.a.a.a function with two arguments. 
One is just the result of `"5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="` Base64 decoding.
Second one is the result of the function call: `b("8d127684cbc37c17616d806cf50473cc")`. Which performs some operations to change String to byte array.

Inside `sg.vantagepoint.a.a.a` those two byte arrays are being encrypted using AES algorithm, the result is the secret key that we are looking for.

```Java
public class a {
   public static byte[] a(byte[] bArr, byte[] bArr2) {
       SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES/ECB/PKCS7Padding");
       Cipher instance = Cipher.getInstance("AES");
       instance.init(2, secretKeySpec);
       return instance.doFinal(bArr2);
   }
}
```

## Pro tip
When working with obfuscated code it is good practice to rename those obfuscated methods to something meaningful, so you can understand more and more code.
Let’s rename some functions.

Before:
```Java
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

After:
```Java
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
This section contains different solutions how to get the hidden secret, but also how to just bypass the security check and just get a success alert.

## Solution 1: Find the comparison method and print out the key

First solution to retrieve a hidden key is to copy / paste methods that are responsible for decryption of it and just print out the value.
We can change `compareSecret` function to return the value instead of comparing it to userInput

`Note: As it is Android code it is not possible to run it in the same way using just Java, it has to be run on Android device or adjusted to normal Java code.`

```Java
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
Let’s run it :D

`I want to believe`

 Veryfing this value will result success message 🥳

![Success message](/assets/images/posts/UnCrackable1/uncrackable1-success.png)


## Solution 2: Frida script

In short simple words Frida allows to change applications behaviour without modifying application code, but change it while app code is being loaded.
If you don't know what is Frida you can read about it [here](https://frida.re/docs/home/).

### [How to run Frida](https://frida.re/docs/android/)

To use frida you need to install it and run following [tutorial](https://frida.re/docs/android/).

After first run in the future we will just need this command:

`adb shell "/data/local/tmp/frida-server &"`

tu run Frida server in the background.
When Frida is working you can attach the script to the app and change its behaviour.
We will need an app identifier for attach command you can find it using command:

```
MacBook-Pro:~ macbook$ frida-ps -Ua
 PID  Name          Identifier             
----  ------------  -----------------------
8337  Calendar      com.android.calendar   
8363  Clock         com.android.deskclock  
8909  Uncrackable1  owasp.mstg.uncrackable1
```

Then we can attach Frida code using command:

```
frida -U -l UncrackableLevel1.js  -f owasp.mstg.uncrackable1
```

Where `UncrackableLevel1.js` is a file which contains our code frida code.
It will be created in [section](https://github.com/karolpiateknet/Android-Security-UnCrackable-Level-1/blob/main/README.md#frida-code)

#### Pro tips

If you are using Android emulator remenber to use Android version without google API and google play.
As some of Android emulators may not allow adb root access, [see stackOverFlow thread](https://stackoverflow.com/questions/43923996/adb-root-is-not-working-on-emulator-cannot-run-as-root-in-production-builds).
I'm working on Nexus 6 API 29 without any problems.

If you got some problem with Frida you can restart it using commands:
```
adb shell 
ps -e | grep frida-server 
kill -9 PID_of_frida_process_from_previous_command
```

### Root detection bypass

After running the application on Rooted devices you can see that Uncrackable App is detecting root access and closing the app.
In order to be able to run the app without closing it we need to bypass those detections.
As we can find out there are three checks, if even single one will return true our app will be closed.

```javascript
if (c.a() || c.b() || c.c()) {
  a("Root detected!");
}
```

Preventing app from closing can be achieved here in multiple ways, we can either override returned values by root checks to always return false or override `System.exit(0);` function to do not close the app. Let's see how it would look like.

#### Overriding root detection checks

Code for bypassing root detection functions and returning always false.

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

Code for overriding system exit function to do not close app.

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

### Decrypting function

The hidden secret can be decrypted in the same way as it is done in [Solution 1](https://github.com/karolpiateknet/Android-Security-UnCrackable-Level-1#solution-1-find-the-comparison-method-and-print-out-the-key).
We need to run all decrypting methods as it is done in the orginal code and return the hidden value.

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

In order to get success alert we can just override the check secret function to return always true.
It won't solve the challenge which is to find the hidden secret, but it will be an intresting way to get success alert.

```javascript
function bypassSecretCheck() {
    var secretCheckClass = Java.use('sg.vantagepoint.uncrackable1.a');
    secretCheckClass.a.overload('java.lang.String').implementation = function(a) {
        return true;
    };
};
```

### Complete Frida code - UncrackableLevel1.js

Complete frida code to solve the challenge in different ways.

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

## Solution 3: Change static code using apktool

In this section we will use Apktool to change application behaviour to get success alert without getting the hidden key.

### What is Apktool?

Apktool can decode the application code to [smali](https://github.com/JesusFreke/smali), which can be modified and rebuild to working application with modified static code.

[Installation doc](https://ibotpeaches.github.io/Apktool/install/)

### Solution

Using apktool we can bypass root detection and secret check function to get the success alert, as previously it was done in [Frida section](https://github.com/karolpiateknet/Android-Security-UnCrackable-Level-1#overriding-root-detection-checks).

Let's see how we can achieve that.

1. First we need to decompile apk file using command:

`apktool d UnCrackable-Level1.apk`

We will receive the application smali code with project structure:

![Project structure](/assets/images/posts/UnCrackable1/uncrackable1-project-structure.png)

As we can see structure is basically the same as it was with jadx tool.

2. Find proper smali a.smali file

As previously we need to return false inside root detection functions and secret check function.
Inside uncrakable1 directory we can see the a.smali file there which contains the secret check function.

The method is quite long comparing to Java code:

```smali
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

But we know that we just need to return the true.

4. Change comparison to always true

After changing behaviour to always return true the function will look like this:

```smali
.method public static a(Ljava/lang/String;)Z
    .locals 5

    /// Create true value.
    const/4 v0, 0x1

    /// Return created value.
    return v0
.end method
```

In the same way we need to bypass the root detection and debuggable detection, but just return `0x0` instead of `0x1`.

4. Repackage app using command:

`apktool b -f -d UnCrackable-Level1`

5. After recompiling new build is available inside dist directory

Path: `/UnCrackable-Level1/dist/UnCrackable-Level1.apk`

7. Repackaging the app with your Certificate

Inorder to be able to install app again we need to sign it with our new certificate.

  6.1 Create certificate 
      `keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000`
  6.2 Sign app with certificate
      `jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore UnCrackable-Level1.apk alias_name`
  6.3 Install app to emulators
      `adb install UnCrackable-Level1.apk`
      
8. Our app is displaying always success alert.
