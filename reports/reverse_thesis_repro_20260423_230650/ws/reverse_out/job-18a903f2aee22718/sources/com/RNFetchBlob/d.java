package com.RNFetchBlob;

import android.content.res.AssetFileDescriptor;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Environment;
import android.os.StatFs;
import android.os.SystemClock;
import android.util.Base64;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

/* JADX INFO: loaded from: classes.dex */
class d {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static HashMap f5773e = new HashMap();

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private ReactApplicationContext f5774a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private DeviceEventManagerModule.RCTDeviceEventEmitter f5775b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private String f5776c = "base64";

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private OutputStream f5777d = null;

    class a extends AsyncTask {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Callback f5778a;

        a(Callback callback) {
            this.f5778a = callback;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Integer doInBackground(String... strArr) {
            WritableArray writableArrayCreateArray = Arguments.createArray();
            if (strArr[0] == null) {
                this.f5778a.invoke("the path specified for lstat is either `null` or `undefined`.");
                return 0;
            }
            File file = new File(strArr[0]);
            if (!file.exists()) {
                this.f5778a.invoke("failed to lstat path `" + strArr[0] + "` because it does not exist or it is not a folder");
                return 0;
            }
            if (file.isDirectory()) {
                for (String str : file.list()) {
                    writableArrayCreateArray.pushMap(d.D(file.getPath() + "/" + str));
                }
            } else {
                writableArrayCreateArray.pushMap(d.D(file.getAbsolutePath()));
            }
            this.f5778a.invoke(null, writableArrayCreateArray);
            return 0;
        }
    }

    class b implements MediaScannerConnection.OnScanCompletedListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Callback f5779a;

        b(Callback callback) {
            this.f5779a = callback;
        }

        @Override // android.media.MediaScannerConnection.OnScanCompletedListener
        public void onScanCompleted(String str, Uri uri) {
            this.f5779a.invoke(null, Boolean.TRUE);
        }
    }

    class c extends AsyncTask {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Callback f5781a;

        c(Callback callback) {
            this.f5781a = callback;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Integer doInBackground(ReadableArray... readableArrayArr) {
            try {
                ArrayList arrayList = new ArrayList();
                for (int i3 = 0; i3 < readableArrayArr[0].size(); i3++) {
                    String string = readableArrayArr[0].getString(i3);
                    File file = new File(string);
                    if (file.exists() && !file.delete()) {
                        arrayList.add(string);
                    }
                }
                if (arrayList.isEmpty()) {
                    this.f5781a.invoke(null, Boolean.TRUE);
                } else {
                    StringBuilder sb = new StringBuilder();
                    sb.append("Failed to delete: ");
                    Iterator it = arrayList.iterator();
                    while (it.hasNext()) {
                        sb.append((String) it.next());
                        sb.append(", ");
                    }
                    this.f5781a.invoke(sb.toString());
                }
            } catch (Exception e3) {
                this.f5781a.invoke(e3.getLocalizedMessage());
            }
            return Integer.valueOf(readableArrayArr[0].size());
        }
    }

    d(ReactApplicationContext reactApplicationContext) {
        this.f5774a = reactApplicationContext;
        this.f5775b = (DeviceEventManagerModule.RCTDeviceEventEmitter) reactApplicationContext.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class);
    }

    static void B(String str, String str2, int i3, int i4, String str3, Promise promise) {
        try {
            String strW = w(str);
            File file = new File(strW);
            if (file.isDirectory()) {
                promise.reject("EISDIR", "Expecting a file but '" + strW + "' is a directory");
                return;
            }
            if (!file.exists()) {
                promise.reject("ENOENT", "No such file '" + strW + "'");
                return;
            }
            int length = (int) file.length();
            int iMin = Math.min(length, i4) - i3;
            FileInputStream fileInputStream = new FileInputStream(new File(strW));
            FileOutputStream fileOutputStream = new FileOutputStream(new File(str2));
            int iSkip = (int) fileInputStream.skip(i3);
            if (iSkip != i3) {
                promise.reject("EUNSPECIFIED", "Skipped " + iSkip + " instead of the specified " + i3 + " bytes, size is " + length);
                return;
            }
            byte[] bArr = new byte[10240];
            int i5 = 0;
            while (i5 < iMin) {
                int i6 = fileInputStream.read(bArr, 0, 10240);
                int i7 = iMin - i5;
                if (i6 <= 0) {
                    break;
                }
                fileOutputStream.write(bArr, 0, Math.min(i7, i6));
                i5 += i6;
            }
            fileInputStream.close();
            fileOutputStream.flush();
            fileOutputStream.close();
            promise.resolve(str2);
        } catch (Exception e3) {
            e3.printStackTrace();
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    static void C(String str, Callback callback) {
        try {
            String strW = w(str);
            WritableMap writableMapD = D(strW);
            if (writableMapD == null) {
                callback.invoke("failed to stat path `" + strW + "` because it does not exist or it is not a folder", null);
            } else {
                callback.invoke(null, writableMapD);
            }
        } catch (Exception e3) {
            callback.invoke(e3.getLocalizedMessage());
        }
    }

    static WritableMap D(String str) {
        try {
            String strW = w(str);
            WritableMap writableMapCreateMap = Arguments.createMap();
            if (q(strW)) {
                String strReplace = strW.replace("bundle-assets://", "");
                AssetFileDescriptor assetFileDescriptorOpenFd = RNFetchBlob.RCTContext.getAssets().openFd(strReplace);
                writableMapCreateMap.putString("filename", strReplace);
                writableMapCreateMap.putString("path", strW);
                writableMapCreateMap.putString("type", "asset");
                writableMapCreateMap.putString("size", String.valueOf(assetFileDescriptorOpenFd.getLength()));
                writableMapCreateMap.putInt("lastModified", 0);
            } else {
                File file = new File(strW);
                if (!file.exists()) {
                    return null;
                }
                writableMapCreateMap.putString("filename", file.getName());
                writableMapCreateMap.putString("path", file.getPath());
                writableMapCreateMap.putString("type", file.isDirectory() ? "directory" : "file");
                writableMapCreateMap.putString("size", String.valueOf(file.length()));
                writableMapCreateMap.putString("lastModified", String.valueOf(file.lastModified()));
            }
            return writableMapCreateMap;
        } catch (Exception unused) {
            return null;
        }
    }

    private static byte[] E(String str, String str2) {
        return str2.equalsIgnoreCase("ascii") ? str.getBytes(Charset.forName("US-ASCII")) : str2.toLowerCase().contains("base64") ? Base64.decode(str, 2) : str2.equalsIgnoreCase("utf8") ? str.getBytes(Charset.forName("UTF-8")) : str.getBytes(Charset.forName("US-ASCII"));
    }

    static void F(String str, Callback callback) {
        try {
            e(new File(w(str)));
            callback.invoke(null, Boolean.TRUE);
        } catch (Exception e3) {
            callback.invoke(e3.getLocalizedMessage(), Boolean.FALSE);
        }
    }

    static void G(String str, ReadableArray readableArray, Callback callback) {
        try {
            OutputStream outputStream = ((d) f5773e.get(str)).f5777d;
            byte[] bArr = new byte[readableArray.size()];
            for (int i3 = 0; i3 < readableArray.size(); i3++) {
                bArr[i3] = (byte) readableArray.getInt(i3);
            }
            outputStream.write(bArr);
            callback.invoke(new Object[0]);
        } catch (Exception e3) {
            callback.invoke(e3.getLocalizedMessage());
        }
    }

    static void H(String str, String str2, Callback callback) {
        d dVar = (d) f5773e.get(str);
        try {
            dVar.f5777d.write(E(str2, dVar.f5776c));
            callback.invoke(new Object[0]);
        } catch (Exception e3) {
            callback.invoke(e3.getLocalizedMessage());
        }
    }

    static void I(String str, ReadableArray readableArray, boolean z3, Promise promise) {
        try {
            File file = new File(str);
            File parentFile = file.getParentFile();
            if (!file.exists()) {
                if (parentFile != null && !parentFile.exists() && !parentFile.mkdirs()) {
                    promise.reject("ENOTDIR", "Failed to create parent directory of '" + str + "'");
                    return;
                }
                if (!file.createNewFile()) {
                    promise.reject("ENOENT", "File '" + str + "' does not exist and could not be created");
                    return;
                }
            }
            FileOutputStream fileOutputStream = new FileOutputStream(file, z3);
            try {
                byte[] bArr = new byte[readableArray.size()];
                for (int i3 = 0; i3 < readableArray.size(); i3++) {
                    bArr[i3] = (byte) readableArray.getInt(i3);
                }
                fileOutputStream.write(bArr);
                fileOutputStream.close();
                promise.resolve(Integer.valueOf(readableArray.size()));
            } catch (Throwable th) {
                fileOutputStream.close();
                throw th;
            }
        } catch (FileNotFoundException unused) {
            promise.reject("ENOENT", "File '" + str + "' does not exist and could not be created");
        } catch (Exception e3) {
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    static void J(String str, String str2, String str3, boolean z3, Promise promise) {
        int length;
        FileOutputStream fileOutputStream;
        try {
            File file = new File(str);
            File parentFile = file.getParentFile();
            if (!file.exists()) {
                if (parentFile != null && !parentFile.exists() && !parentFile.mkdirs()) {
                    promise.reject("EUNSPECIFIED", "Failed to create parent directory of '" + str + "'");
                    return;
                }
                if (!file.createNewFile()) {
                    promise.reject("ENOENT", "File '" + str + "' does not exist and could not be created");
                    return;
                }
            }
            if (str2.equalsIgnoreCase("uri")) {
                String strW = w(str3);
                File file2 = new File(strW);
                if (!file2.exists()) {
                    promise.reject("ENOENT", "No such file '" + str + "' ('" + strW + "')");
                    return;
                }
                byte[] bArr = new byte[10240];
                FileInputStream fileInputStream = null;
                try {
                    FileInputStream fileInputStream2 = new FileInputStream(file2);
                    try {
                        fileOutputStream = new FileOutputStream(file, z3);
                        length = 0;
                        while (true) {
                            try {
                                int i3 = fileInputStream2.read(bArr);
                                if (i3 <= 0) {
                                    break;
                                }
                                fileOutputStream.write(bArr, 0, i3);
                                length += i3;
                            } catch (Throwable th) {
                                th = th;
                                fileInputStream = fileInputStream2;
                                if (fileInputStream != null) {
                                    fileInputStream.close();
                                }
                                if (fileOutputStream != null) {
                                    fileOutputStream.close();
                                }
                                throw th;
                            }
                        }
                        fileInputStream2.close();
                        fileOutputStream.close();
                    } catch (Throwable th2) {
                        th = th2;
                        fileOutputStream = null;
                    }
                } catch (Throwable th3) {
                    th = th3;
                    fileOutputStream = null;
                }
            } else {
                byte[] bArrE = E(str3, str2);
                FileOutputStream fileOutputStream2 = new FileOutputStream(file, z3);
                try {
                    fileOutputStream2.write(bArrE);
                    length = bArrE.length;
                } finally {
                    fileOutputStream2.close();
                }
            }
            promise.resolve(Integer.valueOf(length));
        } catch (FileNotFoundException unused) {
            promise.reject("ENOENT", "File '" + str + "' does not exist and could not be created, or it is a directory");
        } catch (Exception e3) {
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    static void a(String str, Callback callback) {
        try {
            OutputStream outputStream = ((d) f5773e.get(str)).f5777d;
            f5773e.remove(str);
            outputStream.close();
            callback.invoke(new Object[0]);
        } catch (Exception e3) {
            callback.invoke(e3.getLocalizedMessage());
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:56:0x00fa A[Catch: Exception -> 0x00f6, TRY_LEAVE, TryCatch #4 {Exception -> 0x00f6, blocks: (B:52:0x00f2, B:56:0x00fa), top: B:62:0x00f2 }] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00f2 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static void b(java.lang.String r4, java.lang.String r5, com.facebook.react.bridge.Callback r6) {
        /*
            Method dump skipped, instruction units count: 258
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.RNFetchBlob.d.b(java.lang.String, java.lang.String, com.facebook.react.bridge.Callback):void");
    }

    static void c(String str, String str2, String str3, Promise promise) {
        try {
            File file = new File(str);
            boolean zCreateNewFile = file.createNewFile();
            if (str3.equals("uri")) {
                File file2 = new File(str2.replace("RNFetchBlob-file://", ""));
                if (!file2.exists()) {
                    promise.reject("ENOENT", "Source file : " + str2 + " does not exist");
                    return;
                }
                FileInputStream fileInputStream = new FileInputStream(file2);
                FileOutputStream fileOutputStream = new FileOutputStream(file);
                byte[] bArr = new byte[10240];
                for (int i3 = fileInputStream.read(bArr); i3 > 0; i3 = fileInputStream.read(bArr)) {
                    fileOutputStream.write(bArr, 0, i3);
                }
                fileInputStream.close();
                fileOutputStream.close();
            } else {
                if (!zCreateNewFile) {
                    promise.reject("EEXIST", "File `" + str + "` already exists");
                    return;
                }
                new FileOutputStream(file).write(E(str2, str3));
            }
            promise.resolve(str);
        } catch (Exception e3) {
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    static void d(String str, ReadableArray readableArray, Promise promise) {
        try {
            File file = new File(str);
            if (!file.createNewFile()) {
                promise.reject("EEXIST", "File at path `" + str + "` already exists");
                return;
            }
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            byte[] bArr = new byte[readableArray.size()];
            for (int i3 = 0; i3 < readableArray.size(); i3++) {
                bArr[i3] = (byte) readableArray.getInt(i3);
            }
            fileOutputStream.write(bArr);
            promise.resolve(str);
        } catch (Exception e3) {
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    private static void e(File file) throws IOException {
        if (file.isDirectory()) {
            File[] fileArrListFiles = file.listFiles();
            if (fileArrListFiles == null) {
                throw new NullPointerException("Received null trying to list files of directory '" + file + "'");
            }
            for (File file2 : fileArrListFiles) {
                e(file2);
            }
        }
        if (file.delete()) {
            return;
        }
        throw new IOException("Failed to delete '" + file + "'");
    }

    static void f(Callback callback) {
        StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putString("internal_free", String.valueOf(statFs.getFreeBytes()));
        writableMapCreateMap.putString("internal_total", String.valueOf(statFs.getTotalBytes()));
        StatFs statFs2 = new StatFs(Environment.getExternalStorageDirectory().getPath());
        writableMapCreateMap.putString("external_free", String.valueOf(statFs2.getFreeBytes()));
        writableMapCreateMap.putString("external_total", String.valueOf(statFs2.getTotalBytes()));
        callback.invoke(null, writableMapCreateMap);
    }

    private void g(String str, String str2, WritableArray writableArray) {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putString("event", str2);
        writableMapCreateMap.putArray("detail", writableArray);
        this.f5775b.emit(str, writableMapCreateMap);
    }

    private void h(String str, String str2, String str3) {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putString("event", str2);
        writableMapCreateMap.putString("detail", str3);
        this.f5775b.emit(str, writableMapCreateMap);
    }

    private void i(String str, String str2, String str3, String str4) {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putString("event", str2);
        writableMapCreateMap.putString("code", str3);
        writableMapCreateMap.putString("detail", str4);
        this.f5775b.emit(str, writableMapCreateMap);
    }

    static void j(String str, Callback callback) {
        if (q(str)) {
            try {
                RNFetchBlob.RCTContext.getAssets().openFd(str.replace("bundle-assets://", ""));
                callback.invoke(Boolean.TRUE, Boolean.FALSE);
                return;
            } catch (IOException unused) {
                Boolean bool = Boolean.FALSE;
                callback.invoke(bool, bool);
                return;
            }
        }
        String strW = w(str);
        if (strW == null) {
            Boolean bool2 = Boolean.FALSE;
            callback.invoke(bool2, bool2);
        } else {
            callback.invoke(Boolean.valueOf(new File(strW).exists()), Boolean.valueOf(new File(strW).isDirectory()));
        }
    }

    public static void k(ReactApplicationContext reactApplicationContext, Promise promise) {
        if (!Environment.getExternalStorageState().equals("mounted")) {
            promise.reject("RNFetchBlob.getSDCardApplicationDir", "External storage not mounted");
            return;
        }
        try {
            promise.resolve(reactApplicationContext.getExternalFilesDir(null).getParentFile().getAbsolutePath());
        } catch (Exception e3) {
            promise.reject("RNFetchBlob.getSDCardApplicationDir", e3.getLocalizedMessage());
        }
    }

    public static void l(Promise promise) {
        if (Environment.getExternalStorageState().equals("mounted")) {
            promise.resolve(Environment.getExternalStorageDirectory().getAbsolutePath());
        } else {
            promise.reject("RNFetchBlob.getSDCardDir", "External storage not mounted");
        }
    }

    static Map m(ReactApplicationContext reactApplicationContext) {
        HashMap map = new HashMap();
        map.put("DocumentDir", reactApplicationContext.getFilesDir().getAbsolutePath());
        map.put("CacheDir", reactApplicationContext.getCacheDir().getAbsolutePath());
        map.put("DCIMDir", Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM).getAbsolutePath());
        map.put("PictureDir", Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES).getAbsolutePath());
        map.put("MusicDir", Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MUSIC).getAbsolutePath());
        map.put("DownloadDir", Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath());
        map.put("MovieDir", Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MOVIES).getAbsolutePath());
        map.put("RingtoneDir", Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_RINGTONES).getAbsolutePath());
        if (Environment.getExternalStorageState().equals("mounted")) {
            map.put("SDCardDir", Environment.getExternalStorageDirectory().getAbsolutePath());
            File externalFilesDir = reactApplicationContext.getExternalFilesDir(null);
            if (externalFilesDir != null) {
                map.put("SDCardApplicationDir", externalFilesDir.getParentFile().getAbsolutePath());
            } else {
                map.put("SDCardApplicationDir", "");
            }
        }
        map.put("MainBundleDir", reactApplicationContext.getApplicationInfo().dataDir);
        return map;
    }

    static String n(String str) {
        return RNFetchBlob.RCTContext.getFilesDir() + "/RNFetchBlobTmp_" + str;
    }

    static void o(String str, String str2, Promise promise) {
        try {
            HashMap map = new HashMap();
            map.put("md5", "MD5");
            map.put("sha1", "SHA-1");
            map.put("sha224", "SHA-224");
            map.put("sha256", "SHA-256");
            map.put("sha384", "SHA-384");
            map.put("sha512", "SHA-512");
            if (!map.containsKey(str2)) {
                promise.reject("EINVAL", "Invalid algorithm '" + str2 + "', must be one of md5, sha1, sha224, sha256, sha384, sha512");
                return;
            }
            File file = new File(str);
            if (file.isDirectory()) {
                promise.reject("EISDIR", "Expecting a file but '" + str + "' is a directory");
                return;
            }
            if (!file.exists()) {
                promise.reject("ENOENT", "No such file '" + str + "'");
                return;
            }
            MessageDigest messageDigest = MessageDigest.getInstance((String) map.get(str2));
            FileInputStream fileInputStream = new FileInputStream(str);
            byte[] bArr = new byte[1048576];
            if (file.length() != 0) {
                while (true) {
                    int i3 = fileInputStream.read(bArr);
                    if (i3 == -1) {
                        break;
                    } else {
                        messageDigest.update(bArr, 0, i3);
                    }
                }
            }
            StringBuilder sb = new StringBuilder();
            for (byte b3 : messageDigest.digest()) {
                sb.append(String.format("%02x", Byte.valueOf(b3)));
            }
            promise.resolve(sb.toString());
        } catch (Exception e3) {
            e3.printStackTrace();
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    private static InputStream p(String str) {
        return str.startsWith("bundle-assets://") ? RNFetchBlob.RCTContext.getAssets().open(str.replace("bundle-assets://", "")) : new FileInputStream(new File(str));
    }

    static boolean q(String str) {
        return str != null && str.startsWith("bundle-assets://");
    }

    private static boolean r(String str) {
        if (!str.startsWith("bundle-assets://")) {
            return new File(str).exists();
        }
        try {
            RNFetchBlob.RCTContext.getAssets().open(str.replace("bundle-assets://", ""));
            return true;
        } catch (IOException unused) {
            return false;
        }
    }

    static void s(String str, Promise promise) {
        try {
            String strW = w(str);
            File file = new File(strW);
            if (!file.exists()) {
                promise.reject("ENOENT", "No such file '" + strW + "'");
                return;
            }
            if (!file.isDirectory()) {
                promise.reject("ENOTDIR", "Not a directory '" + strW + "'");
                return;
            }
            String[] list = new File(strW).list();
            WritableArray writableArrayCreateArray = Arguments.createArray();
            for (String str2 : list) {
                writableArrayCreateArray.pushString(str2);
            }
            promise.resolve(writableArrayCreateArray);
        } catch (Exception e3) {
            e3.printStackTrace();
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    static void t(String str, Callback callback) {
        new a(callback).execute(w(str));
    }

    static void u(String str, Promise promise) {
        File file = new File(str);
        if (file.exists()) {
            StringBuilder sb = new StringBuilder();
            sb.append(file.isDirectory() ? "Folder" : "File");
            sb.append(" '");
            sb.append(str);
            sb.append("' already exists");
            promise.reject("EEXIST", sb.toString());
            return;
        }
        try {
            if (file.mkdirs()) {
                promise.resolve(Boolean.TRUE);
                return;
            }
            promise.reject("EUNSPECIFIED", "mkdir failed to create some or all directories in '" + str + "'");
        } catch (Exception e3) {
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    static void v(String str, String str2, Callback callback) {
        File file = new File(str);
        if (!file.exists()) {
            callback.invoke("Source file at path `" + str + "` does not exist");
            return;
        }
        try {
            FileInputStream fileInputStream = new FileInputStream(str);
            FileOutputStream fileOutputStream = new FileOutputStream(str2);
            byte[] bArr = new byte[1024];
            while (true) {
                int i3 = fileInputStream.read(bArr);
                if (i3 == -1) {
                    fileInputStream.close();
                    fileOutputStream.flush();
                    file.delete();
                    callback.invoke(new Object[0]);
                    return;
                }
                fileOutputStream.write(bArr, 0, i3);
            }
        } catch (FileNotFoundException unused) {
            callback.invoke("Source file not found.");
        } catch (Exception e3) {
            callback.invoke(e3.toString());
        }
    }

    static String w(String str) {
        if (str == null) {
            return null;
        }
        if (!str.matches("\\w+\\:.*")) {
            return str;
        }
        if (str.startsWith("file://")) {
            return str.replace("file://", "");
        }
        return str.startsWith("bundle-assets://") ? str : P.a.c(RNFetchBlob.RCTContext, Uri.parse(str));
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0043  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00d1  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    static void x(java.lang.String r7, java.lang.String r8, com.facebook.react.bridge.Promise r9) {
        /*
            Method dump skipped, instruction units count: 342
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.RNFetchBlob.d.x(java.lang.String, java.lang.String, com.facebook.react.bridge.Promise):void");
    }

    static void z(ReadableArray readableArray, Callback callback) {
        new c(callback).execute(readableArray);
    }

    void A(String[] strArr, String[] strArr2, Callback callback) {
        try {
            MediaScannerConnection.scanFile(this.f5774a, strArr, strArr2, new b(callback));
        } catch (Exception e3) {
            callback.invoke(e3.getLocalizedMessage(), null);
        }
    }

    void K(String str, String str2, boolean z3, Callback callback) {
        try {
            File file = new File(str);
            File parentFile = file.getParentFile();
            if (file.exists()) {
                if (file.isDirectory()) {
                    callback.invoke("EISDIR", "Expecting a file but '" + str + "' is a directory");
                    return;
                }
            } else {
                if (parentFile != null && !parentFile.exists() && !parentFile.mkdirs()) {
                    callback.invoke("ENOTDIR", "Failed to create parent directory of '" + str + "'");
                    return;
                }
                if (!file.createNewFile()) {
                    callback.invoke("ENOENT", "File '" + str + "' does not exist and could not be created");
                    return;
                }
            }
            FileOutputStream fileOutputStream = new FileOutputStream(str, z3);
            this.f5776c = str2;
            String string = UUID.randomUUID().toString();
            f5773e.put(string, this);
            this.f5777d = fileOutputStream;
            callback.invoke(null, null, string);
        } catch (Exception e3) {
            callback.invoke("EUNSPECIFIED", "Failed to create write stream at path `" + str + "`; " + e3.getLocalizedMessage());
        }
    }

    void y(String str, String str2, int i3, int i4, String str3) {
        String strW = w(str);
        String str4 = strW != null ? strW : str;
        try {
            int i5 = str2.equalsIgnoreCase("base64") ? 4095 : 4096;
            if (i3 > 0) {
                i5 = i3;
            }
            InputStream inputStreamOpenInputStream = (strW == null || !str4.startsWith("bundle-assets://")) ? strW == null ? RNFetchBlob.RCTContext.getContentResolver().openInputStream(Uri.parse(str4)) : new FileInputStream(new File(str4)) : RNFetchBlob.RCTContext.getAssets().open(str4.replace("bundle-assets://", ""));
            byte[] bArr = new byte[i5];
            int i6 = -1;
            String str5 = "data";
            int i7 = 0;
            if (str2.equalsIgnoreCase("utf8")) {
                CharsetEncoder charsetEncoderNewEncoder = Charset.forName("UTF-8").newEncoder();
                while (true) {
                    int i8 = inputStreamOpenInputStream.read(bArr);
                    if (i8 == -1) {
                        break;
                    }
                    charsetEncoderNewEncoder.encode(ByteBuffer.wrap(bArr).asCharBuffer());
                    h(str3, "data", new String(bArr, i7, i8));
                    if (i4 > 0) {
                        SystemClock.sleep(i4);
                    }
                    i7 = 0;
                }
            } else if (str2.equalsIgnoreCase("ascii")) {
                while (true) {
                    int i9 = inputStreamOpenInputStream.read(bArr);
                    if (i9 == -1) {
                        break;
                    }
                    WritableArray writableArrayCreateArray = Arguments.createArray();
                    for (int i10 = 0; i10 < i9; i10++) {
                        writableArrayCreateArray.pushInt(bArr[i10]);
                    }
                    g(str3, "data", writableArrayCreateArray);
                    if (i4 > 0) {
                        SystemClock.sleep(i4);
                    }
                }
            } else {
                if (!str2.equalsIgnoreCase("base64")) {
                    i(str3, "error", "EINVAL", "Unrecognized encoding `" + str2 + "`, should be one of `base64`, `utf8`, `ascii`");
                    inputStreamOpenInputStream.close();
                }
                while (true) {
                    int i11 = inputStreamOpenInputStream.read(bArr);
                    if (i11 == i6) {
                        break;
                    }
                    if (i11 < i5) {
                        byte[] bArr2 = new byte[i11];
                        System.arraycopy(bArr, 0, bArr2, 0, i11);
                        h(str3, str5, Base64.encodeToString(bArr2, 2));
                    } else {
                        h(str3, str5, Base64.encodeToString(bArr, 2));
                    }
                    if (i4 > 0) {
                        SystemClock.sleep(i4);
                        str5 = str5;
                        i6 = -1;
                    }
                }
            }
            h(str3, "end", "");
            inputStreamOpenInputStream.close();
        } catch (FileNotFoundException unused) {
            i(str3, "error", "ENOENT", "No such file '" + str4 + "'");
        } catch (Exception e3) {
            i(str3, "error", "EUNSPECIFIED", "Failed to convert data to " + str2 + " encoded string. This might be because this encoding cannot be used for this data.");
            e3.printStackTrace();
        }
    }
}
