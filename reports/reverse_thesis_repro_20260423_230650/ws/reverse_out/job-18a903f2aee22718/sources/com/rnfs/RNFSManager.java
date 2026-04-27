package com.rnfs;

import android.content.res.AssetFileDescriptor;
import android.content.res.AssetManager;
import android.database.Cursor;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.util.Base64;
import android.util.SparseArray;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.RCTNativeAppEventEmitter;
import com.rnfs.a;
import com.rnfs.g;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = RNFSManager.MODULE_NAME)
public class RNFSManager extends ReactContextBaseJavaModule {
    static final String MODULE_NAME = "RNFSManager";
    private static final String RNFSCachesDirectoryPath = "RNFSCachesDirectoryPath";
    private static final String RNFSDocumentDirectory = "RNFSDocumentDirectory";
    private static final String RNFSDocumentDirectoryPath = "RNFSDocumentDirectoryPath";
    private static final String RNFSDownloadDirectoryPath = "RNFSDownloadDirectoryPath";
    private static final String RNFSExternalCachesDirectoryPath = "RNFSExternalCachesDirectoryPath";
    private static final String RNFSExternalDirectoryPath = "RNFSExternalDirectoryPath";
    private static final String RNFSExternalStorageDirectoryPath = "RNFSExternalStorageDirectoryPath";
    private static final String RNFSFileTypeDirectory = "RNFSFileTypeDirectory";
    private static final String RNFSFileTypeRegular = "RNFSFileTypeRegular";
    private static final String RNFSPicturesDirectoryPath = "RNFSPicturesDirectoryPath";
    private static final String RNFSTemporaryDirectoryPath = "RNFSTemporaryDirectoryPath";
    private SparseArray<com.rnfs.c> downloaders;
    private ReactApplicationContext reactContext;
    private SparseArray<com.rnfs.i> uploaders;

    class a extends j {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ File f8671b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Promise f8672c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ String f8673d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(File file, Promise promise, String str) {
            super();
            this.f8671b = file;
            this.f8672c = promise;
            this.f8673d = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void onPostExecute(Exception exc) {
            if (exc == null) {
                this.f8671b.delete();
                this.f8672c.resolve(Boolean.TRUE);
            } else {
                exc.printStackTrace();
                RNFSManager.this.reject(this.f8672c, this.f8673d, exc);
            }
        }
    }

    class b extends j {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Promise f8675b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f8676c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        b(Promise promise, String str) {
            super();
            this.f8675b = promise;
            this.f8676c = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void onPostExecute(Exception exc) {
            if (exc == null) {
                this.f8675b.resolve(null);
            } else {
                exc.printStackTrace();
                RNFSManager.this.reject(this.f8675b, this.f8676c, exc);
            }
        }
    }

    class c implements a.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f8678a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Promise f8679b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ ReadableMap f8680c;

        c(int i3, Promise promise, ReadableMap readableMap) {
            this.f8678a = i3;
            this.f8679b = promise;
            this.f8680c = readableMap;
        }

        @Override // com.rnfs.a.c
        public void a(com.rnfs.b bVar) {
            if (bVar.f8709c != null) {
                RNFSManager.this.reject(this.f8679b, this.f8680c.getString("toFile"), bVar.f8709c);
                return;
            }
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putInt("jobId", this.f8678a);
            writableMapCreateMap.putInt("statusCode", bVar.f8707a);
            writableMapCreateMap.putDouble("bytesWritten", bVar.f8708b);
            this.f8679b.resolve(writableMapCreateMap);
        }
    }

    class d implements a.InterfaceC0124a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f8682a;

        d(int i3) {
            this.f8682a = i3;
        }

        @Override // com.rnfs.a.InterfaceC0124a
        public void a(int i3, long j3, Map map) {
            WritableMap writableMapCreateMap = Arguments.createMap();
            for (Map.Entry entry : map.entrySet()) {
                writableMapCreateMap.putString((String) entry.getKey(), (String) entry.getValue());
            }
            WritableMap writableMapCreateMap2 = Arguments.createMap();
            writableMapCreateMap2.putInt("jobId", this.f8682a);
            writableMapCreateMap2.putInt("statusCode", i3);
            writableMapCreateMap2.putDouble("contentLength", j3);
            writableMapCreateMap2.putMap("headers", writableMapCreateMap);
            RNFSManager rNFSManager = RNFSManager.this;
            rNFSManager.sendEvent(rNFSManager.getReactApplicationContext(), "DownloadBegin", writableMapCreateMap2);
        }
    }

    class e implements a.b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f8684a;

        e(int i3) {
            this.f8684a = i3;
        }

        @Override // com.rnfs.a.b
        public void a(long j3, long j4) {
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putInt("jobId", this.f8684a);
            writableMapCreateMap.putDouble("contentLength", j3);
            writableMapCreateMap.putDouble("bytesWritten", j4);
            RNFSManager rNFSManager = RNFSManager.this;
            rNFSManager.sendEvent(rNFSManager.getReactApplicationContext(), "DownloadProgress", writableMapCreateMap);
        }
    }

    class f implements g.b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f8686a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Promise f8687b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ ReadableMap f8688c;

        f(int i3, Promise promise, ReadableMap readableMap) {
            this.f8686a = i3;
            this.f8687b = promise;
            this.f8688c = readableMap;
        }

        @Override // com.rnfs.g.b
        public void a(com.rnfs.h hVar) {
            if (hVar.f8726c != null) {
                RNFSManager.this.reject(this.f8687b, this.f8688c.getString("toUrl"), hVar.f8726c);
                return;
            }
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putInt("jobId", this.f8686a);
            writableMapCreateMap.putInt("statusCode", hVar.f8724a);
            writableMapCreateMap.putMap("headers", hVar.f8725b);
            writableMapCreateMap.putString("body", hVar.f8727d);
            this.f8687b.resolve(writableMapCreateMap);
        }
    }

    class g implements g.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f8690a;

        g(int i3) {
            this.f8690a = i3;
        }

        @Override // com.rnfs.g.a
        public void a() {
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putInt("jobId", this.f8690a);
            RNFSManager rNFSManager = RNFSManager.this;
            rNFSManager.sendEvent(rNFSManager.getReactApplicationContext(), "UploadBegin", writableMapCreateMap);
        }
    }

    class h implements g.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f8692a;

        h(int i3) {
            this.f8692a = i3;
        }

        @Override // com.rnfs.g.c
        public void a(int i3, int i4) {
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putInt("jobId", this.f8692a);
            writableMapCreateMap.putInt("totalBytesExpectedToSend", i3);
            writableMapCreateMap.putInt("totalBytesSent", i4);
            RNFSManager rNFSManager = RNFSManager.this;
            rNFSManager.sendEvent(rNFSManager.getReactApplicationContext(), "UploadProgress", writableMapCreateMap);
        }
    }

    class i implements MediaScannerConnection.MediaScannerConnectionClient {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Promise f8694a;

        i(Promise promise) {
            this.f8694a = promise;
        }

        @Override // android.media.MediaScannerConnection.MediaScannerConnectionClient
        public void onMediaScannerConnected() {
        }

        @Override // android.media.MediaScannerConnection.OnScanCompletedListener
        public void onScanCompleted(String str, Uri uri) {
            this.f8694a.resolve(str);
        }
    }

    private class j extends AsyncTask {
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Exception doInBackground(String... strArr) {
            try {
                String str = strArr[0];
                String str2 = strArr[1];
                InputStream inputStream = RNFSManager.this.getInputStream(str);
                OutputStream outputStream = RNFSManager.this.getOutputStream(str2, false);
                byte[] bArr = new byte[1024];
                while (true) {
                    int i3 = inputStream.read(bArr);
                    if (i3 <= 0) {
                        inputStream.close();
                        outputStream.close();
                        return null;
                    }
                    outputStream.write(bArr, 0, i3);
                    Thread.yield();
                }
            } catch (Exception e3) {
                return e3;
            }
        }

        private j() {
        }
    }

    public RNFSManager(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
        this.downloaders = new SparseArray<>();
        this.uploaders = new SparseArray<>();
        this.reactContext = reactApplicationContext;
    }

    private void DeleteRecursive(File file) {
        if (file.isDirectory()) {
            for (File file2 : file.listFiles()) {
                DeleteRecursive(file2);
            }
        }
        file.delete();
    }

    /* JADX WARN: Can't wrap try/catch for region: R(12:0|2|38|3|4|(2:50|5)|(4:6|(1:8)(1:52)|37|26)|13|46|14|(3:16|37|26)(1:53)|(1:(0))) */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void copyInputStream(java.io.InputStream r7, java.lang.String r8, java.lang.String r9, com.facebook.react.bridge.Promise r10) throws java.lang.Throwable {
        /*
            r6 = this;
            r0 = 0
            r1 = 0
            java.io.OutputStream r2 = r6.getOutputStream(r9, r0)     // Catch: java.lang.Throwable -> L27 java.lang.Exception -> L29
            r3 = 10240(0x2800, float:1.4349E-41)
            byte[] r3 = new byte[r3]     // Catch: java.lang.Throwable -> L15 java.lang.Exception -> L18
        La:
            int r4 = r7.read(r3)     // Catch: java.lang.Throwable -> L15 java.lang.Exception -> L18
            r5 = -1
            if (r4 == r5) goto L1b
            r2.write(r3, r0, r4)     // Catch: java.lang.Throwable -> L15 java.lang.Exception -> L18
            goto La
        L15:
            r8 = move-exception
            r1 = r2
            goto L4b
        L18:
            r0 = move-exception
            r1 = r2
            goto L2a
        L1b:
            r10.resolve(r1)     // Catch: java.lang.Throwable -> L15 java.lang.Exception -> L18
            r7.close()     // Catch: java.io.IOException -> L21
        L21:
            if (r2 == 0) goto L4a
            r2.close()     // Catch: java.io.IOException -> L4a
            goto L4a
        L27:
            r8 = move-exception
            goto L4b
        L29:
            r0 = move-exception
        L2a:
            java.lang.Exception r2 = new java.lang.Exception     // Catch: java.lang.Throwable -> L27
            java.lang.String r3 = "Failed to copy '%s' to %s (%s)"
            java.lang.String r0 = r0.getLocalizedMessage()     // Catch: java.lang.Throwable -> L27
            java.lang.Object[] r9 = new java.lang.Object[]{r8, r9, r0}     // Catch: java.lang.Throwable -> L27
            java.lang.String r9 = java.lang.String.format(r3, r9)     // Catch: java.lang.Throwable -> L27
            r2.<init>(r9)     // Catch: java.lang.Throwable -> L27
            r6.reject(r10, r8, r2)     // Catch: java.lang.Throwable -> L27
            if (r7 == 0) goto L45
            r7.close()     // Catch: java.io.IOException -> L45
        L45:
            if (r1 == 0) goto L4a
            r1.close()     // Catch: java.io.IOException -> L4a
        L4a:
            return
        L4b:
            if (r7 == 0) goto L50
            r7.close()     // Catch: java.io.IOException -> L50
        L50:
            if (r1 == 0) goto L55
            r1.close()     // Catch: java.io.IOException -> L55
        L55:
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.rnfs.RNFSManager.copyInputStream(java.io.InputStream, java.lang.String, java.lang.String, com.facebook.react.bridge.Promise):void");
    }

    private Uri getFileUri(String str, boolean z3) throws com.rnfs.d {
        Uri uri = Uri.parse(str);
        if (uri.getScheme() != null) {
            return uri;
        }
        File file = new File(str);
        if (z3 || !file.isDirectory()) {
            return Uri.parse("file://" + str);
        }
        throw new com.rnfs.d("EISDIR", "EISDIR: illegal operation on a directory, read '" + str + "'");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public InputStream getInputStream(String str) throws com.rnfs.d {
        try {
            InputStream inputStreamOpenInputStream = this.reactContext.getContentResolver().openInputStream(getFileUri(str, false));
            if (inputStreamOpenInputStream != null) {
                return inputStreamOpenInputStream;
            }
            throw new com.rnfs.d("ENOENT", "ENOENT: could not open an input stream for '" + str + "'");
        } catch (FileNotFoundException e3) {
            throw new com.rnfs.d("ENOENT", "ENOENT: " + e3.getMessage() + ", open '" + str + "'");
        }
    }

    private static byte[] getInputStreamBytes(InputStream inputStream) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] bArr = new byte[1024];
        while (true) {
            try {
                int i3 = inputStream.read(bArr);
                if (i3 == -1) {
                    break;
                }
                byteArrayOutputStream.write(bArr, 0, i3);
            } catch (Throwable th) {
                try {
                    byteArrayOutputStream.close();
                } catch (IOException unused) {
                }
                throw th;
            }
        }
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        try {
            byteArrayOutputStream.close();
        } catch (IOException unused2) {
        }
        return byteArray;
    }

    private String getOriginalFilepath(String str, boolean z3) throws com.rnfs.d {
        Uri fileUri = getFileUri(str, z3);
        if (fileUri.getScheme().equals("content")) {
            try {
                Cursor cursorQuery = this.reactContext.getContentResolver().query(fileUri, null, null, null, null);
                if (cursorQuery.moveToFirst()) {
                    str = cursorQuery.getString(cursorQuery.getColumnIndexOrThrow("_data"));
                }
                cursorQuery.close();
            } catch (IllegalArgumentException unused) {
            }
        }
        return str;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public OutputStream getOutputStream(String str, boolean z3) throws com.rnfs.d {
        try {
            OutputStream outputStreamOpenOutputStream = this.reactContext.getContentResolver().openOutputStream(getFileUri(str, false), z3 ? "wa" : getWriteAccessByAPILevel());
            if (outputStreamOpenOutputStream != null) {
                return outputStreamOpenOutputStream;
            }
            throw new com.rnfs.d("ENOENT", "ENOENT: could not open an output stream for '" + str + "'");
        } catch (FileNotFoundException e3) {
            throw new com.rnfs.d("ENOENT", "ENOENT: " + e3.getMessage() + ", open '" + str + "'");
        }
    }

    private int getResIdentifier(String str) {
        boolean z3 = true;
        String strSubstring = str.substring(str.lastIndexOf(".") + 1);
        String strSubstring2 = str.substring(0, str.lastIndexOf("."));
        if (!strSubstring.equals("png") && !strSubstring.equals("jpg") && !strSubstring.equals("jpeg") && !strSubstring.equals("bmp") && !strSubstring.equals("gif") && !strSubstring.equals("webp") && !strSubstring.equals("psd") && !strSubstring.equals("svg") && !strSubstring.equals("tiff")) {
            z3 = false;
        }
        return getReactApplicationContext().getResources().getIdentifier(strSubstring2, z3 ? "drawable" : "raw", getReactApplicationContext().getPackageName());
    }

    private String getWriteAccessByAPILevel() {
        return Build.VERSION.SDK_INT <= 28 ? "w" : "rwt";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void reject(Promise promise, String str, Exception exc) {
        if (exc instanceof FileNotFoundException) {
            rejectFileNotFound(promise, str);
        } else if (!(exc instanceof com.rnfs.d)) {
            promise.reject((String) null, exc.getMessage());
        } else {
            com.rnfs.d dVar = (com.rnfs.d) exc;
            promise.reject(dVar.a(), dVar.getMessage());
        }
    }

    private void rejectFileIsDirectory(Promise promise) {
        promise.reject("EISDIR", "EISDIR: illegal operation on a directory, read");
    }

    private void rejectFileNotFound(Promise promise, String str) {
        promise.reject("ENOENT", "ENOENT: no such file or directory, open '" + str + "'");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendEvent(ReactContext reactContext, String str, WritableMap writableMap) {
        ((RCTNativeAppEventEmitter) reactContext.getJSModule(RCTNativeAppEventEmitter.class)).emit(str, writableMap);
    }

    @ReactMethod
    public void addListener(String str) {
    }

    @ReactMethod
    public void appendFile(String str, String str2, Promise promise) {
        try {
            byte[] bArrDecode = Base64.decode(str2, 0);
            OutputStream outputStream = getOutputStream(str, true);
            outputStream.write(bArrDecode);
            outputStream.close();
            promise.resolve(null);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void copyFile(String str, String str2, ReadableMap readableMap, Promise promise) {
        new b(promise, str).execute(str, str2);
    }

    @ReactMethod
    public void copyFileAssets(String str, String str2, Promise promise) throws Throwable {
        try {
            copyInputStream(getReactApplicationContext().getAssets().open(str), str, str2, promise);
        } catch (IOException unused) {
            reject(promise, str, new Exception(String.format("Asset '%s' could not be opened", str)));
        }
    }

    @ReactMethod
    public void copyFileRes(String str, String str2, Promise promise) throws Throwable {
        try {
            copyInputStream(getReactApplicationContext().getResources().openRawResource(getResIdentifier(str)), str, str2, promise);
        } catch (Exception unused) {
            reject(promise, str, new Exception(String.format("Res '%s' could not be opened", str)));
        }
    }

    @ReactMethod
    public void downloadFile(ReadableMap readableMap, Promise promise) {
        try {
            File file = new File(readableMap.getString("toFile"));
            URL url = new URL(readableMap.getString("fromUrl"));
            int i3 = readableMap.getInt("jobId");
            ReadableMap map = readableMap.getMap("headers");
            int i4 = readableMap.getInt("progressInterval");
            int i5 = readableMap.getInt("progressDivider");
            int i6 = readableMap.getInt("readTimeout");
            int i7 = readableMap.getInt("connectionTimeout");
            boolean z3 = readableMap.getBoolean("hasBeginCallback");
            boolean z4 = readableMap.getBoolean("hasProgressCallback");
            com.rnfs.a aVar = new com.rnfs.a();
            aVar.f8697a = url;
            aVar.f8698b = file;
            aVar.f8699c = map;
            aVar.f8700d = i4;
            aVar.f8701e = i5;
            aVar.f8702f = i6;
            aVar.f8703g = i7;
            aVar.f8704h = new c(i3, promise, readableMap);
            if (z3) {
                aVar.f8705i = new d(i3);
            }
            if (z4) {
                aVar.f8706j = new e(i3);
            }
            com.rnfs.c cVar = new com.rnfs.c();
            cVar.execute(aVar);
            this.downloaders.put(i3, cVar);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, readableMap.getString("toFile"), e3);
        }
    }

    @ReactMethod
    public void exists(String str, Promise promise) {
        try {
            promise.resolve(Boolean.valueOf(new File(str).exists()));
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void existsAssets(String str, Promise promise) {
        try {
            AssetManager assets = getReactApplicationContext().getAssets();
            try {
                String[] list = assets.list(str);
                if (list != null && list.length > 0) {
                    promise.resolve(Boolean.TRUE);
                    return;
                }
            } catch (Exception unused) {
            }
            InputStream inputStreamOpen = null;
            try {
                try {
                    inputStreamOpen = assets.open(str);
                    promise.resolve(Boolean.TRUE);
                    if (inputStreamOpen == null) {
                        return;
                    }
                } catch (Exception unused2) {
                    promise.resolve(Boolean.FALSE);
                    if (inputStreamOpen == null) {
                        return;
                    }
                }
                try {
                    inputStreamOpen.close();
                } catch (Exception unused3) {
                }
            } catch (Throwable th) {
                if (inputStreamOpen != null) {
                    try {
                        inputStreamOpen.close();
                    } catch (Exception unused4) {
                    }
                }
                throw th;
            }
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void existsRes(String str, Promise promise) {
        try {
            if (getResIdentifier(str) > 0) {
                promise.resolve(Boolean.TRUE);
            } else {
                promise.resolve(Boolean.FALSE);
            }
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void getAllExternalFilesDirs(Promise promise) {
        File[] externalFilesDirs = getReactApplicationContext().getExternalFilesDirs(null);
        WritableArray writableArrayCreateArray = Arguments.createArray();
        for (File file : externalFilesDirs) {
            if (file != null) {
                writableArrayCreateArray.pushString(file.getAbsolutePath());
            }
        }
        promise.resolve(writableArrayCreateArray);
    }

    @Override // com.facebook.react.bridge.BaseJavaModule
    public Map<String, Object> getConstants() {
        HashMap map = new HashMap();
        map.put(RNFSDocumentDirectory, 0);
        map.put(RNFSDocumentDirectoryPath, getReactApplicationContext().getFilesDir().getAbsolutePath());
        map.put(RNFSTemporaryDirectoryPath, getReactApplicationContext().getCacheDir().getAbsolutePath());
        map.put(RNFSPicturesDirectoryPath, Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES).getAbsolutePath());
        map.put(RNFSCachesDirectoryPath, getReactApplicationContext().getCacheDir().getAbsolutePath());
        map.put(RNFSDownloadDirectoryPath, Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath());
        map.put(RNFSFileTypeRegular, 0);
        map.put(RNFSFileTypeDirectory, 1);
        File externalStorageDirectory = Environment.getExternalStorageDirectory();
        if (externalStorageDirectory != null) {
            map.put(RNFSExternalStorageDirectoryPath, externalStorageDirectory.getAbsolutePath());
        } else {
            map.put(RNFSExternalStorageDirectoryPath, null);
        }
        File externalFilesDir = getReactApplicationContext().getExternalFilesDir(null);
        if (externalFilesDir != null) {
            map.put(RNFSExternalDirectoryPath, externalFilesDir.getAbsolutePath());
        } else {
            map.put(RNFSExternalDirectoryPath, null);
        }
        File externalCacheDir = getReactApplicationContext().getExternalCacheDir();
        if (externalCacheDir != null) {
            map.put(RNFSExternalCachesDirectoryPath, externalCacheDir.getAbsolutePath());
        } else {
            map.put(RNFSExternalCachesDirectoryPath, null);
        }
        return map;
    }

    @ReactMethod
    public void getFSInfo(Promise promise) {
        StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
        StatFs statFs2 = new StatFs(Environment.getExternalStorageDirectory().getPath());
        long totalBytes = statFs.getTotalBytes();
        long freeBytes = statFs.getFreeBytes();
        long totalBytes2 = statFs2.getTotalBytes();
        long freeBytes2 = statFs2.getFreeBytes();
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putDouble("totalSpace", totalBytes);
        writableMapCreateMap.putDouble("freeSpace", freeBytes);
        writableMapCreateMap.putDouble("totalSpaceEx", totalBytes2);
        writableMapCreateMap.putDouble("freeSpaceEx", freeBytes2);
        promise.resolve(writableMapCreateMap);
    }

    @Override // com.facebook.react.bridge.NativeModule
    public String getName() {
        return MODULE_NAME;
    }

    @ReactMethod
    public void hash(String str, String str2, Promise promise) {
        int i3;
        try {
            HashMap map = new HashMap();
            map.put("md5", "MD5");
            map.put("sha1", "SHA-1");
            map.put("sha224", "SHA-224");
            map.put("sha256", "SHA-256");
            map.put("sha384", "SHA-384");
            map.put("sha512", "SHA-512");
            if (!map.containsKey(str2)) {
                throw new Exception("Invalid hash algorithm");
            }
            File file = new File(str);
            if (file.isDirectory()) {
                rejectFileIsDirectory(promise);
                return;
            }
            if (!file.exists()) {
                rejectFileNotFound(promise, str);
                return;
            }
            MessageDigest messageDigest = MessageDigest.getInstance((String) map.get(str2));
            FileInputStream fileInputStream = new FileInputStream(str);
            byte[] bArr = new byte[10240];
            while (true) {
                int i4 = fileInputStream.read(bArr);
                if (i4 == -1) {
                    break;
                } else {
                    messageDigest.update(bArr, 0, i4);
                }
            }
            StringBuilder sb = new StringBuilder();
            for (byte b3 : messageDigest.digest()) {
                sb.append(String.format("%02x", Byte.valueOf(b3)));
            }
            promise.resolve(sb.toString());
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void mkdir(String str, ReadableMap readableMap, Promise promise) {
        try {
            File file = new File(str);
            file.mkdirs();
            if (!file.exists()) {
                throw new Exception("Directory could not be created");
            }
            promise.resolve(null);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void moveFile(String str, String str2, ReadableMap readableMap, Promise promise) {
        try {
            File file = new File(str);
            if (file.renameTo(new File(str2))) {
                promise.resolve(Boolean.TRUE);
            } else {
                new a(file, promise, str).execute(str, str2);
            }
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void pathForBundle(String str, Promise promise) {
    }

    @ReactMethod
    public void pathForGroup(String str, Promise promise) {
    }

    @ReactMethod
    public void read(String str, int i3, int i4, Promise promise) {
        try {
            InputStream inputStream = getInputStream(str);
            byte[] bArr = new byte[i3];
            inputStream.skip(i4);
            promise.resolve(Base64.encodeToString(bArr, 0, inputStream.read(bArr, 0, i3), 2));
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void readDir(String str, Promise promise) {
        try {
            File file = new File(str);
            if (!file.exists()) {
                throw new Exception("Folder does not exist");
            }
            File[] fileArrListFiles = file.listFiles();
            WritableArray writableArrayCreateArray = Arguments.createArray();
            for (File file2 : fileArrListFiles) {
                WritableMap writableMapCreateMap = Arguments.createMap();
                writableMapCreateMap.putDouble("mtime", file2.lastModified() / 1000.0d);
                writableMapCreateMap.putString("name", file2.getName());
                writableMapCreateMap.putString("path", file2.getAbsolutePath());
                writableMapCreateMap.putDouble("size", file2.length());
                writableMapCreateMap.putInt("type", file2.isDirectory() ? 1 : 0);
                writableArrayCreateArray.pushMap(writableMapCreateMap);
            }
            promise.resolve(writableArrayCreateArray);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void readDirAssets(String str, Promise promise) {
        int length;
        try {
            AssetManager assets = getReactApplicationContext().getAssets();
            String[] list = assets.list(str);
            WritableArray writableArrayCreateArray = Arguments.createArray();
            for (String str2 : list) {
                WritableMap writableMapCreateMap = Arguments.createMap();
                writableMapCreateMap.putString("name", str2);
                if (!str.isEmpty()) {
                    str2 = String.format("%s/%s", str, str2);
                }
                writableMapCreateMap.putString("path", str2);
                int i3 = 1;
                try {
                    AssetFileDescriptor assetFileDescriptorOpenFd = assets.openFd(str2);
                    if (assetFileDescriptorOpenFd != null) {
                        length = (int) assetFileDescriptorOpenFd.getLength();
                        try {
                            assetFileDescriptorOpenFd.close();
                            i3 = 0;
                        } catch (IOException e3) {
                            e = e3;
                            i3 = 1 ^ (e.getMessage().contains("compressed") ? 1 : 0);
                        }
                    } else {
                        length = 0;
                    }
                } catch (IOException e4) {
                    e = e4;
                    length = 0;
                }
                writableMapCreateMap.putInt("size", length);
                writableMapCreateMap.putInt("type", i3);
                writableArrayCreateArray.pushMap(writableMapCreateMap);
            }
            promise.resolve(writableArrayCreateArray);
        } catch (IOException e5) {
            reject(promise, str, e5);
        }
    }

    @ReactMethod
    public void readFile(String str, Promise promise) {
        try {
            promise.resolve(Base64.encodeToString(getInputStreamBytes(getInputStream(str)), 2));
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void readFileAssets(String str, Promise promise) {
        InputStream inputStreamOpen = null;
        try {
            try {
                inputStreamOpen = getReactApplicationContext().getAssets().open(str, 0);
            } catch (Throwable th) {
                if (0 != 0) {
                    try {
                        inputStreamOpen.close();
                    } catch (IOException unused) {
                    }
                }
                throw th;
            }
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
            if (0 == 0) {
                return;
            }
        }
        if (inputStreamOpen == null) {
            reject(promise, str, new Exception("Failed to open file"));
            if (inputStreamOpen != null) {
                try {
                    inputStreamOpen.close();
                    return;
                } catch (IOException unused2) {
                    return;
                }
            }
            return;
        }
        byte[] bArr = new byte[inputStreamOpen.available()];
        inputStreamOpen.read(bArr);
        promise.resolve(Base64.encodeToString(bArr, 2));
        try {
            inputStreamOpen.close();
        } catch (IOException unused3) {
        }
    }

    @ReactMethod
    public void readFileRes(String str, Promise promise) {
        InputStream inputStreamOpenRawResource = null;
        try {
            try {
                inputStreamOpenRawResource = getReactApplicationContext().getResources().openRawResource(getResIdentifier(str));
            } catch (Throwable th) {
                if (0 != 0) {
                    try {
                        inputStreamOpenRawResource.close();
                    } catch (IOException unused) {
                    }
                }
                throw th;
            }
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
            if (0 == 0) {
                return;
            }
        }
        if (inputStreamOpenRawResource == null) {
            reject(promise, str, new Exception("Failed to open file"));
            if (inputStreamOpenRawResource != null) {
                try {
                    inputStreamOpenRawResource.close();
                    return;
                } catch (IOException unused2) {
                    return;
                }
            }
            return;
        }
        byte[] bArr = new byte[inputStreamOpenRawResource.available()];
        inputStreamOpenRawResource.read(bArr);
        promise.resolve(Base64.encodeToString(bArr, 2));
        try {
            inputStreamOpenRawResource.close();
        } catch (IOException unused3) {
        }
    }

    @ReactMethod
    public void removeListeners(Integer num) {
    }

    @ReactMethod
    public void scanFile(String str, Promise promise) {
        MediaScannerConnection.scanFile(getReactApplicationContext(), new String[]{str}, null, new i(promise));
    }

    @ReactMethod
    public void setReadable(String str, Boolean bool, Boolean bool2, Promise promise) {
        try {
            File file = new File(str);
            if (!file.exists()) {
                throw new Exception("File does not exist");
            }
            file.setReadable(bool.booleanValue(), bool2.booleanValue());
            promise.resolve(Boolean.TRUE);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void stat(String str, Promise promise) {
        try {
            String originalFilepath = getOriginalFilepath(str, true);
            File file = new File(originalFilepath);
            if (!file.exists()) {
                throw new Exception("File does not exist");
            }
            WritableMap writableMapCreateMap = Arguments.createMap();
            writableMapCreateMap.putInt("ctime", (int) (file.lastModified() / 1000));
            writableMapCreateMap.putInt("mtime", (int) (file.lastModified() / 1000));
            writableMapCreateMap.putDouble("size", file.length());
            writableMapCreateMap.putInt("type", file.isDirectory() ? 1 : 0);
            writableMapCreateMap.putString("originalFilepath", originalFilepath);
            promise.resolve(writableMapCreateMap);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void stopDownload(int i3) {
        com.rnfs.c cVar = this.downloaders.get(i3);
        if (cVar != null) {
            cVar.g();
        }
    }

    @ReactMethod
    public void stopUpload(int i3) {
        com.rnfs.i iVar = this.uploaders.get(i3);
        if (iVar != null) {
            iVar.f();
        }
    }

    @ReactMethod
    public void touch(String str, double d3, double d4, Promise promise) {
        try {
            promise.resolve(Boolean.valueOf(new File(str).setLastModified((long) d3)));
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void unlink(String str, Promise promise) {
        try {
            File file = new File(str);
            if (!file.exists()) {
                throw new Exception("File does not exist");
            }
            DeleteRecursive(file);
            promise.resolve(null);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void uploadFiles(ReadableMap readableMap, Promise promise) {
        String str;
        try {
            ReadableArray array = readableMap.getArray("files");
            URL url = new URL(readableMap.getString("toUrl"));
            int i3 = readableMap.getInt("jobId");
            ReadableMap map = readableMap.getMap("headers");
            ReadableMap map2 = readableMap.getMap("fields");
            String string = readableMap.getString("method");
            boolean z3 = readableMap.getBoolean("binaryStreamOnly");
            boolean z4 = readableMap.getBoolean("hasBeginCallback");
            boolean z5 = readableMap.getBoolean("hasProgressCallback");
            ArrayList arrayList = new ArrayList();
            com.rnfs.g gVar = new com.rnfs.g();
            str = "toUrl";
            for (int i4 = 0; i4 < array.size(); i4++) {
                try {
                    arrayList.add(array.getMap(i4));
                } catch (Exception e3) {
                    e = e3;
                    e.printStackTrace();
                    reject(promise, readableMap.getString(str), e);
                    return;
                }
            }
            gVar.f8715a = url;
            gVar.f8716b = arrayList;
            gVar.f8718d = map;
            gVar.f8720f = string;
            gVar.f8719e = map2;
            gVar.f8717c = z3;
            gVar.f8721g = new f(i3, promise, readableMap);
            if (z4) {
                gVar.f8723i = new g(i3);
            }
            if (z5) {
                gVar.f8722h = new h(i3);
            }
            com.rnfs.i iVar = new com.rnfs.i();
            iVar.execute(gVar);
            this.uploaders.put(i3, iVar);
        } catch (Exception e4) {
            e = e4;
            str = "toUrl";
        }
    }

    @ReactMethod
    public void write(String str, String str2, int i3, Promise promise) {
        try {
            byte[] bArrDecode = Base64.decode(str2, 0);
            if (i3 < 0) {
                OutputStream outputStream = getOutputStream(str, true);
                outputStream.write(bArrDecode);
                outputStream.close();
            } else {
                RandomAccessFile randomAccessFile = new RandomAccessFile(str, "rw");
                randomAccessFile.seek(i3);
                randomAccessFile.write(bArrDecode);
                randomAccessFile.close();
            }
            promise.resolve(null);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }

    @ReactMethod
    public void writeFile(String str, String str2, ReadableMap readableMap, Promise promise) {
        try {
            byte[] bArrDecode = Base64.decode(str2, 0);
            OutputStream outputStream = getOutputStream(str, false);
            outputStream.write(bArrDecode);
            outputStream.close();
            promise.resolve(null);
        } catch (Exception e3) {
            e3.printStackTrace();
            reject(promise, str, e3);
        }
    }
}
