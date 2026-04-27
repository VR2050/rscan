package com.reactnativecommunity.cameraroll;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.graphics.BitmapFactory;
import android.media.ExifInterface;
import android.media.MediaMetadataRetriever;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.provider.MediaStore;
import android.text.TextUtils;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.BaseActivityEventListener;
import com.facebook.react.bridge.GuardedAsyncTask;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeArray;
import com.facebook.react.bridge.WritableNativeMap;
import e2.AbstractC0521e;
import e2.h;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = "RNCCameraRoll")
public class CameraRollModule extends NativeCameraRollModuleSpec {
    private static final String ASSET_TYPE_ALL = "All";
    private static final String ASSET_TYPE_PHOTOS = "Photos";
    private static final String ASSET_TYPE_VIDEOS = "Videos";
    private static final int DELETE_REQUEST_CODE = 1001;
    private static final String ERROR_UNABLE_TO_DELETE = "E_UNABLE_TO_DELETE";
    private static final String ERROR_UNABLE_TO_FILTER = "E_UNABLE_TO_FILTER";
    private static final String ERROR_UNABLE_TO_LOAD = "E_UNABLE_TO_LOAD";
    private static final String ERROR_UNABLE_TO_LOAD_PERMISSION = "E_UNABLE_TO_LOAD_PERMISSION";
    private static final String ERROR_UNABLE_TO_SAVE = "E_UNABLE_TO_SAVE";
    private static final String INCLUDE_ALBUMS = "albums";
    private static final String INCLUDE_FILENAME = "filename";
    private static final String INCLUDE_FILE_EXTENSION = "fileExtension";
    private static final String INCLUDE_FILE_SIZE = "fileSize";
    private static final String INCLUDE_IMAGE_SIZE = "imageSize";
    private static final String INCLUDE_LOCATION = "location";
    private static final String INCLUDE_PLAYABLE_DURATION = "playableDuration";
    private static final String INCLUDE_SOURCE_TYPE = "sourceType";
    public static final String NAME = "RNCCameraRoll";
    private static final String SELECTION_BUCKET = "bucket_display_name = ?";
    private Promise deletePromise;
    private static final String INCLUDE_ORIENTATION = "orientation";
    private static final String[] PROJECTION = {"_id", "mime_type", "bucket_display_name", "datetaken", "date_added", "date_modified", "width", "height", "_size", "_data", INCLUDE_ORIENTATION};

    class a extends BaseActivityEventListener {
        a() {
        }

        @Override // com.facebook.react.bridge.BaseActivityEventListener, com.facebook.react.bridge.ActivityEventListener
        public void onActivityResult(Activity activity, int i3, int i4, Intent intent) {
            if (i3 != CameraRollModule.DELETE_REQUEST_CODE || CameraRollModule.this.deletePromise == null) {
                return;
            }
            if (i4 == -1) {
                CameraRollModule.this.deletePromise.resolve("Files successfully deleted");
            } else {
                CameraRollModule.this.deletePromise.reject("ERROR", "Deletion was not completed");
            }
            CameraRollModule.this.deletePromise = null;
        }
    }

    class b extends HashMap {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f8535b;

        b(String str) {
            this.f8535b = str;
            put("id", str);
            put("count", 1);
        }
    }

    private static class c extends GuardedAsyncTask {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Context f8537a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f8538b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final String f8539c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final String f8540d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final ReadableArray f8541e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final Promise f8542f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final String f8543g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private final long f8544h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private final long f8545i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private final Set f8546j;

        private static Set a(ReadableArray readableArray) {
            HashSet hashSet = new HashSet();
            if (readableArray == null) {
                return hashSet;
            }
            for (int i3 = 0; i3 < readableArray.size(); i3++) {
                String string = readableArray.getString(i3);
                if (string != null) {
                    hashSet.add(string);
                }
            }
            return hashSet;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.react.bridge.GuardedAsyncTask
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void doInBackgroundGuarded(Void... voidArr) {
            Cursor cursorQuery;
            StringBuilder sb = new StringBuilder("1");
            ArrayList arrayList = new ArrayList();
            if (!TextUtils.isEmpty(this.f8540d)) {
                sb.append(" AND bucket_display_name = ?");
                arrayList.add(this.f8540d);
            }
            if (this.f8543g.equals(CameraRollModule.ASSET_TYPE_PHOTOS)) {
                sb.append(" AND media_type = 1");
            } else if (this.f8543g.equals(CameraRollModule.ASSET_TYPE_VIDEOS)) {
                sb.append(" AND media_type = 3");
            } else {
                if (!this.f8543g.equals(CameraRollModule.ASSET_TYPE_ALL)) {
                    this.f8542f.reject(CameraRollModule.ERROR_UNABLE_TO_FILTER, "Invalid filter option: '" + this.f8543g + "'. Expected one of '" + CameraRollModule.ASSET_TYPE_PHOTOS + "', '" + CameraRollModule.ASSET_TYPE_VIDEOS + "' or '" + CameraRollModule.ASSET_TYPE_ALL + "'.");
                    return;
                }
                sb.append(" AND media_type IN (3,1)");
            }
            ReadableArray readableArray = this.f8541e;
            if (readableArray != null && readableArray.size() > 0) {
                sb.append(" AND mime_type IN (");
                for (int i3 = 0; i3 < this.f8541e.size(); i3++) {
                    sb.append("?,");
                    arrayList.add(this.f8541e.getString(i3));
                }
                sb.replace(sb.length() - 1, sb.length(), ")");
            }
            long j3 = this.f8544h;
            if (j3 > 0) {
                sb.append(" AND (datetaken > ? OR ( datetaken IS NULL AND date_added> ? ))");
                arrayList.add(this.f8544h + "");
                arrayList.add((j3 / 1000) + "");
            }
            long j4 = this.f8545i;
            if (j4 > 0) {
                sb.append(" AND (datetaken <= ? OR ( datetaken IS NULL AND date_added <= ? ))");
                arrayList.add(this.f8545i + "");
                arrayList.add((j4 / 1000) + "");
            }
            WritableNativeMap writableNativeMap = new WritableNativeMap();
            ContentResolver contentResolver = this.f8537a.getContentResolver();
            try {
                if (Build.VERSION.SDK_INT >= 30) {
                    Bundle bundle = new Bundle();
                    bundle.putString("android:query-arg-sql-selection", sb.toString());
                    bundle.putStringArray("android:query-arg-sql-selection-args", (String[]) arrayList.toArray(new String[arrayList.size()]));
                    bundle.putString("android:query-arg-sql-sort-order", "date_added DESC, date_modified DESC");
                    bundle.putInt("android:query-arg-limit", this.f8538b + 1);
                    if (!TextUtils.isEmpty(this.f8539c)) {
                        bundle.putInt("android:query-arg-offset", Integer.parseInt(this.f8539c));
                    }
                    cursorQuery = contentResolver.query(MediaStore.Files.getContentUri("external"), CameraRollModule.PROJECTION, bundle, null);
                } else {
                    String str = "limit=" + (this.f8538b + 1);
                    if (!TextUtils.isEmpty(this.f8539c)) {
                        str = "limit=" + this.f8539c + "," + (this.f8538b + 1);
                    }
                    cursorQuery = contentResolver.query(MediaStore.Files.getContentUri("external").buildUpon().encodedQuery(str).build(), CameraRollModule.PROJECTION, sb.toString(), (String[]) arrayList.toArray(new String[arrayList.size()]), "date_added DESC, date_modified DESC");
                }
                if (cursorQuery == null) {
                    this.f8542f.reject(CameraRollModule.ERROR_UNABLE_TO_LOAD, "Could not get media");
                    return;
                }
                try {
                    CameraRollModule.putEdges(contentResolver, cursorQuery, writableNativeMap, this.f8538b, this.f8546j);
                    CameraRollModule.putPageInfo(cursorQuery, writableNativeMap, this.f8538b, TextUtils.isEmpty(this.f8539c) ? 0 : Integer.parseInt(this.f8539c));
                    cursorQuery.close();
                    this.f8542f.resolve(writableNativeMap);
                } catch (Throwable th) {
                    cursorQuery.close();
                    this.f8542f.resolve(writableNativeMap);
                    throw th;
                }
            } catch (SecurityException e3) {
                this.f8542f.reject(CameraRollModule.ERROR_UNABLE_TO_LOAD_PERMISSION, "Could not get media: need READ_EXTERNAL_STORAGE permission", e3);
            }
        }

        private c(ReactContext reactContext, int i3, String str, String str2, ReadableArray readableArray, String str3, long j3, long j4, ReadableArray readableArray2, Promise promise) {
            super(reactContext);
            this.f8537a = reactContext;
            this.f8538b = i3;
            this.f8539c = str;
            this.f8540d = str2;
            this.f8541e = readableArray;
            this.f8542f = promise;
            this.f8543g = str3;
            this.f8544h = j3;
            this.f8545i = j4;
            this.f8546j = a(readableArray2);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class d extends GuardedAsyncTask {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Context f8547a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Uri f8548b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Promise f8549c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final ReadableMap f8550d;

        public d(ReactContext reactContext, Uri uri, ReadableMap readableMap, Promise promise) {
            super(reactContext);
            this.f8547a = reactContext;
            this.f8548b = uri;
            this.f8549c = promise;
            this.f8550d = readableMap;
        }

        private WritableMap c(Uri uri) {
            ContentResolver contentResolver = this.f8547a.getContentResolver();
            Cursor cursorQuery = contentResolver.query(uri, CameraRollModule.PROJECTION, null, null, null);
            if (cursorQuery == null) {
                throw new RuntimeException("Failed to find the photo that was just saved!");
            }
            cursorQuery.moveToFirst();
            WritableMap writableMapConvertMediaToMap = CameraRollModule.convertMediaToMap(contentResolver, cursorQuery, AbstractC0521e.a(new Object[]{CameraRollModule.INCLUDE_LOCATION, CameraRollModule.INCLUDE_FILENAME, CameraRollModule.INCLUDE_FILE_SIZE, CameraRollModule.INCLUDE_FILE_EXTENSION, CameraRollModule.INCLUDE_IMAGE_SIZE, CameraRollModule.INCLUDE_PLAYABLE_DURATION, CameraRollModule.INCLUDE_ORIENTATION, CameraRollModule.INCLUDE_ALBUMS, CameraRollModule.INCLUDE_SOURCE_TYPE}));
            cursorQuery.close();
            return writableMapConvertMediaToMap;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public /* synthetic */ void d(String str, Uri uri) {
            if (uri == null) {
                this.f8549c.reject(CameraRollModule.ERROR_UNABLE_TO_SAVE, "Could not add image to gallery");
                return;
            }
            try {
                this.f8549c.resolve(c(uri));
            } catch (Exception e3) {
                this.f8549c.reject(CameraRollModule.ERROR_UNABLE_TO_SAVE, e3.getMessage());
            }
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Can't wrap try/catch for region: R(9:0|2|(1:7)(1:6)|(4:109|8|9|115)|(9:11|(1:13)|20|(1:22)(1:23)|(1:25)|26|119|27|28)(7:(2:39|(1:41)(1:42))(1:44)|(2:46|(1:52)(2:50|51))|53|(2:55|56)(9:57|(2:59|60)(1:61)|124|(3:64|65|62)|123|66|121|67|68)|86|(2:116|88)|(3:93|108|94)(1:127))|113|69|(3:74|108|94)(1:125)|(1:(0))) */
        /* JADX WARN: Code restructure failed: missing block: B:71:0x01ae, code lost:
        
            r0 = move-exception;
         */
        /* JADX WARN: Code restructure failed: missing block: B:72:0x01af, code lost:
        
            Y.a.n("ReactNative", "Could not close input channel", r0);
         */
        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Removed duplicated region for block: B:106:0x01f5 A[EXC_TOP_SPLITTER, SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:111:0x01ea A[EXC_TOP_SPLITTER, SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:116:0x01d9 A[EXC_TOP_SPLITTER, SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:127:? A[RETURN, SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:128:? A[SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:93:0x01e4 A[Catch: IOException -> 0x01b9, TRY_ENTER, TRY_LEAVE, TryCatch #1 {IOException -> 0x01b9, blocks: (B:74:0x01b5, B:93:0x01e4), top: B:109:0x002e }] */
        /* JADX WARN: Type inference failed for: r10v0 */
        /* JADX WARN: Type inference failed for: r10v1 */
        /* JADX WARN: Type inference failed for: r10v10 */
        /* JADX WARN: Type inference failed for: r10v13 */
        /* JADX WARN: Type inference failed for: r10v14 */
        /* JADX WARN: Type inference failed for: r10v19, types: [java.io.OutputStream] */
        /* JADX WARN: Type inference failed for: r10v2 */
        /* JADX WARN: Type inference failed for: r10v20, types: [java.io.OutputStream] */
        /* JADX WARN: Type inference failed for: r10v23 */
        /* JADX WARN: Type inference failed for: r10v24 */
        /* JADX WARN: Type inference failed for: r10v25 */
        /* JADX WARN: Type inference failed for: r10v26 */
        /* JADX WARN: Type inference failed for: r10v27 */
        /* JADX WARN: Type inference failed for: r10v28 */
        /* JADX WARN: Type inference failed for: r10v3 */
        /* JADX WARN: Type inference failed for: r10v4, types: [java.io.OutputStream] */
        /* JADX WARN: Type inference failed for: r10v5, types: [java.io.OutputStream] */
        /* JADX WARN: Type inference failed for: r10v6 */
        /* JADX WARN: Type inference failed for: r10v7 */
        /* JADX WARN: Type inference failed for: r10v8 */
        /* JADX WARN: Type inference failed for: r10v9 */
        /* JADX WARN: Type inference failed for: r11v0 */
        /* JADX WARN: Type inference failed for: r11v1 */
        /* JADX WARN: Type inference failed for: r11v11, types: [java.io.FileInputStream] */
        /* JADX WARN: Type inference failed for: r11v13 */
        /* JADX WARN: Type inference failed for: r11v14 */
        /* JADX WARN: Type inference failed for: r11v15 */
        /* JADX WARN: Type inference failed for: r11v2, types: [java.io.FileInputStream] */
        /* JADX WARN: Type inference failed for: r11v3, types: [java.io.FileInputStream] */
        /* JADX WARN: Type inference failed for: r11v4, types: [java.lang.String] */
        /* JADX WARN: Type inference failed for: r11v5 */
        /* JADX WARN: Type inference failed for: r11v6 */
        /* JADX WARN: Type inference failed for: r11v7 */
        /* JADX WARN: Type inference failed for: r11v8, types: [java.io.FileInputStream] */
        @Override // com.facebook.react.bridge.GuardedAsyncTask
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void doInBackgroundGuarded(java.lang.Void... r19) throws java.lang.Throwable {
            /*
                Method dump skipped, instruction units count: 511
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.reactnativecommunity.cameraroll.CameraRollModule.d.doInBackgroundGuarded(java.lang.Void[]):void");
        }
    }

    public CameraRollModule(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
        reactApplicationContext.addActivityEventListener(new a());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static WritableMap convertMediaToMap(ContentResolver contentResolver, Cursor cursor, Set<String> set) {
        int columnIndex = cursor.getColumnIndex("_id");
        int columnIndex2 = cursor.getColumnIndex("mime_type");
        int columnIndex3 = cursor.getColumnIndex("bucket_display_name");
        int columnIndex4 = cursor.getColumnIndex("datetaken");
        int columnIndex5 = cursor.getColumnIndex("date_added");
        int columnIndex6 = cursor.getColumnIndex("date_modified");
        int columnIndex7 = cursor.getColumnIndex("width");
        int columnIndex8 = cursor.getColumnIndex("height");
        int columnIndex9 = cursor.getColumnIndex("_size");
        int columnIndex10 = cursor.getColumnIndex("_data");
        int columnIndex11 = cursor.getColumnIndex(INCLUDE_ORIENTATION);
        boolean zContains = set.contains(INCLUDE_LOCATION);
        boolean zContains2 = set.contains(INCLUDE_FILENAME);
        boolean zContains3 = set.contains(INCLUDE_FILE_SIZE);
        boolean zContains4 = set.contains(INCLUDE_FILE_EXTENSION);
        boolean zContains5 = set.contains(INCLUDE_IMAGE_SIZE);
        boolean zContains6 = set.contains(INCLUDE_PLAYABLE_DURATION);
        boolean zContains7 = set.contains(INCLUDE_ORIENTATION);
        boolean zContains8 = set.contains(INCLUDE_ALBUMS);
        boolean zContains9 = set.contains(INCLUDE_SOURCE_TYPE);
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        WritableNativeMap writableNativeMap2 = new WritableNativeMap();
        if (!putImageInfo(contentResolver, cursor, writableNativeMap2, columnIndex7, columnIndex8, columnIndex9, columnIndex10, columnIndex11, columnIndex2, zContains2, zContains3, zContains4, zContains5, zContains6, zContains7)) {
            return null;
        }
        putBasicNodeInfo(cursor, writableNativeMap2, columnIndex, columnIndex2, columnIndex3, columnIndex4, columnIndex5, columnIndex6, zContains8, zContains9);
        putLocationInfo(cursor, writableNativeMap2, columnIndex10, zContains, columnIndex2, contentResolver);
        writableNativeMap.putMap("node", writableNativeMap2);
        return writableNativeMap;
    }

    private static void putBasicNodeInfo(Cursor cursor, WritableMap writableMap, int i3, int i4, int i5, int i6, int i7, int i8, boolean z3, boolean z4) {
        writableMap.putString("id", Long.toString(cursor.getLong(i3)));
        writableMap.putString("type", cursor.getString(i4));
        writableMap.putArray("subTypes", Arguments.createArray());
        if (z4) {
            writableMap.putString(INCLUDE_SOURCE_TYPE, "UserLibrary");
        } else {
            writableMap.putNull(INCLUDE_SOURCE_TYPE);
        }
        WritableArray writableArrayCreateArray = Arguments.createArray();
        if (z3) {
            writableArrayCreateArray.pushString(cursor.getString(i5));
        }
        writableMap.putArray("group_name", writableArrayCreateArray);
        long j3 = cursor.getLong(i6);
        if (j3 == 0) {
            j3 = cursor.getLong(i7) * 1000;
        }
        writableMap.putDouble("timestamp", j3 / 1000.0d);
        writableMap.putDouble("modificationTimestamp", cursor.getLong(i8));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void putEdges(ContentResolver contentResolver, Cursor cursor, WritableMap writableMap, int i3, Set<String> set) {
        WritableNativeArray writableNativeArray = new WritableNativeArray();
        cursor.moveToFirst();
        int i4 = 0;
        while (i4 < i3 && !cursor.isAfterLast()) {
            WritableMap writableMapConvertMediaToMap = convertMediaToMap(contentResolver, cursor, set);
            if (writableMapConvertMediaToMap != null) {
                writableNativeArray.pushMap(writableMapConvertMediaToMap);
            } else {
                i4--;
            }
            cursor.moveToNext();
            i4++;
        }
        writableMap.putArray("edges", writableNativeArray);
    }

    private static boolean putImageInfo(ContentResolver contentResolver, Cursor cursor, WritableMap writableMap, int i3, int i4, int i5, int i6, int i7, int i8, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, boolean z8) throws FileNotFoundException {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        int columnIndex = cursor.getColumnIndex("_id");
        long j3 = columnIndex >= 0 ? cursor.getLong(columnIndex) : -1L;
        String string = cursor.getString(i8);
        boolean z9 = string != null && string.startsWith("video");
        Uri uriWithAppendedId = z9 ? ContentUris.withAppendedId(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, j3) : ContentUris.withAppendedId(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, j3);
        writableNativeMap.putString("uri", uriWithAppendedId.toString());
        boolean zPutImageSize = putImageSize(contentResolver, cursor, writableNativeMap, i3, i4, i7, uriWithAppendedId, z9, z6);
        boolean zPutPlayableDuration = putPlayableDuration(contentResolver, writableNativeMap, uriWithAppendedId, z9, z7);
        if (z3) {
            writableNativeMap.putString(INCLUDE_FILENAME, new File(cursor.getString(i6)).getName());
        } else {
            writableNativeMap.putNull(INCLUDE_FILENAME);
        }
        if (z4) {
            writableNativeMap.putDouble(INCLUDE_FILE_SIZE, cursor.getLong(i5));
        } else {
            writableNativeMap.putNull(INCLUDE_FILE_SIZE);
        }
        if (z5) {
            writableNativeMap.putString("extension", h.a(string));
        } else {
            writableNativeMap.putNull("extension");
        }
        if (!z8) {
            writableNativeMap.putNull(INCLUDE_ORIENTATION);
        } else if (cursor.isNull(i7)) {
            writableNativeMap.putInt(INCLUDE_ORIENTATION, cursor.getInt(i7));
        } else {
            writableNativeMap.putInt(INCLUDE_ORIENTATION, 0);
        }
        writableMap.putMap("image", writableNativeMap);
        return zPutImageSize && zPutPlayableDuration;
    }

    /* JADX WARN: Unreachable blocks removed: 2, instructions: 2 */
    private static boolean putImageSize(ContentResolver contentResolver, Cursor cursor, WritableMap writableMap, int i3, int i4, int i5, Uri uri, boolean z3, boolean z4) throws FileNotFoundException {
        boolean z5;
        AssetFileDescriptor assetFileDescriptorOpenAssetFileDescriptor;
        int i6;
        writableMap.putNull("width");
        writableMap.putNull("height");
        boolean z6 = true;
        if (!z4) {
            return true;
        }
        int i7 = cursor.getInt(i3);
        int i8 = cursor.getInt(i4);
        if (i7 <= 0 || i8 <= 0) {
            boolean z7 = false;
            try {
                assetFileDescriptorOpenAssetFileDescriptor = contentResolver.openAssetFileDescriptor(uri, "r");
                z5 = true;
            } catch (FileNotFoundException e3) {
                Y.a.n("ReactNative", "Could not open asset file " + uri.toString(), e3);
                z5 = false;
                assetFileDescriptorOpenAssetFileDescriptor = null;
            }
            if (assetFileDescriptorOpenAssetFileDescriptor != null) {
                if (z3) {
                    MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
                    try {
                        mediaMetadataRetriever.setDataSource(assetFileDescriptorOpenAssetFileDescriptor.getFileDescriptor());
                    } catch (RuntimeException unused) {
                    }
                    try {
                        i7 = Integer.parseInt(mediaMetadataRetriever.extractMetadata(18));
                        i8 = Integer.parseInt(mediaMetadataRetriever.extractMetadata(19));
                        z7 = z5;
                    } catch (NumberFormatException e4) {
                        Y.a.n("ReactNative", "Number format exception occurred while trying to fetch video metadata for " + uri.toString(), e4);
                    }
                    try {
                        mediaMetadataRetriever.release();
                    } catch (Exception unused2) {
                    }
                    z6 = z7;
                } else {
                    BitmapFactory.Options options = new BitmapFactory.Options();
                    options.inJustDecodeBounds = true;
                    BitmapFactory.decodeFileDescriptor(assetFileDescriptorOpenAssetFileDescriptor.getFileDescriptor(), null, options);
                    int i9 = options.outWidth;
                    i8 = options.outHeight;
                    i7 = i9;
                    z6 = z5;
                }
                try {
                    assetFileDescriptorOpenAssetFileDescriptor.close();
                } catch (IOException e5) {
                    Y.a.n("ReactNative", "Can't close media descriptor " + uri.toString(), e5);
                }
            } else {
                z6 = z5;
            }
        }
        if (!cursor.isNull(i5) && (i6 = cursor.getInt(i5)) >= 0 && i6 % 180 != 0) {
            int i10 = i8;
            i8 = i7;
            i7 = i10;
        }
        writableMap.putInt("width", i7);
        writableMap.putInt("height", i8);
        return z6;
    }

    private static void putLocationInfo(Cursor cursor, WritableMap writableMap, int i3, boolean z3, int i4, ContentResolver contentResolver) {
        AssetFileDescriptor assetFileDescriptorOpenAssetFileDescriptor;
        writableMap.putNull(INCLUDE_LOCATION);
        if (z3) {
            try {
                String string = cursor.getString(i4);
                if (string == null || !string.startsWith("video")) {
                    ExifInterface exifInterface = new ExifInterface(cursor.getString(i3));
                    float[] fArr = new float[2];
                    if (exifInterface.getLatLong(fArr)) {
                        double d3 = fArr[1];
                        double d4 = fArr[0];
                        WritableNativeMap writableNativeMap = new WritableNativeMap();
                        writableNativeMap.putDouble("longitude", d3);
                        writableNativeMap.putDouble("latitude", d4);
                        writableMap.putMap(INCLUDE_LOCATION, writableNativeMap);
                        return;
                    }
                    return;
                }
                Uri uri = Uri.parse("file://" + cursor.getString(i3));
                try {
                    assetFileDescriptorOpenAssetFileDescriptor = contentResolver.openAssetFileDescriptor(uri, "r");
                } catch (FileNotFoundException e3) {
                    Y.a.n("ReactNative", "Could not open asset file " + uri.toString(), e3);
                    assetFileDescriptorOpenAssetFileDescriptor = null;
                }
                if (assetFileDescriptorOpenAssetFileDescriptor != null) {
                    MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
                    try {
                        mediaMetadataRetriever.setDataSource(assetFileDescriptorOpenAssetFileDescriptor.getFileDescriptor());
                    } catch (RuntimeException unused) {
                    }
                    try {
                        String strExtractMetadata = mediaMetadataRetriever.extractMetadata(23);
                        if (strExtractMetadata != null) {
                            String strReplaceAll = strExtractMetadata.replaceAll("/", "");
                            WritableNativeMap writableNativeMap2 = new WritableNativeMap();
                            writableNativeMap2.putDouble("latitude", Double.parseDouble(strReplaceAll.split("[+]|[-]")[1]));
                            writableNativeMap2.putDouble("longitude", Double.parseDouble(strReplaceAll.split("[+]|[-]")[2]));
                            writableMap.putMap(INCLUDE_LOCATION, writableNativeMap2);
                        }
                    } catch (NumberFormatException e4) {
                        Y.a.n("ReactNative", "Number format exception occurred while trying to fetch video metadata for " + uri.toString(), e4);
                    }
                    try {
                        mediaMetadataRetriever.release();
                    } catch (Exception unused2) {
                    }
                }
                if (assetFileDescriptorOpenAssetFileDescriptor != null) {
                    try {
                        assetFileDescriptorOpenAssetFileDescriptor.close();
                    } catch (IOException unused3) {
                    }
                }
            } catch (IOException e5) {
                Y.a.n("ReactNative", "Could not read the metadata", e5);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void putPageInfo(Cursor cursor, WritableMap writableMap, int i3, int i4) {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        writableNativeMap.putBoolean("has_next_page", i3 < cursor.getCount());
        if (i3 < cursor.getCount()) {
            writableNativeMap.putString("end_cursor", Integer.toString(i4 + i3));
        }
        writableMap.putMap("page_info", writableNativeMap);
    }

    private static boolean putPlayableDuration(ContentResolver contentResolver, WritableMap writableMap, Uri uri, boolean z3, boolean z4) {
        AssetFileDescriptor assetFileDescriptorOpenAssetFileDescriptor;
        writableMap.putNull(INCLUDE_PLAYABLE_DURATION);
        boolean z5 = true;
        if (z4 && z3) {
            boolean z6 = false;
            Integer numValueOf = null;
            try {
                assetFileDescriptorOpenAssetFileDescriptor = contentResolver.openAssetFileDescriptor(uri, "r");
            } catch (FileNotFoundException e3) {
                Y.a.n("ReactNative", "Could not open asset file " + uri.toString(), e3);
                z5 = false;
                assetFileDescriptorOpenAssetFileDescriptor = null;
            }
            if (assetFileDescriptorOpenAssetFileDescriptor != null) {
                MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
                try {
                    mediaMetadataRetriever.setDataSource(assetFileDescriptorOpenAssetFileDescriptor.getFileDescriptor());
                } catch (RuntimeException unused) {
                }
                try {
                    numValueOf = Integer.valueOf(Integer.parseInt(mediaMetadataRetriever.extractMetadata(9)) / 1000);
                    z6 = z5;
                } catch (NumberFormatException e4) {
                    Y.a.n("ReactNative", "Number format exception occurred while trying to fetch video metadata for " + uri.toString(), e4);
                }
                try {
                    mediaMetadataRetriever.release();
                } catch (Exception unused2) {
                }
                z5 = z6;
            }
            if (assetFileDescriptorOpenAssetFileDescriptor != null) {
                try {
                    assetFileDescriptorOpenAssetFileDescriptor.close();
                } catch (IOException unused3) {
                }
            }
            if (numValueOf != null) {
                writableMap.putInt(INCLUDE_PLAYABLE_DURATION, numValueOf.intValue());
            }
        }
        return z5;
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec
    public void addListener(String str) {
    }

    @ReactMethod
    public void deleteMediaFiles(ReadableArray readableArray, Promise promise) {
        ContentResolver contentResolver = getReactApplicationContext().getContentResolver();
        ArrayList arrayList = new ArrayList();
        for (int i3 = 0; i3 < readableArray.size(); i3++) {
            arrayList.add(Uri.parse(readableArray.getString(i3)));
        }
        this.deletePromise = promise;
        if (Build.VERSION.SDK_INT < 30) {
            try {
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    contentResolver.delete((Uri) it.next(), null, null);
                }
                promise.resolve("Files deleted");
                return;
            } catch (Exception e3) {
                promise.reject("ERROR", e3.getMessage());
                return;
            }
        }
        try {
            IntentSender intentSender = MediaStore.createDeleteRequest(contentResolver, arrayList).getIntentSender();
            Activity currentActivity = getCurrentActivity();
            if (currentActivity != null) {
                currentActivity.startIntentSenderForResult(intentSender, DELETE_REQUEST_CODE, null, 0, 0, 0);
            } else {
                promise.reject("ERROR", "Activity is null");
            }
        } catch (Exception e4) {
            promise.reject("ERROR", e4.getMessage());
        }
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec
    @ReactMethod
    public void deletePhotos(ReadableArray readableArray, Promise promise) {
        if (readableArray.size() == 0) {
            promise.reject(ERROR_UNABLE_TO_DELETE, "Need at least one URI to delete");
        } else {
            deleteMediaFiles(readableArray, promise);
        }
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec
    @ReactMethod
    public void getAlbums(ReadableMap readableMap, Promise promise) {
        String string = readableMap.hasKey("assetType") ? readableMap.getString("assetType") : ASSET_TYPE_ALL;
        StringBuilder sb = new StringBuilder("1");
        ArrayList arrayList = new ArrayList();
        if (string.equals(ASSET_TYPE_PHOTOS)) {
            sb.append(" AND media_type = 1");
        } else if (string.equals(ASSET_TYPE_VIDEOS)) {
            sb.append(" AND media_type = 3");
        } else {
            if (!string.equals(ASSET_TYPE_ALL)) {
                promise.reject(ERROR_UNABLE_TO_FILTER, "Invalid filter option: '" + string + "'. Expected one of '" + ASSET_TYPE_PHOTOS + "', '" + ASSET_TYPE_VIDEOS + "' or '" + ASSET_TYPE_ALL + "'.");
                return;
            }
            sb.append(" AND media_type IN (3,1)");
        }
        try {
            Cursor cursorQuery = getReactApplicationContext().getContentResolver().query(MediaStore.Files.getContentUri("external"), new String[]{"bucket_display_name", "bucket_id"}, sb.toString(), (String[]) arrayList.toArray(new String[arrayList.size()]), null);
            if (cursorQuery == null) {
                promise.reject(ERROR_UNABLE_TO_LOAD, "Could not get media");
                return;
            }
            WritableNativeArray writableNativeArray = new WritableNativeArray();
            try {
                if (cursorQuery.moveToFirst()) {
                    HashMap map = new HashMap();
                    do {
                        int columnIndex = cursorQuery.getColumnIndex("bucket_display_name");
                        int columnIndex2 = cursorQuery.getColumnIndex("bucket_id");
                        if (columnIndex < 0) {
                            throw new IndexOutOfBoundsException();
                        }
                        String string2 = cursorQuery.getString(columnIndex2);
                        String string3 = cursorQuery.getString(columnIndex);
                        if (string3 != null) {
                            Map map2 = (Map) map.get(string3);
                            if (map2 == null) {
                                map.put(string3, new b(string2));
                            } else {
                                map2.put("count", Integer.valueOf(((Integer) map2.get("count")).intValue() + 1));
                            }
                        }
                    } while (cursorQuery.moveToNext());
                    for (Map.Entry entry : map.entrySet()) {
                        WritableNativeMap writableNativeMap = new WritableNativeMap();
                        Map map3 = (Map) entry.getValue();
                        writableNativeMap.putString("title", (String) entry.getKey());
                        writableNativeMap.putInt("count", ((Integer) map3.get("count")).intValue());
                        writableNativeMap.putString("id", (String) map3.get("id"));
                        writableNativeArray.pushMap(writableNativeMap);
                    }
                }
                cursorQuery.close();
                promise.resolve(writableNativeArray);
            } catch (Throwable th) {
                cursorQuery.close();
                promise.resolve(writableNativeArray);
                throw th;
            }
        } catch (Exception e3) {
            promise.reject(ERROR_UNABLE_TO_LOAD, "Could not get media", e3);
        }
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec, com.facebook.react.bridge.NativeModule
    public String getName() {
        return "RNCCameraRoll";
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec
    @ReactMethod
    public void getPhotoByInternalID(String str, ReadableMap readableMap, Promise promise) {
        promise.reject("CameraRoll:getPhotoByInternalID", "getPhotoByInternalID is not supported on Android");
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec
    @ReactMethod
    public void getPhotoThumbnail(String str, ReadableMap readableMap, Promise promise) {
        promise.reject("CameraRoll:getPhotoThumbnail", "getPhotoThumbnail is not supported on Android");
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec
    @ReactMethod
    public void getPhotos(ReadableMap readableMap, Promise promise) {
        int i3 = readableMap.getInt("first");
        String string = readableMap.hasKey("after") ? readableMap.getString("after") : null;
        String string2 = readableMap.hasKey("groupName") ? readableMap.getString("groupName") : null;
        String string3 = readableMap.hasKey("assetType") ? readableMap.getString("assetType") : ASSET_TYPE_PHOTOS;
        long j3 = readableMap.hasKey("fromTime") ? (long) readableMap.getDouble("fromTime") : 0L;
        long j4 = readableMap.hasKey("toTime") ? (long) readableMap.getDouble("toTime") : 0L;
        new c(getReactApplicationContext(), i3, string, string2, readableMap.hasKey("mimeTypes") ? readableMap.getArray("mimeTypes") : null, string3, j3, j4, readableMap.hasKey("include") ? readableMap.getArray("include") : null, promise).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Void[0]);
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec
    public void removeListeners(double d3) {
    }

    @Override // com.reactnativecommunity.cameraroll.NativeCameraRollModuleSpec
    @ReactMethod
    public void saveToCameraRoll(String str, ReadableMap readableMap, Promise promise) {
        new d(getReactApplicationContext(), Uri.parse(str), readableMap, promise).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Void[0]);
    }
}
