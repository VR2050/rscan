package com.blankj.utilcode.util;

import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.util.Log;
import androidx.core.content.FileProvider;
import java.io.File;

/* JADX INFO: loaded from: classes.dex */
public final class UriUtils {
    private UriUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static Uri file2Uri(File file) {
        if (file == null) {
            throw new NullPointerException("Argument 'file' of type File (#0 out of 1, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        if (Build.VERSION.SDK_INT >= 24) {
            String authority = Utils.getApp().getPackageName() + ".utilcode.provider";
            return FileProvider.getUriForFile(Utils.getApp(), authority, file);
        }
        return Uri.fromFile(file);
    }

    /* JADX WARN: Code restructure failed: missing block: B:76:0x024b, code lost:
    
        android.util.Log.d("UriUtils", r25.toString() + " parse failed. -> 1_0");
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0264, code lost:
    
        return null;
     */
    /* JADX WARN: Removed duplicated region for block: B:52:0x019c  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x019f A[Catch: Exception -> 0x0209, TryCatch #3 {Exception -> 0x0209, blocks: (B:43:0x0175, B:45:0x0183, B:53:0x019f, B:55:0x01ae, B:58:0x01c0, B:60:0x01cb, B:62:0x01d1), top: B:128:0x0175 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.io.File uri2File(android.net.Uri r25) {
        /*
            Method dump skipped, instruction units count: 897
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.blankj.utilcode.util.UriUtils.uri2File(android.net.Uri):java.io.File");
    }

    private static File getFileFromUri(Uri uri, String code) {
        return getFileFromUri(uri, null, null, code);
    }

    private static File getFileFromUri(Uri uri, String selection, String[] selectionArgs, String code) {
        Cursor cursor = Utils.getApp().getContentResolver().query(uri, new String[]{"_data"}, selection, selectionArgs, null);
        try {
            if (cursor == null) {
                Log.d("UriUtils", uri.toString() + " parse failed(cursor is null). -> " + code);
                return null;
            }
            if (!cursor.moveToFirst()) {
                Log.d("UriUtils", uri.toString() + " parse failed(moveToFirst return false). -> " + code);
                return null;
            }
            int columnIndex = cursor.getColumnIndex("_data");
            if (columnIndex > -1) {
                return new File(cursor.getString(columnIndex));
            }
            Log.d("UriUtils", uri.toString() + " parse failed(columnIndex: " + columnIndex + " is wrong). -> " + code);
            return null;
        } catch (Exception e) {
            Log.d("UriUtils", uri.toString() + " parse failed. -> " + code);
            return null;
        } finally {
            cursor.close();
        }
    }
}
