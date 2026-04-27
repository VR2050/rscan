package im.uwrkaxlmjj.messenger.utils;

import android.content.ContentUris;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import com.king.zxing.util.LogUtils;

/* JADX INFO: loaded from: classes2.dex */
public class GalleryUtil {
    public static String getRealPathFromUri(Context context, Uri uri) {
        int sdkVersion = Build.VERSION.SDK_INT;
        if (sdkVersion >= 19) {
            return getRealPathFromUriAboveApi19(context, uri);
        }
        return getRealPathFromUriBelowAPI19(context, uri);
    }

    private static String getRealPathFromUriBelowAPI19(Context context, Uri uri) {
        return getDataColumn(context, uri, null, null);
    }

    private static String getRealPathFromUriAboveApi19(Context context, Uri uri) {
        if (!DocumentsContract.isDocumentUri(context, uri)) {
            if ("content".equalsIgnoreCase(uri.getScheme())) {
                String filePath = getDataColumn(context, uri, null, null);
                return filePath;
            }
            if (!"file".equals(uri.getScheme())) {
                return null;
            }
            String filePath2 = uri.getPath();
            return filePath2;
        }
        String documentId = DocumentsContract.getDocumentId(uri);
        if (isMediaDocument(uri)) {
            String id = documentId.split(LogUtils.COLON)[1];
            String[] selectionArgs = {id};
            String filePath3 = getDataColumn(context, MediaStore.Images.Media.EXTERNAL_CONTENT_URI, "_id=?", selectionArgs);
            return filePath3;
        }
        if (!isDownloadsDocument(uri)) {
            return null;
        }
        Uri contentUri = ContentUris.withAppendedId(Uri.parse("content://downloads/public_downloads"), Long.valueOf(documentId).longValue());
        String filePath4 = getDataColumn(context, contentUri, null, null);
        return filePath4;
    }

    private static String getDataColumn(Context context, Uri uri, String selection, String[] selectionArgs) {
        String[] projection = {"_data"};
        Cursor cursor = null;
        try {
            cursor = context.getContentResolver().query(uri, projection, selection, selectionArgs, null);
            if (cursor == null || !cursor.moveToFirst()) {
                return null;
            }
            int columnIndex = cursor.getColumnIndexOrThrow(projection[0]);
            String path = cursor.getString(columnIndex);
            return path;
        } catch (Exception e) {
            if (cursor == null) {
                return null;
            }
            cursor.close();
            return null;
        }
    }

    private static boolean isMediaDocument(Uri uri) {
        return "com.android.providers.media.documents".equals(uri.getAuthority());
    }

    private static boolean isDownloadsDocument(Uri uri) {
        return "com.android.providers.downloads.documents".equals(uri.getAuthority());
    }
}
