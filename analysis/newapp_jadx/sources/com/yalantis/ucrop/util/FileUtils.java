package com.yalantis.ucrop.util;

import android.annotation.SuppressLint;
import android.content.ContentUris;
import android.content.Context;
import android.net.Uri;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.channels.FileChannel;
import java.text.SimpleDateFormat;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class FileUtils {
    private static final String TAG = "FileUtils";

    /* renamed from: sf */
    private static SimpleDateFormat f10921sf = new SimpleDateFormat("yyyyMMdd_HHmmssSS");

    private FileUtils() {
    }

    public static boolean copyFile(FileInputStream fileInputStream, String str) {
        FileChannel fileChannel;
        FileChannel fileChannel2;
        if (fileInputStream == null) {
            return false;
        }
        FileChannel fileChannel3 = null;
        try {
            FileChannel channel = fileInputStream.getChannel();
            try {
                fileChannel3 = new FileOutputStream(new File(str)).getChannel();
                channel.transferTo(0L, channel.size(), fileChannel3);
                channel.close();
                fileInputStream.close();
                channel.close();
                if (fileChannel3 != null) {
                    fileChannel3.close();
                }
                return true;
            } catch (Exception unused) {
                fileChannel2 = fileChannel3;
                fileChannel3 = channel;
                fileInputStream.close();
                if (fileChannel3 != null) {
                    fileChannel3.close();
                }
                if (fileChannel2 != null) {
                    fileChannel2.close();
                }
                return false;
            } catch (Throwable th) {
                th = th;
                fileChannel = fileChannel3;
                fileChannel3 = channel;
                fileInputStream.close();
                if (fileChannel3 != null) {
                    fileChannel3.close();
                }
                if (fileChannel != null) {
                    fileChannel.close();
                }
                throw th;
            }
        } catch (Exception unused2) {
            fileChannel2 = null;
        } catch (Throwable th2) {
            th = th2;
            fileChannel = null;
        }
    }

    public static String getCreateFileName(String str) {
        long currentTimeMillis = System.currentTimeMillis();
        StringBuilder m586H = C1499a.m586H(str);
        m586H.append(f10921sf.format(Long.valueOf(currentTimeMillis)));
        return m586H.toString();
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0046, code lost:
    
        if (r8 == null) goto L21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:5:0x0029, code lost:
    
        if (r8 != null) goto L13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x002b, code lost:
    
        r8.close();
     */
    /* JADX WARN: Code restructure failed: missing block: B:7:0x0049, code lost:
    
        return null;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:23:0x004e  */
    /* JADX WARN: Type inference failed for: r7v0 */
    /* JADX WARN: Type inference failed for: r7v1, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r7v2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String getDataColumn(android.content.Context r8, android.net.Uri r9, java.lang.String r10, java.lang.String[] r11) {
        /*
            java.lang.String r0 = "_data"
            java.lang.String[] r3 = new java.lang.String[]{r0}
            r7 = 0
            android.content.ContentResolver r1 = r8.getContentResolver()     // Catch: java.lang.Throwable -> L2f java.lang.IllegalArgumentException -> L31
            r6 = 0
            r2 = r9
            r4 = r10
            r5 = r11
            android.database.Cursor r8 = r1.query(r2, r3, r4, r5, r6)     // Catch: java.lang.Throwable -> L2f java.lang.IllegalArgumentException -> L31
            if (r8 == 0) goto L29
            boolean r9 = r8.moveToFirst()     // Catch: java.lang.IllegalArgumentException -> L27 java.lang.Throwable -> L4a
            if (r9 == 0) goto L29
            int r9 = r8.getColumnIndexOrThrow(r0)     // Catch: java.lang.IllegalArgumentException -> L27 java.lang.Throwable -> L4a
            java.lang.String r9 = r8.getString(r9)     // Catch: java.lang.IllegalArgumentException -> L27 java.lang.Throwable -> L4a
            r8.close()
            return r9
        L27:
            r9 = move-exception
            goto L33
        L29:
            if (r8 == 0) goto L49
        L2b:
            r8.close()
            goto L49
        L2f:
            r9 = move-exception
            goto L4c
        L31:
            r9 = move-exception
            r8 = r7
        L33:
            java.util.Locale r10 = java.util.Locale.getDefault()     // Catch: java.lang.Throwable -> L4a
            java.lang.String r11 = "getDataColumn: _data - [%s]"
            r0 = 1
            java.lang.Object[] r0 = new java.lang.Object[r0]     // Catch: java.lang.Throwable -> L4a
            r1 = 0
            java.lang.String r9 = r9.getMessage()     // Catch: java.lang.Throwable -> L4a
            r0[r1] = r9     // Catch: java.lang.Throwable -> L4a
            java.lang.String.format(r10, r11, r0)     // Catch: java.lang.Throwable -> L4a
            if (r8 == 0) goto L49
            goto L2b
        L49:
            return r7
        L4a:
            r9 = move-exception
            r7 = r8
        L4c:
            if (r7 == 0) goto L51
            r7.close()
        L51:
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.yalantis.ucrop.util.FileUtils.getDataColumn(android.content.Context, android.net.Uri, java.lang.String, java.lang.String[]):java.lang.String");
    }

    @SuppressLint({"NewApi"})
    public static String getPath(Context context, Uri uri) {
        Uri uri2 = null;
        if (DocumentsContract.isDocumentUri(context, uri)) {
            if (isExternalStorageDocument(uri)) {
                String[] split = DocumentsContract.getDocumentId(uri).split(":");
                if ("primary".equalsIgnoreCase(split[0])) {
                    return Environment.getExternalStorageDirectory() + "/" + split[1];
                }
            } else if (isDownloadsDocument(uri)) {
                String documentId = DocumentsContract.getDocumentId(uri);
                if (!TextUtils.isEmpty(documentId)) {
                    try {
                        return getDataColumn(context, ContentUris.withAppendedId(Uri.parse("content://downloads/public_downloads"), Long.valueOf(documentId).longValue()), null, null);
                    } catch (NumberFormatException e2) {
                        e2.getMessage();
                        return null;
                    }
                }
            } else if (isMediaDocument(uri)) {
                String[] split2 = DocumentsContract.getDocumentId(uri).split(":");
                String str = split2[0];
                if ("image".equals(str)) {
                    uri2 = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
                } else if ("video".equals(str)) {
                    uri2 = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
                } else if ("audio".equals(str)) {
                    uri2 = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI;
                }
                return getDataColumn(context, uri2, "_id=?", new String[]{split2[1]});
            }
        } else {
            if ("content".equalsIgnoreCase(uri.getScheme())) {
                return isGooglePhotosUri(uri) ? uri.getLastPathSegment() : getDataColumn(context, uri, null, null);
            }
            if ("file".equalsIgnoreCase(uri.getScheme())) {
                return uri.getPath();
            }
        }
        return null;
    }

    public static boolean isDownloadsDocument(Uri uri) {
        return "com.android.providers.downloads.documents".equals(uri.getAuthority());
    }

    public static boolean isExternalStorageDocument(Uri uri) {
        return "com.android.externalstorage.documents".equals(uri.getAuthority());
    }

    public static boolean isGooglePhotosUri(Uri uri) {
        return "com.google.android.apps.photos.content".equals(uri.getAuthority());
    }

    public static boolean isMediaDocument(Uri uri) {
        return "com.android.providers.media.documents".equals(uri.getAuthority());
    }

    public static String rename(String str) {
        String substring = str.substring(0, str.lastIndexOf("."));
        String substring2 = str.substring(str.lastIndexOf("."));
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append(substring);
        stringBuffer.append("_");
        stringBuffer.append(getCreateFileName());
        stringBuffer.append(substring2);
        return stringBuffer.toString();
    }

    public static String getCreateFileName() {
        return f10921sf.format(Long.valueOf(System.currentTimeMillis()));
    }

    public static void copyFile(@NonNull String str, @NonNull String str2) {
        FileChannel fileChannel;
        FileChannel channel;
        if (str.equalsIgnoreCase(str2)) {
            return;
        }
        FileChannel fileChannel2 = null;
        try {
            channel = new FileInputStream(new File(str)).getChannel();
        } catch (Throwable th) {
            th = th;
            fileChannel = null;
        }
        try {
            fileChannel2 = new FileOutputStream(new File(str2)).getChannel();
            channel.transferTo(0L, channel.size(), fileChannel2);
            channel.close();
            channel.close();
            if (fileChannel2 != null) {
                fileChannel2.close();
            }
        } catch (Throwable th2) {
            th = th2;
            FileChannel fileChannel3 = fileChannel2;
            fileChannel2 = channel;
            fileChannel = fileChannel3;
            if (fileChannel2 != null) {
                fileChannel2.close();
            }
            if (fileChannel != null) {
                fileChannel.close();
            }
            throw th;
        }
    }
}
