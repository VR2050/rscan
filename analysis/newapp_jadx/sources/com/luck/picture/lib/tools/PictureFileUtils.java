package com.luck.picture.lib.tools;

import android.annotation.SuppressLint;
import android.content.ContentUris;
import android.content.Context;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.FileProvider;
import androidx.exifinterface.media.ExifInterface;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.widget.longimage.SubsamplingScaleImageView;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p474l.C4757s;
import p474l.InterfaceC4745g;
import p474l.InterfaceC4746h;

/* loaded from: classes2.dex */
public class PictureFileUtils {
    public static final String POSTFIX = ".jpeg";
    public static final String POST_AUDIO = ".mp3";
    public static final String POST_VIDEO = ".mp4";
    public static final String TAG = "PictureFileUtils";

    private PictureFileUtils() {
    }

    public static boolean bufferCopy(InterfaceC4746h interfaceC4746h, File file) {
        InterfaceC4745g interfaceC4745g = null;
        try {
            interfaceC4745g = C2354n.m2497n(C2354n.m2391F1(file, false, 1, null));
            C4757s c4757s = (C4757s) interfaceC4745g;
            c4757s.mo5396y(interfaceC4746h);
            c4757s.flush();
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        } finally {
            close(interfaceC4746h);
            close(interfaceC4745g);
        }
    }

    public static void close(@Nullable Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (Exception unused) {
            }
        }
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

    public static File createCameraFile(Context context, int i2, String str, String str2, String str3) {
        return createMediaFile(context, i2, str, str2, str3);
    }

    public static String createFilePath(Context context, String str, String str2, String str3) {
        String lastImgSuffix = PictureMimeType.getLastImgSuffix(str2);
        if (PictureMimeType.isHasVideo(str2)) {
            String str4 = getVideoDiskCacheDir(context) + File.separator;
            if (TextUtils.isEmpty(str)) {
                if (TextUtils.isEmpty(str3)) {
                    str3 = DateUtils.getCreateFileName("VID_") + lastImgSuffix;
                }
                return C1499a.m637w(str4, str3);
            }
            if (TextUtils.isEmpty(str3)) {
                StringBuilder m586H = C1499a.m586H("VID_");
                m586H.append(str.toUpperCase());
                m586H.append(lastImgSuffix);
                str3 = m586H.toString();
            }
            return C1499a.m637w(str4, str3);
        }
        if (PictureMimeType.isHasAudio(str2)) {
            String str5 = getAudioDiskCacheDir(context) + File.separator;
            if (TextUtils.isEmpty(str)) {
                if (TextUtils.isEmpty(str3)) {
                    str3 = DateUtils.getCreateFileName("AUD_") + lastImgSuffix;
                }
                return C1499a.m637w(str5, str3);
            }
            if (TextUtils.isEmpty(str3)) {
                StringBuilder m586H2 = C1499a.m586H("AUD_");
                m586H2.append(str.toUpperCase());
                m586H2.append(lastImgSuffix);
                str3 = m586H2.toString();
            }
            return C1499a.m637w(str5, str3);
        }
        String str6 = getDiskCacheDir(context) + File.separator;
        if (TextUtils.isEmpty(str)) {
            if (TextUtils.isEmpty(str3)) {
                str3 = DateUtils.getCreateFileName("IMG_") + lastImgSuffix;
            }
            return C1499a.m637w(str6, str3);
        }
        if (TextUtils.isEmpty(str3)) {
            StringBuilder m586H3 = C1499a.m586H("IMG_");
            m586H3.append(str.toUpperCase());
            m586H3.append(lastImgSuffix);
            str3 = m586H3.toString();
        }
        return C1499a.m637w(str6, str3);
    }

    private static File createMediaFile(Context context, int i2, String str, String str2, String str3) {
        return createOutFile(context, i2, str, str2, str3);
    }

    private static File createOutFile(Context context, int i2, String str, String str2, String str3) {
        File file;
        File rootDirFile;
        if (TextUtils.isEmpty(str3)) {
            if (TextUtils.equals("mounted", Environment.getExternalStorageState())) {
                rootDirFile = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM);
                StringBuilder sb = new StringBuilder();
                sb.append(rootDirFile.getAbsolutePath());
                String str4 = File.separator;
                file = new File(C1499a.m583E(sb, str4, PictureMimeType.CAMERA, str4));
            } else {
                rootDirFile = getRootDirFile(context, i2);
                file = new File(rootDirFile.getAbsolutePath() + File.separator);
            }
            if (!rootDirFile.exists()) {
                rootDirFile.mkdirs();
            }
        } else {
            file = new File(str3);
        }
        if (!file.exists()) {
            file.mkdirs();
        }
        boolean isEmpty = TextUtils.isEmpty(str);
        if (i2 == 2) {
            if (isEmpty) {
                str = DateUtils.getCreateFileName("VID_") + ".mp4";
            }
            return new File(file, str);
        }
        if (i2 == 3) {
            if (isEmpty) {
                str = DateUtils.getCreateFileName("AUD_") + POST_AUDIO;
            }
            return new File(file, str);
        }
        if (TextUtils.isEmpty(str2)) {
            str2 = ".jpeg";
        }
        if (isEmpty) {
            str = DateUtils.getCreateFileName("IMG_") + str2;
        }
        return new File(file, str);
    }

    public static void deleteAllCacheDirFile(Context context) {
        File[] listFiles;
        File[] listFiles2;
        File[] listFiles3;
        File externalFilesDir = context.getExternalFilesDir(Environment.DIRECTORY_PICTURES);
        if (externalFilesDir != null && (listFiles3 = externalFilesDir.listFiles()) != null) {
            for (File file : listFiles3) {
                if (file.isFile()) {
                    file.delete();
                }
            }
        }
        File externalFilesDir2 = context.getExternalFilesDir(Environment.DIRECTORY_MOVIES);
        if (externalFilesDir2 != null && (listFiles2 = externalFilesDir2.listFiles()) != null) {
            for (File file2 : listFiles2) {
                if (file2.isFile()) {
                    file2.delete();
                }
            }
        }
        File externalFilesDir3 = context.getExternalFilesDir(Environment.DIRECTORY_MUSIC);
        if (externalFilesDir3 == null || (listFiles = externalFilesDir3.listFiles()) == null) {
            return;
        }
        for (File file3 : listFiles) {
            if (file3.isFile()) {
                file3.delete();
            }
        }
    }

    public static void deleteCacheDirFile(Context context, int i2) {
        File[] listFiles;
        File externalFilesDir = context.getExternalFilesDir(i2 == PictureMimeType.ofImage() ? Environment.DIRECTORY_PICTURES : Environment.DIRECTORY_MOVIES);
        if (externalFilesDir == null || (listFiles = externalFilesDir.listFiles()) == null) {
            return;
        }
        for (File file : listFiles) {
            if (file.isFile()) {
                file.delete();
            }
        }
    }

    public static String extSuffix(InputStream inputStream) {
        try {
            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inJustDecodeBounds = true;
            BitmapFactory.decodeStream(inputStream, null, options);
            return options.outMimeType.replace("image/", ".");
        } catch (Exception unused) {
            return ".jpeg";
        }
    }

    public static String getAudioDiskCacheDir(Context context) {
        File externalFilesDir = context.getExternalFilesDir(Environment.DIRECTORY_MUSIC);
        return externalFilesDir == null ? "" : externalFilesDir.getPath();
    }

    public static String getDCIMCameraPath() {
        try {
            return "%" + Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM).getAbsolutePath() + "/Camera";
        } catch (Exception e2) {
            e2.printStackTrace();
            return "";
        }
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
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.tools.PictureFileUtils.getDataColumn(android.content.Context, android.net.Uri, java.lang.String, java.lang.String[]):java.lang.String");
    }

    public static String getDiskCacheDir(Context context) {
        File externalFilesDir = context.getExternalFilesDir(Environment.DIRECTORY_PICTURES);
        return externalFilesDir == null ? "" : externalFilesDir.getPath();
    }

    @SuppressLint({"NewApi"})
    public static String getPath(Context context, Uri uri) {
        Context applicationContext = context.getApplicationContext();
        Uri uri2 = null;
        if (DocumentsContract.isDocumentUri(applicationContext, uri)) {
            if (isExternalStorageDocument(uri)) {
                String[] split = DocumentsContract.getDocumentId(uri).split(":");
                if ("primary".equalsIgnoreCase(split[0])) {
                    if (SdkVersionUtils.checkedAndroid_Q()) {
                        return applicationContext.getExternalFilesDir(Environment.DIRECTORY_PICTURES) + "/" + split[1];
                    }
                    return Environment.getExternalStorageDirectory() + "/" + split[1];
                }
            } else {
                if (isDownloadsDocument(uri)) {
                    return getDataColumn(applicationContext, ContentUris.withAppendedId(Uri.parse("content://downloads/public_downloads"), Long.valueOf(DocumentsContract.getDocumentId(uri)).longValue()), null, null);
                }
                if (isMediaDocument(uri)) {
                    String[] split2 = DocumentsContract.getDocumentId(uri).split(":");
                    String str = split2[0];
                    if ("image".equals(str)) {
                        uri2 = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
                    } else if ("video".equals(str)) {
                        uri2 = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
                    } else if ("audio".equals(str)) {
                        uri2 = MediaStore.Audio.Media.EXTERNAL_CONTENT_URI;
                    }
                    return getDataColumn(applicationContext, uri2, "_id=?", new String[]{split2[1]});
                }
            }
        } else {
            if ("content".equalsIgnoreCase(uri.getScheme())) {
                return isGooglePhotosUri(uri) ? uri.getLastPathSegment() : getDataColumn(applicationContext, uri, null, null);
            }
            if ("file".equalsIgnoreCase(uri.getScheme())) {
                return uri.getPath();
            }
        }
        return null;
    }

    private static File getRootDirFile(Context context, int i2) {
        return i2 != 2 ? i2 != 3 ? context.getExternalFilesDir(Environment.DIRECTORY_PICTURES) : context.getExternalFilesDir(Environment.DIRECTORY_MUSIC) : context.getExternalFilesDir(Environment.DIRECTORY_MOVIES);
    }

    public static String getVideoDiskCacheDir(Context context) {
        File externalFilesDir = context.getExternalFilesDir(Environment.DIRECTORY_MOVIES);
        return externalFilesDir == null ? "" : externalFilesDir.getPath();
    }

    public static boolean isDownloadsDocument(Uri uri) {
        return "com.android.providers.downloads.documents".equals(uri.getAuthority());
    }

    public static boolean isExternalStorageDocument(Uri uri) {
        return "com.android.externalstorage.documents".equals(uri.getAuthority());
    }

    public static boolean isFileExists(String str) {
        return TextUtils.isEmpty(str) || new File(str).exists();
    }

    public static boolean isGooglePhotosUri(Uri uri) {
        return "com.google.android.apps.photos.content".equals(uri.getAuthority());
    }

    public static boolean isMediaDocument(Uri uri) {
        return "com.android.providers.media.documents".equals(uri.getAuthority());
    }

    public static Uri parUri(Context context, File file) {
        return Build.VERSION.SDK_INT > 23 ? FileProvider.getUriForFile(context, context.getPackageName() + ".provider", file) : Uri.fromFile(file);
    }

    public static int readPictureDegree(Context context, String str) {
        try {
            int attributeInt = ((SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isContent(str)) ? new ExifInterface(context.getContentResolver().openFileDescriptor(Uri.parse(str), "r").getFileDescriptor()) : new ExifInterface(str)).getAttributeInt(ExifInterface.TAG_ORIENTATION, 1);
            if (attributeInt == 3) {
                return 180;
            }
            if (attributeInt == 6) {
                return 90;
            }
            if (attributeInt != 8) {
                return 0;
            }
            return SubsamplingScaleImageView.ORIENTATION_270;
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    public static boolean bufferCopy(InterfaceC4746h interfaceC4746h, OutputStream outputStream) {
        InterfaceC4745g interfaceC4745g = null;
        try {
            try {
                interfaceC4745g = C2354n.m2497n(C2354n.m2385D1(outputStream));
                C4757s c4757s = (C4757s) interfaceC4745g;
                c4757s.mo5396y(interfaceC4746h);
                c4757s.flush();
                return true;
            } catch (Exception e2) {
                e2.printStackTrace();
                close(interfaceC4746h);
                close(interfaceC4745g);
                return false;
            }
        } finally {
            close(interfaceC4746h);
            close(interfaceC4745g);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v9, types: [l.s] */
    /* JADX WARN: Type inference failed for: r3v7, types: [java.io.Closeable, l.h, l.z] */
    public static boolean bufferCopy(File file, OutputStream outputStream) {
        InterfaceC4745g interfaceC4745g;
        InterfaceC4745g interfaceC4745g2 = null;
        try {
            ?? m2500o = C2354n.m2500o(C2354n.m2394G1(file));
            try {
                interfaceC4745g2 = C2354n.m2497n(C2354n.m2385D1(outputStream));
                ?? r1 = (C4757s) interfaceC4745g2;
                r1.mo5396y(m2500o);
                r1.flush();
                close(m2500o);
                close(outputStream);
                close(interfaceC4745g2);
                return true;
            } catch (Exception e2) {
                e = e2;
                InterfaceC4745g interfaceC4745g3 = interfaceC4745g2;
                interfaceC4745g2 = m2500o;
                interfaceC4745g = interfaceC4745g3;
                try {
                    e.printStackTrace();
                    close(interfaceC4745g2);
                    close(outputStream);
                    close(interfaceC4745g);
                    return false;
                } catch (Throwable th) {
                    th = th;
                    close(interfaceC4745g2);
                    close(outputStream);
                    close(interfaceC4745g);
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
                InterfaceC4745g interfaceC4745g4 = interfaceC4745g2;
                interfaceC4745g2 = m2500o;
                interfaceC4745g = interfaceC4745g4;
                close(interfaceC4745g2);
                close(outputStream);
                close(interfaceC4745g);
                throw th;
            }
        } catch (Exception e3) {
            e = e3;
            interfaceC4745g = null;
        } catch (Throwable th3) {
            th = th3;
            interfaceC4745g = null;
        }
    }
}
