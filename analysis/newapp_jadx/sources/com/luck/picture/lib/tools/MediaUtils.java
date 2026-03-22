package com.luck.picture.lib.tools;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.graphics.BitmapFactory;
import android.media.MediaMetadataRetriever;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.provider.MediaStore;
import android.text.TextUtils;
import androidx.annotation.Nullable;
import androidx.exifinterface.media.ExifInterface;
import com.luck.picture.lib.config.PictureConfig;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnCallbackListener;
import com.luck.picture.lib.thread.PictureThreadUtils;
import java.io.InputStream;
import java.util.Objects;

/* loaded from: classes2.dex */
public class MediaUtils {
    @Nullable
    public static Uri createImageUri(Context context, String str) {
        Uri[] uriArr = {null};
        String externalStorageState = Environment.getExternalStorageState();
        String valueOf = ValueOf.toString(Long.valueOf(System.currentTimeMillis()));
        ContentValues contentValues = new ContentValues(3);
        contentValues.put("_display_name", DateUtils.getCreateFileName("IMG_"));
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 29) {
            contentValues.put("datetaken", valueOf);
        }
        if (TextUtils.isEmpty(str) || str.startsWith("video")) {
            str = "image/jpeg";
        }
        contentValues.put("mime_type", str);
        if (externalStorageState.equals("mounted")) {
            if (i2 >= 29) {
                contentValues.put("relative_path", PictureMimeType.DCIM);
            }
            uriArr[0] = context.getContentResolver().insert(MediaStore.Images.Media.getContentUri("external"), contentValues);
        } else {
            uriArr[0] = context.getContentResolver().insert(MediaStore.Images.Media.getContentUri("internal"), contentValues);
        }
        return uriArr[0];
    }

    public static Bundle createQueryArgsBundle(String str, String[] strArr, int i2, int i3) {
        Bundle bundle = new Bundle();
        int i4 = Build.VERSION.SDK_INT;
        if (i4 >= 26) {
            bundle.putString("android:query-arg-sql-selection", str);
            bundle.putStringArray("android:query-arg-sql-selection-args", strArr);
            bundle.putString("android:query-arg-sql-sort-order", "_id DESC");
            if (i4 >= 30) {
                bundle.putString("android:query-arg-sql-limit", i2 + " offset " + i3);
            }
        }
        return bundle;
    }

    @Nullable
    public static Uri createVideoUri(Context context, String str) {
        Uri[] uriArr = {null};
        String externalStorageState = Environment.getExternalStorageState();
        String valueOf = ValueOf.toString(Long.valueOf(System.currentTimeMillis()));
        ContentValues contentValues = new ContentValues(3);
        contentValues.put("_display_name", DateUtils.getCreateFileName("VID_"));
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 29) {
            contentValues.put("datetaken", valueOf);
        }
        if (TextUtils.isEmpty(str) || str.startsWith("image")) {
            str = "video/mp4";
        }
        contentValues.put("mime_type", str);
        if (externalStorageState.equals("mounted")) {
            if (i2 >= 29) {
                contentValues.put("relative_path", Environment.DIRECTORY_MOVIES);
            }
            uriArr[0] = context.getContentResolver().insert(MediaStore.Video.Media.getContentUri("external"), contentValues);
        } else {
            uriArr[0] = context.getContentResolver().insert(MediaStore.Video.Media.getContentUri("internal"), contentValues);
        }
        return uriArr[0];
    }

    public static long extractDuration(Context context, boolean z, String str) {
        return z ? getLocalDuration(context, Uri.parse(str)) : getLocalDuration(str);
    }

    @Nullable
    public static String getAudioFilePathFromUri(Context context, Uri uri) {
        String str = "";
        try {
            Cursor query = context.getApplicationContext().getContentResolver().query(uri, null, null, null, null);
            if (query != null) {
                try {
                    query.moveToFirst();
                    str = query.getString(query.getColumnIndex("_data"));
                } finally {
                }
            }
            if (query != null) {
                query.close();
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return str;
    }

    public static long getCameraFirstBucketId(Context context) {
        Cursor cursor = null;
        try {
            try {
                String[] strArr = {PictureFileUtils.getDCIMCameraPath() + "%"};
                cursor = SdkVersionUtils.checkedAndroid_R() ? context.getApplicationContext().getContentResolver().query(MediaStore.Files.getContentUri("external"), null, createQueryArgsBundle("_data like ?", strArr, 1, 0), null) : context.getApplicationContext().getContentResolver().query(MediaStore.Files.getContentUri("external"), null, "_data like ?", strArr, "_id DESC limit 1 offset 0");
            } catch (Exception e2) {
                e2.printStackTrace();
                if (cursor == null) {
                    return -1L;
                }
            }
            if (cursor != null && cursor.getCount() > 0 && cursor.moveToFirst()) {
                long j2 = cursor.getLong(cursor.getColumnIndex(PictureConfig.EXTRA_BUCKET_ID));
                cursor.close();
                return j2;
            }
            if (cursor == null) {
                return -1L;
            }
            cursor.close();
            return -1L;
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.close();
            }
            throw th;
        }
    }

    public static int getDCIMLastImageId(Context context) {
        Cursor cursor = null;
        try {
            try {
                String[] strArr = {PictureFileUtils.getDCIMCameraPath() + "%"};
                cursor = SdkVersionUtils.checkedAndroid_R() ? context.getApplicationContext().getContentResolver().query(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, null, createQueryArgsBundle("_data like ?", strArr, 1, 0), null) : context.getApplicationContext().getContentResolver().query(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, null, "_data like ?", strArr, "_id DESC limit 1 offset 0");
                if (cursor == null || cursor.getCount() <= 0 || !cursor.moveToFirst()) {
                    if (cursor != null) {
                        cursor.close();
                    }
                    return -1;
                }
                int i2 = DateUtils.dateDiffer(cursor.getLong(cursor.getColumnIndex("date_added"))) <= 1 ? cursor.getInt(cursor.getColumnIndex("_id")) : -1;
                cursor.close();
                return i2;
            } catch (Exception e2) {
                e2.printStackTrace();
                if (cursor != null) {
                    cursor.close();
                }
                return -1;
            }
        } catch (Throwable th) {
            if (cursor != null) {
                cursor.close();
            }
            throw th;
        }
    }

    public static int getImageOrientationForUrl(Context context, String str) {
        InputStream inputStream;
        InputStream inputStream2 = null;
        ExifInterface exifInterface = null;
        InputStream inputStream3 = null;
        try {
            try {
                if (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isContent(str)) {
                    inputStream = context.getContentResolver().openInputStream(Uri.parse(str));
                    if (inputStream != null) {
                        try {
                            exifInterface = new ExifInterface(inputStream);
                        } catch (Exception e2) {
                            e = e2;
                            inputStream3 = inputStream;
                            e.printStackTrace();
                            PictureFileUtils.close(inputStream3);
                            return 0;
                        } catch (Throwable th) {
                            th = th;
                            inputStream2 = inputStream;
                            PictureFileUtils.close(inputStream2);
                            throw th;
                        }
                    }
                } else {
                    exifInterface = new ExifInterface(str);
                    inputStream = null;
                }
                int attributeInt = exifInterface != null ? exifInterface.getAttributeInt(ExifInterface.TAG_ORIENTATION, 1) : 0;
                PictureFileUtils.close(inputStream);
                return attributeInt;
            } catch (Exception e3) {
                e = e3;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0 */
    /* JADX WARN: Type inference failed for: r1v1 */
    /* JADX WARN: Type inference failed for: r1v15 */
    /* JADX WARN: Type inference failed for: r1v2, types: [java.io.Closeable] */
    /* JADX WARN: Type inference failed for: r1v5 */
    /* JADX WARN: Type inference failed for: r1v6 */
    /* JADX WARN: Type inference failed for: r1v7 */
    /* JADX WARN: Type inference failed for: r1v9, types: [int] */
    /* JADX WARN: Type inference failed for: r5v4, types: [int[]] */
    public static int[] getImageSizeForUri(Context context, Uri uri) {
        boolean z;
        int i2;
        BitmapFactory.Options options;
        ?? r1;
        boolean z2;
        ?? r12 = 0;
        ParcelFileDescriptor parcelFileDescriptor = null;
        try {
            try {
                ParcelFileDescriptor openFileDescriptor = context.getContentResolver().openFileDescriptor(uri, "r");
                if (openFileDescriptor != null) {
                    try {
                        try {
                            options = new BitmapFactory.Options();
                            options.inJustDecodeBounds = true;
                            BitmapFactory.decodeFileDescriptor(openFileDescriptor.getFileDescriptor(), null, options);
                            r1 = options.outWidth;
                        } catch (Exception e2) {
                            e = e2;
                            parcelFileDescriptor = openFileDescriptor;
                            z = false;
                            e.printStackTrace();
                            PictureFileUtils.close(parcelFileDescriptor);
                            i2 = 0;
                            r12 = z;
                            return new int[]{r12, i2};
                        }
                        try {
                            i2 = options.outHeight;
                            z2 = r1;
                        } catch (Exception e3) {
                            e = e3;
                            parcelFileDescriptor = openFileDescriptor;
                            z = r1;
                            e.printStackTrace();
                            PictureFileUtils.close(parcelFileDescriptor);
                            i2 = 0;
                            r12 = z;
                            return new int[]{r12, i2};
                        }
                    } catch (Throwable th) {
                        th = th;
                        r12 = openFileDescriptor;
                        PictureFileUtils.close(r12);
                        throw th;
                    }
                } else {
                    i2 = 0;
                    z2 = false;
                }
                PictureFileUtils.close(openFileDescriptor);
                r12 = z2;
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (Exception e4) {
            e = e4;
        }
        return new int[]{r12, i2};
    }

    public static int[] getImageSizeForUrl(String str) {
        int i2;
        int i3;
        ExifInterface exifInterface;
        try {
            exifInterface = new ExifInterface(str);
            i2 = exifInterface.getAttributeInt(ExifInterface.TAG_IMAGE_WIDTH, 1);
        } catch (Exception e2) {
            e = e2;
            i2 = 0;
        }
        try {
            i3 = exifInterface.getAttributeInt(ExifInterface.TAG_IMAGE_LENGTH, 1);
        } catch (Exception e3) {
            e = e3;
            e.printStackTrace();
            i3 = 0;
            return new int[]{i2, i3};
        }
        return new int[]{i2, i3};
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0048, code lost:
    
        return r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0045, code lost:
    
        if (r1 == null) goto L16;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int[] getImageSizeForUrlToAndroidQ(android.content.Context r4, java.lang.String r5) {
        /*
            r0 = 2
            int[] r0 = new int[r0]
            r1 = 0
            int r2 = android.os.Build.VERSION.SDK_INT     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            r3 = 26
            if (r2 < r3) goto L39
            android.content.Context r4 = r4.getApplicationContext()     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            android.content.ContentResolver r4 = r4.getContentResolver()     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            android.net.Uri r5 = android.net.Uri.parse(r5)     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            android.database.Cursor r1 = r4.query(r5, r1, r1, r1)     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            if (r1 == 0) goto L39
            r1.moveToFirst()     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            r4 = 0
            java.lang.String r5 = "width"
            int r5 = r1.getColumnIndexOrThrow(r5)     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            int r5 = r1.getInt(r5)     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            r0[r4] = r5     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            r4 = 1
            java.lang.String r5 = "height"
            int r5 = r1.getColumnIndexOrThrow(r5)     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            int r5 = r1.getInt(r5)     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
            r0[r4] = r5     // Catch: java.lang.Throwable -> L3f java.lang.Exception -> L41
        L39:
            if (r1 == 0) goto L48
        L3b:
            r1.close()
            goto L48
        L3f:
            r4 = move-exception
            goto L49
        L41:
            r4 = move-exception
            r4.printStackTrace()     // Catch: java.lang.Throwable -> L3f
            if (r1 == 0) goto L48
            goto L3b
        L48:
            return r0
        L49:
            if (r1 == 0) goto L4e
            r1.close()
        L4e:
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.luck.picture.lib.tools.MediaUtils.getImageSizeForUrlToAndroidQ(android.content.Context, java.lang.String):int[]");
    }

    private static long getLocalDuration(Context context, Uri uri) {
        try {
            MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
            mediaMetadataRetriever.setDataSource(context, uri);
            String extractMetadata = mediaMetadataRetriever.extractMetadata(9);
            Objects.requireNonNull(extractMetadata);
            return Long.parseLong(extractMetadata);
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0L;
        }
    }

    public static int getVideoOrientationForUri(Context context, Uri uri) {
        try {
            MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
            mediaMetadataRetriever.setDataSource(context, uri);
            int i2 = ValueOf.toInt(mediaMetadataRetriever.extractMetadata(24));
            if (i2 != 90) {
                return i2 != 270 ? 0 : 8;
            }
            return 6;
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    public static int getVideoOrientationForUrl(String str) {
        try {
            MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
            mediaMetadataRetriever.setDataSource(str);
            int i2 = ValueOf.toInt(mediaMetadataRetriever.extractMetadata(24));
            if (i2 != 90) {
                return i2 != 270 ? 0 : 8;
            }
            return 6;
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0;
        }
    }

    public static void getVideoSizeForUri(final Context context, final Uri uri, final LocalMedia localMedia) {
        PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<Integer[]>() { // from class: com.luck.picture.lib.tools.MediaUtils.1
            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public Integer[] doInBackground() {
                MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
                mediaMetadataRetriever.setDataSource(context, uri);
                return new Integer[]{Integer.valueOf(ValueOf.toInt(mediaMetadataRetriever.extractMetadata(18))), Integer.valueOf(ValueOf.toInt(mediaMetadataRetriever.extractMetadata(19)))};
            }

            @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
            public void onSuccess(Integer[] numArr) {
                localMedia.setWidth(numArr[0].intValue());
                localMedia.setHeight(numArr[1].intValue());
                PictureThreadUtils.cancel(this);
            }
        });
    }

    public static int[] getVideoSizeForUrl(String str) {
        int[] iArr = new int[2];
        try {
            MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
            mediaMetadataRetriever.setDataSource(str);
            iArr[0] = ValueOf.toInt(mediaMetadataRetriever.extractMetadata(18));
            iArr[1] = ValueOf.toInt(mediaMetadataRetriever.extractMetadata(19));
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return iArr;
    }

    public static boolean isLongImg(int i2, int i3) {
        return i3 > i2 * 3;
    }

    public static boolean isLongImg(LocalMedia localMedia) {
        if (localMedia != null) {
            return localMedia.getHeight() > localMedia.getWidth() * 3;
        }
        return false;
    }

    public static void removeMedia(Context context, int i2) {
        try {
            context.getApplicationContext().getContentResolver().delete(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, "_id=?", new String[]{Long.toString(i2)});
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    public static void setOrientationAsynchronous(final Context context, final LocalMedia localMedia, boolean z, boolean z2, final OnCallbackListener<LocalMedia> onCallbackListener) {
        if (!PictureMimeType.isHasImage(localMedia.getMimeType()) || z) {
            if (!PictureMimeType.isHasVideo(localMedia.getMimeType()) || z2) {
                if (localMedia.getOrientation() == -1) {
                    PictureThreadUtils.executeByIo(new PictureThreadUtils.SimpleTask<Integer>() { // from class: com.luck.picture.lib.tools.MediaUtils.2
                        @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                        public Integer doInBackground() {
                            return Integer.valueOf(PictureMimeType.isHasImage(LocalMedia.this.getMimeType()) ? MediaUtils.getImageOrientationForUrl(context, LocalMedia.this.getPath()) : PictureMimeType.isHasVideo(LocalMedia.this.getMimeType()) ? PictureMimeType.isContent(LocalMedia.this.getPath()) ? MediaUtils.getVideoOrientationForUri(context, Uri.parse(LocalMedia.this.getPath())) : MediaUtils.getVideoOrientationForUrl(LocalMedia.this.getPath()) : 0);
                        }

                        @Override // com.luck.picture.lib.thread.PictureThreadUtils.Task
                        public void onSuccess(Integer num) {
                            if (num.intValue() == 6 || num.intValue() == 8) {
                                LocalMedia localMedia2 = LocalMedia.this;
                                localMedia2.setWidth(localMedia2.getHeight());
                                LocalMedia localMedia3 = LocalMedia.this;
                                localMedia3.setHeight(localMedia3.getWidth());
                            }
                            LocalMedia.this.setOrientation(num.intValue());
                            OnCallbackListener onCallbackListener2 = onCallbackListener;
                            if (onCallbackListener2 != null) {
                                onCallbackListener2.onCall(LocalMedia.this);
                            }
                        }
                    });
                } else if (onCallbackListener != null) {
                    onCallbackListener.onCall(localMedia);
                }
            }
        }
    }

    public static void setOrientationSynchronous(Context context, LocalMedia localMedia, boolean z, boolean z2) {
        if (!PictureMimeType.isHasImage(localMedia.getMimeType()) || z) {
            if (!PictureMimeType.isHasVideo(localMedia.getMimeType()) || z2) {
                int i2 = 0;
                if (PictureMimeType.isHasImage(localMedia.getMimeType())) {
                    i2 = getImageOrientationForUrl(context, localMedia.getPath());
                } else if (PictureMimeType.isHasVideo(localMedia.getMimeType())) {
                    i2 = PictureMimeType.isContent(localMedia.getPath()) ? getVideoOrientationForUri(context, Uri.parse(localMedia.getPath())) : getVideoOrientationForUrl(localMedia.getPath());
                }
                if (i2 == 6 || i2 == 8) {
                    localMedia.setWidth(localMedia.getHeight());
                    localMedia.setHeight(localMedia.getWidth());
                }
                localMedia.setOrientation(i2);
            }
        }
    }

    private static long getLocalDuration(String str) {
        try {
            MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
            mediaMetadataRetriever.setDataSource(str);
            String extractMetadata = mediaMetadataRetriever.extractMetadata(9);
            Objects.requireNonNull(extractMetadata);
            return Long.parseLong(extractMetadata);
        } catch (Exception e2) {
            e2.printStackTrace();
            return 0L;
        }
    }
}
