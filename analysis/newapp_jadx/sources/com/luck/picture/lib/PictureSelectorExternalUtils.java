package com.luck.picture.lib;

import android.content.Context;
import android.media.ExifInterface;
import android.net.Uri;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.tools.PictureFileUtils;
import com.luck.picture.lib.tools.SdkVersionUtils;
import java.io.InputStream;

/* loaded from: classes2.dex */
public class PictureSelectorExternalUtils {
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0 */
    /* JADX WARN: Type inference failed for: r0v1, types: [java.io.Closeable] */
    /* JADX WARN: Type inference failed for: r0v2 */
    public static ExifInterface getExifInterface(Context context, String str) {
        InputStream inputStream;
        ?? r0 = 0;
        ExifInterface exifInterface = null;
        try {
            try {
                if (SdkVersionUtils.checkedAndroid_Q() && PictureMimeType.isContent(str)) {
                    inputStream = context.getContentResolver().openInputStream(Uri.parse(str));
                    if (inputStream != null) {
                        try {
                            exifInterface = new ExifInterface(inputStream);
                        } catch (Exception e2) {
                            e = e2;
                            e.printStackTrace();
                            PictureFileUtils.close(inputStream);
                            return null;
                        }
                    }
                } else {
                    exifInterface = new ExifInterface(str);
                    inputStream = null;
                }
                PictureFileUtils.close(inputStream);
                return exifInterface;
            } catch (Throwable th) {
                th = th;
                r0 = context;
                PictureFileUtils.close(r0);
                throw th;
            }
        } catch (Exception e3) {
            e = e3;
            inputStream = null;
        } catch (Throwable th2) {
            th = th2;
            PictureFileUtils.close(r0);
            throw th;
        }
    }
}
