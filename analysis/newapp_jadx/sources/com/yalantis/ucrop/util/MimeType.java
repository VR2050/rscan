package com.yalantis.ucrop.util;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import android.webkit.MimeTypeMap;
import com.luck.picture.lib.config.PictureMimeType;
import java.io.File;

/* loaded from: classes2.dex */
public class MimeType {
    public static final String MIME_TYPE_PREFIX_IMAGE = "image";
    public static final String MIME_TYPE_PREFIX_VIDEO = "video";

    public static String getImageMimeType(String str) {
        try {
            if (TextUtils.isEmpty(str)) {
                return "image/jpeg";
            }
            String name = new File(str).getName();
            return "image/" + name.substring(name.lastIndexOf(".") + 1);
        } catch (Exception e2) {
            e2.printStackTrace();
            return "image/jpeg";
        }
    }

    public static String getLastImgType(String str) {
        String substring;
        try {
            int lastIndexOf = str.lastIndexOf(".");
            if (lastIndexOf > 0) {
                substring = str.substring(lastIndexOf);
                switch (substring) {
                    case ".png":
                    case ".PNG":
                    case ".jpg":
                    case ".jpeg":
                    case ".JPEG":
                    case ".WEBP":
                    case ".bmp":
                    case ".BMP":
                    case ".webp":
                    case ".gif":
                    case ".GIF":
                        return substring;
                }
            }
            return PictureMimeType.PNG;
        } catch (Exception e2) {
            e2.printStackTrace();
            return PictureMimeType.PNG;
        }
    }

    public static String getMimeTypeFromMediaContentUri(Context context, Uri uri) {
        String type = uri.getScheme().equals("content") ? context.getContentResolver().getType(uri) : MimeTypeMap.getSingleton().getMimeTypeFromExtension(MimeTypeMap.getFileExtensionFromUrl(uri.toString()).toLowerCase());
        return TextUtils.isEmpty(type) ? "image/jpeg" : type;
    }

    public static boolean isContent(String str) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        return str.startsWith("content://");
    }

    public static boolean isGif(String str) {
        return str != null && (str.equals("image/gif") || str.equals("image/GIF"));
    }

    public static boolean isGifForSuffix(String str) {
        return (str != null && str.startsWith(".gif")) || str.startsWith(".GIF");
    }

    public static boolean isHasImage(String str) {
        return str != null && str.startsWith("image");
    }

    public static boolean isHasVideo(String str) {
        return str != null && str.startsWith("video");
    }

    public static boolean isHttp(String str) {
        return (!TextUtils.isEmpty(str) && str.startsWith("http")) || str.startsWith("https");
    }
}
