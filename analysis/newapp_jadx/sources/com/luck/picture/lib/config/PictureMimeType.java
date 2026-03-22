package com.luck.picture.lib.config;

import android.content.Context;
import android.text.TextUtils;
import com.luck.picture.lib.C3979R;
import java.io.File;

/* loaded from: classes2.dex */
public final class PictureMimeType {
    public static final String AVI_Q = "video/avi";
    public static final String CAMERA = "Camera";
    public static final String DCIM = "DCIM/Camera";
    public static final String JPEG = ".jpeg";
    public static final String JPEG_Q = "image/jpeg";
    private static final String MIME_TYPE_3GP = "video/3gp";
    public static final String MIME_TYPE_AUDIO = "audio/mpeg";
    private static final String MIME_TYPE_AVI = "video/avi";
    private static final String MIME_TYPE_BMP = "image/bmp";
    private static final String MIME_TYPE_GIF = "image/gif";
    public static final String MIME_TYPE_IMAGE = "image/jpeg";
    public static final String MIME_TYPE_JPEG = "image/jpeg";
    private static final String MIME_TYPE_JPG = "image/jpg";
    private static final String MIME_TYPE_MP4 = "video/mp4";
    private static final String MIME_TYPE_MPEG = "video/mpeg";
    private static final String MIME_TYPE_PNG = "image/png";
    private static final String MIME_TYPE_PREFIX_AUDIO = "audio";
    private static final String MIME_TYPE_PREFIX_IMAGE = "image";
    private static final String MIME_TYPE_PREFIX_VIDEO = "video";
    public static final String MIME_TYPE_VIDEO = "video/mp4";
    private static final String MIME_TYPE_WEBP = "image/webp";
    public static final String MP4 = ".mp4";
    public static final String MP4_Q = "video/mp4";
    public static final String PNG = ".png";
    public static final String PNG_Q = "image/png";

    public static String getImageMimeType(String str) {
        try {
            if (TextUtils.isEmpty(str)) {
                return "image/jpeg";
            }
            String name = new File(str).getName();
            int lastIndexOf = name.lastIndexOf(".");
            return "image/" + (lastIndexOf == -1 ? "jpeg" : name.substring(lastIndexOf + 1));
        } catch (Exception e2) {
            e2.printStackTrace();
            return "image/jpeg";
        }
    }

    public static String getLastImgSuffix(String str) {
        try {
            int lastIndexOf = str.lastIndexOf("/") + 1;
            if (lastIndexOf <= 0) {
                return PNG;
            }
            return "." + str.substring(lastIndexOf);
        } catch (Exception e2) {
            e2.printStackTrace();
            return PNG;
        }
    }

    public static int getMimeType(String str) {
        if (TextUtils.isEmpty(str)) {
            return 1;
        }
        if (str.startsWith("video")) {
            return 2;
        }
        return str.startsWith("audio") ? 3 : 1;
    }

    public static String getMimeType(int i2) {
        return i2 != 2 ? i2 != 3 ? "image/jpeg" : MIME_TYPE_AUDIO : "video/mp4";
    }

    public static boolean isContent(String str) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        return str.startsWith("content://");
    }

    public static boolean isGif(String str) {
        return str != null && (str.equals(MIME_TYPE_GIF) || str.equals("image/GIF"));
    }

    public static boolean isHasAudio(String str) {
        return str != null && str.startsWith("audio");
    }

    public static boolean isHasHttp(String str) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        return str.startsWith("http") || str.startsWith("https") || str.startsWith("/http") || str.startsWith("/https");
    }

    public static boolean isHasImage(String str) {
        return str != null && str.startsWith("image");
    }

    public static boolean isHasVideo(String str) {
        return str != null && str.startsWith("video");
    }

    public static boolean isJPEG(String str) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        return str.startsWith("image/jpeg") || str.startsWith("image/jpg");
    }

    public static boolean isJPG(String str) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        return str.startsWith("image/jpg");
    }

    public static boolean isMimeTypeSame(String str, String str2) {
        return getMimeType(str) == getMimeType(str2);
    }

    public static boolean isSuffixOfImage(String str) {
        return (!TextUtils.isEmpty(str) && str.endsWith(".PNG")) || str.endsWith(PNG) || str.endsWith(".jpeg") || str.endsWith(".gif") || str.endsWith(".GIF") || str.endsWith(".jpg") || str.endsWith(".webp") || str.endsWith(".WEBP") || str.endsWith(".JPEG") || str.endsWith(".bmp");
    }

    public static boolean isUrlHasVideo(String str) {
        return str.endsWith(".mp4");
    }

    public static String of3GP() {
        return MIME_TYPE_3GP;
    }

    public static String ofAVI() {
        return "video/avi";
    }

    public static int ofAll() {
        return 0;
    }

    @Deprecated
    public static int ofAudio() {
        return 3;
    }

    public static String ofBMP() {
        return MIME_TYPE_BMP;
    }

    public static String ofGIF() {
        return MIME_TYPE_GIF;
    }

    public static int ofImage() {
        return 1;
    }

    public static String ofJPEG() {
        return "image/jpeg";
    }

    public static String ofMP4() {
        return "video/mp4";
    }

    public static String ofMPEG() {
        return MIME_TYPE_MPEG;
    }

    public static String ofPNG() {
        return "image/png";
    }

    public static int ofVideo() {
        return 2;
    }

    public static String ofWEBP() {
        return MIME_TYPE_WEBP;
    }

    /* renamed from: s */
    public static String m4554s(Context context, String str) {
        Context applicationContext = context.getApplicationContext();
        return isHasVideo(str) ? applicationContext.getString(C3979R.string.picture_video_error) : isHasAudio(str) ? applicationContext.getString(C3979R.string.picture_audio_error) : applicationContext.getString(C3979R.string.picture_error);
    }
}
