package com.shuyu.gsyvideoplayer.utils;

/* loaded from: classes2.dex */
public class GSYVideoType {
    public static final int GLSURFACE = 2;
    private static boolean MEDIA_CODEC_FLAG = false;
    public static final int SCREEN_MATCH_FULL = -4;
    public static final int SCREEN_TYPE_16_9 = 1;
    public static final int SCREEN_TYPE_18_9 = 6;
    public static final int SCREEN_TYPE_4_3 = 2;
    public static final int SCREEN_TYPE_CUSTOM = -5;
    public static final int SCREEN_TYPE_DEFAULT = 0;
    public static final int SCREEN_TYPE_FULL = 4;
    public static final int SUFRACE = 1;
    public static final int TEXTURE = 0;
    private static int TYPE = 0;
    private static int sRenderType = 0;
    private static float sScreenScaleRatio = 0.0f;
    private static boolean sTextureMediaPlay = false;

    public static void disableMediaCodec() {
        MEDIA_CODEC_FLAG = false;
    }

    public static void disableMediaCodecTexture() {
        sTextureMediaPlay = false;
    }

    public static void enableMediaCodec() {
        MEDIA_CODEC_FLAG = true;
    }

    public static void enableMediaCodecTexture() {
        sTextureMediaPlay = true;
    }

    public static int getRenderType() {
        return sRenderType;
    }

    public static float getScreenScaleRatio() {
        return sScreenScaleRatio;
    }

    public static int getShowType() {
        return TYPE;
    }

    public static boolean isMediaCodec() {
        return MEDIA_CODEC_FLAG;
    }

    public static boolean isMediaCodecTexture() {
        return sTextureMediaPlay;
    }

    public static void setRenderType(int i2) {
        sRenderType = i2;
    }

    public static void setScreenScaleRatio(float f2) {
        sScreenScaleRatio = f2;
    }

    public static void setShowType(int i2) {
        TYPE = i2;
    }
}
