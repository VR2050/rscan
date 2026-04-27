package com.ding.rtc;

/* JADX INFO: loaded from: classes.dex */
class PrivateRtcModelVideoBeautyFaceParams {
    String lutPath;
    String resourcePath;
    boolean enableSkinBuffing = false;
    float skinBuffingFactor = 0.2f;
    float skinSharpenFactor = 0.0f;
    float skinResolutionFactor = 0.0f;
    boolean enableFaceBuffing = false;
    float pouchFactor = 0.0f;
    float nasolabialFoldsFactor = 0.0f;
    float brightEyesFactor = 0.0f;
    float whitenTeethFactor = 0.0f;
    boolean enableSkinWhitening = false;
    float skinWhitingFactor = 0.2f;
    boolean enableLut = false;
    float lutFactor = 0.5f;

    PrivateRtcModelVideoBeautyFaceParams() {
    }

    public String getResourcePath() {
        return this.resourcePath;
    }

    public boolean isEnableSkinBuffing() {
        return this.enableSkinBuffing;
    }

    public float getSkinBuffingFactor() {
        return this.skinBuffingFactor;
    }

    public float getSkinSharpenFactor() {
        return this.skinSharpenFactor;
    }

    public float getSkinResolutionFactor() {
        return this.skinResolutionFactor;
    }

    public boolean isEnableFaceBuffing() {
        return this.enableFaceBuffing;
    }

    public float getPouchFactor() {
        return this.pouchFactor;
    }

    public float getNasolabialFoldsFactor() {
        return this.nasolabialFoldsFactor;
    }

    public float getBrightEyesFactor() {
        return this.brightEyesFactor;
    }

    public float getWhitenTeethFactor() {
        return this.whitenTeethFactor;
    }

    public boolean isEnableSkinWhitening() {
        return this.enableSkinWhitening;
    }

    public float getSkinWhitingFactor() {
        return this.skinWhitingFactor;
    }

    public boolean isEnableLut() {
        return this.enableLut;
    }

    public String getLutPath() {
        return this.lutPath;
    }

    public float getLutFactor() {
        return this.lutFactor;
    }
}
