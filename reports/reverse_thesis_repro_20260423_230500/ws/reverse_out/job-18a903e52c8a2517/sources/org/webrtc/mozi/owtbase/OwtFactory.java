package org.webrtc.mozi.owtbase;

import org.webrtc.mozi.McsConfig;
import org.webrtc.mozi.McsConfigHelper;

/* JADX INFO: loaded from: classes3.dex */
public class OwtFactory {
    private static boolean enableMultiInst = false;
    private McsConfig mcsConfig;
    private McsConfigHelper mcsConfigHelper;
    private long nativeFactory;

    private static native long nativeCreateOwtFactory();

    private static native void nativeEnableMultiInst(boolean z);

    private static native void nativeFreeFactory(long j);

    private static native long nativeGetMcsConfig(long j);

    public static void enableMultiInst(boolean enable) {
        if (enable != enableMultiInst) {
            enableMultiInst = enable;
            nativeEnableMultiInst(enable);
        }
    }

    public OwtFactory() {
        long jNativeCreateOwtFactory = nativeCreateOwtFactory();
        this.nativeFactory = jNativeCreateOwtFactory;
        long configPtr = nativeGetMcsConfig(jNativeCreateOwtFactory);
        this.mcsConfig = new McsConfig(configPtr);
        McsConfigHelper mcsConfigHelper = new McsConfigHelper(configPtr);
        this.mcsConfigHelper = mcsConfigHelper;
        mcsConfigHelper.setNativeOwtFactory(this.nativeFactory);
    }

    public long getNativeOwtFactory() {
        return this.nativeFactory;
    }

    public McsConfig getMcsConfig() {
        return this.mcsConfig;
    }

    public McsConfigHelper getMcsConfigHelper() {
        return this.mcsConfigHelper;
    }

    public void dispose() {
        nativeFreeFactory(this.nativeFactory);
        this.nativeFactory = 0L;
        this.mcsConfig = new McsConfig(0L);
        this.mcsConfigHelper = new McsConfigHelper(0L);
    }
}
