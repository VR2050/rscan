package net.butterflytv.rtmp_client;

import java.io.IOException;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes3.dex */
public class RtmpClient {

    /* renamed from: a */
    public long f12974a = 0;

    /* renamed from: net.butterflytv.rtmp_client.RtmpClient$a */
    public static class C5032a extends IOException {
        public C5032a(int i2) {
            super(C1499a.m626l("RTMP error: ", i2));
        }
    }

    static {
        System.loadLibrary("rtmp-jni");
    }

    public final native long nativeAlloc();

    public final native void nativeClose(long j2);

    public final native int nativeOpen(String str, boolean z, long j2, int i2, int i3);

    public final native int nativeRead(byte[] bArr, int i2, int i3, long j2);
}
