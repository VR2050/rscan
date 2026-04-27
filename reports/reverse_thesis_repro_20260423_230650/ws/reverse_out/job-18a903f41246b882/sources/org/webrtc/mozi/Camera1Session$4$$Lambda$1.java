package org.webrtc.mozi;

import org.webrtc.mozi.Camera1Session;

/* JADX INFO: loaded from: classes3.dex */
final /* synthetic */ class Camera1Session$4$$Lambda$1 implements Runnable {
    private final Camera1Session.AnonymousClass4 arg$1;
    private final byte[] arg$2;

    private Camera1Session$4$$Lambda$1(Camera1Session.AnonymousClass4 anonymousClass4, byte[] bArr) {
        this.arg$1 = anonymousClass4;
        this.arg$2 = bArr;
    }

    public static Runnable lambdaFactory$(Camera1Session.AnonymousClass4 anonymousClass4, byte[] bArr) {
        return new Camera1Session$4$$Lambda$1(anonymousClass4, bArr);
    }

    @Override // java.lang.Runnable
    public void run() {
        Camera1Session.AnonymousClass4.lambda$onPreviewFrame$2(this.arg$1, this.arg$2);
    }
}
