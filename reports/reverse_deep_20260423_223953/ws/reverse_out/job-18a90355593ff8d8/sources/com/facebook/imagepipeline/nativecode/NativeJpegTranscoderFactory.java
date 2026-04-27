package com.facebook.imagepipeline.nativecode;

/* JADX INFO: loaded from: classes.dex */
public class NativeJpegTranscoderFactory implements V0.d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f6075a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f6076b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f6077c;

    public NativeJpegTranscoderFactory(int i3, boolean z3, boolean z4) {
        this.f6075a = i3;
        this.f6076b = z3;
        this.f6077c = z4;
    }

    @Override // V0.d
    public V0.c createImageTranscoder(C0.c cVar, boolean z3) {
        if (cVar != C0.b.f549b) {
            return null;
        }
        return new NativeJpegTranscoder(z3, this.f6075a, this.f6076b, this.f6077c);
    }
}
