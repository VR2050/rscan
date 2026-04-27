package com.RNFetchBlob;

/* JADX INFO: loaded from: classes.dex */
public class f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private long f5782a = 0;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f5783b = 0;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f5784c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f5785d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f5786e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private a f5787f;

    enum a {
        Upload,
        Download
    }

    f(boolean z3, int i3, int i4, a aVar) {
        this.f5784c = -1;
        this.f5785d = -1;
        this.f5786e = false;
        a aVar2 = a.Upload;
        this.f5786e = z3;
        this.f5785d = i3;
        this.f5787f = aVar;
        this.f5784c = i4;
    }

    public boolean a(float f3) {
        int i3 = this.f5784c;
        boolean z3 = false;
        boolean z4 = i3 <= 0 || f3 <= 0.0f || Math.floor((double) (f3 * ((float) i3))) > ((double) this.f5783b);
        if (System.currentTimeMillis() - this.f5782a > this.f5785d && this.f5786e && z4) {
            z3 = true;
        }
        if (z3) {
            this.f5783b++;
            this.f5782a = System.currentTimeMillis();
        }
        return z3;
    }
}
