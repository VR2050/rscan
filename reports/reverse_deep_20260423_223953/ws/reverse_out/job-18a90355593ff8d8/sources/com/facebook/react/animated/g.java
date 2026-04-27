package com.facebook.react.animated;

import com.facebook.react.bridge.ReadableMap;

/* JADX INFO: loaded from: classes.dex */
public final class g extends e {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private double f6521e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private double f6522f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private long f6523g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private double f6524h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private double f6525i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f6526j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f6527k;

    public g(ReadableMap readableMap) {
        t2.j.f(readableMap, "config");
        this.f6523g = -1L;
        this.f6526j = 1;
        this.f6527k = 1;
        a(readableMap);
    }

    @Override // com.facebook.react.animated.e
    public void a(ReadableMap readableMap) {
        t2.j.f(readableMap, "config");
        this.f6521e = readableMap.getDouble("velocity");
        this.f6522f = readableMap.getDouble("deceleration");
        this.f6523g = -1L;
        this.f6524h = 0.0d;
        this.f6525i = 0.0d;
        int i3 = readableMap.hasKey("iterations") ? readableMap.getInt("iterations") : 1;
        this.f6526j = i3;
        this.f6527k = 1;
        this.f6508a = i3 == 0;
    }

    @Override // com.facebook.react.animated.e
    public void b(long j3) {
        w wVar = this.f6509b;
        if (wVar == null) {
            throw new IllegalArgumentException("Animated value should not be null");
        }
        long j4 = j3 / ((long) 1000000);
        if (this.f6523g == -1) {
            this.f6523g = j4 - ((long) 16);
            double d3 = this.f6524h;
            if (d3 == this.f6525i) {
                this.f6524h = wVar.f6621f;
            } else {
                wVar.f6621f = d3;
            }
            this.f6525i = wVar.f6621f;
        }
        double d4 = this.f6524h;
        double d5 = this.f6521e;
        double d6 = 1;
        double d7 = this.f6522f;
        double dExp = d4 + ((d5 / (d6 - d7)) * (d6 - Math.exp((-(d6 - d7)) * (j4 - this.f6523g))));
        if (Math.abs(this.f6525i - dExp) < 0.1d) {
            int i3 = this.f6526j;
            if (i3 != -1 && this.f6527k >= i3) {
                this.f6508a = true;
                return;
            } else {
                this.f6523g = -1L;
                this.f6527k++;
            }
        }
        this.f6525i = dExp;
        wVar.f6621f = dExp;
    }
}
