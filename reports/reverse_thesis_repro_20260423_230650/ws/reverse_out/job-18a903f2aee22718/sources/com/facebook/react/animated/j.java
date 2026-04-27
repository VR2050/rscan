package com.facebook.react.animated;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import f1.C0527a;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class j extends e {

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final a f6535l = new a(null);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private long f6536e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private double[] f6537f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private double f6538g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private double f6539h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f6540i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f6541j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f6542k;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public j(ReadableMap readableMap) {
        t2.j.f(readableMap, "config");
        this.f6536e = -1L;
        this.f6537f = new double[0];
        this.f6540i = 1;
        this.f6541j = 1;
        a(readableMap);
    }

    @Override // com.facebook.react.animated.e
    public void a(ReadableMap readableMap) {
        int size;
        t2.j.f(readableMap, "config");
        ReadableArray array = readableMap.getArray("frames");
        if (array != null && this.f6537f.length != (size = array.size())) {
            double[] dArr = new double[size];
            for (int i3 = 0; i3 < size; i3++) {
                dArr[i3] = array.getDouble(i3);
            }
            this.f6537f = dArr;
        }
        this.f6538g = (readableMap.hasKey("toValue") && readableMap.getType("toValue") == ReadableType.Number) ? readableMap.getDouble("toValue") : 0.0d;
        int i4 = (readableMap.hasKey("iterations") && readableMap.getType("iterations") == ReadableType.Number) ? readableMap.getInt("iterations") : 1;
        this.f6540i = i4;
        this.f6541j = 1;
        this.f6508a = i4 == 0;
        this.f6536e = -1L;
    }

    @Override // com.facebook.react.animated.e
    public void b(long j3) {
        double d3;
        w wVar = this.f6509b;
        if (wVar == null) {
            throw new IllegalArgumentException("Animated value should not be null");
        }
        if (this.f6536e < 0) {
            this.f6536e = j3;
            if (this.f6541j == 1) {
                this.f6539h = wVar.f6621f;
            }
        }
        int iRound = (int) Math.round(((j3 - this.f6536e) / ((long) 1000000)) / 16.666666666666668d);
        if (iRound < 0) {
            String str = "Calculated frame index should never be lower than 0. Called with frameTimeNanos " + j3 + " and mStartFrameTimeNanos " + this.f6536e;
            if (C0527a.f9198b) {
                throw new IllegalStateException(str.toString());
            }
            if (this.f6542k < 100) {
                Y.a.I("ReactNative", str);
                this.f6542k++;
                return;
            }
            return;
        }
        if (this.f6508a) {
            return;
        }
        double[] dArr = this.f6537f;
        if (iRound >= dArr.length - 1) {
            int i3 = this.f6540i;
            if (i3 == -1 || this.f6541j < i3) {
                double d4 = this.f6539h;
                d3 = d4 + (dArr[dArr.length - 1] * (this.f6538g - d4));
                this.f6536e = -1L;
                this.f6541j++;
            } else {
                d3 = this.f6538g;
                this.f6508a = true;
            }
        } else {
            double d5 = this.f6539h;
            d3 = d5 + (dArr[iRound] * (this.f6538g - d5));
        }
        wVar.f6621f = d3;
    }
}
