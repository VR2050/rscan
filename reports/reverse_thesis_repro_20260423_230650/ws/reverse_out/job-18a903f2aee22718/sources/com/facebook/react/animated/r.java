package com.facebook.react.animated;

import com.facebook.react.bridge.ReadableMap;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class r extends e {

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    public static final a f6585u = new a(null);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private long f6586e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f6587f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private double f6588g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private double f6589h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private double f6590i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private double f6591j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f6592k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final b f6593l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private double f6594m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private double f6595n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private double f6596o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private double f6597p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private double f6598q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private int f6599r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private int f6600s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private double f6601t;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    private static final class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private double f6602a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private double f6603b;

        public b(double d3, double d4) {
            this.f6602a = d3;
            this.f6603b = d4;
        }

        public final double a() {
            return this.f6602a;
        }

        public final double b() {
            return this.f6603b;
        }

        public final void c(double d3) {
            this.f6602a = d3;
        }

        public final void d(double d3) {
            this.f6603b = d3;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof b)) {
                return false;
            }
            b bVar = (b) obj;
            return Double.compare(this.f6602a, bVar.f6602a) == 0 && Double.compare(this.f6603b, bVar.f6603b) == 0;
        }

        public int hashCode() {
            return (Double.hashCode(this.f6602a) * 31) + Double.hashCode(this.f6603b);
        }

        public String toString() {
            return "PhysicsState(position=" + this.f6602a + ", velocity=" + this.f6603b + ")";
        }

        public /* synthetic */ b(double d3, double d4, int i3, DefaultConstructorMarker defaultConstructorMarker) {
            this((i3 & 1) != 0 ? 0.0d : d3, (i3 & 2) != 0 ? 0.0d : d4);
        }
    }

    public r(ReadableMap readableMap) {
        t2.j.f(readableMap, "config");
        b bVar = new b(0.0d, 0.0d, 3, null);
        this.f6593l = bVar;
        bVar.d(readableMap.getDouble("initialVelocity"));
        a(readableMap);
    }

    private final void c(double d3) {
        double dSin;
        double dSin2;
        if (e()) {
            return;
        }
        this.f6598q += d3 <= 0.064d ? d3 : 0.064d;
        double d4 = this.f6589h;
        double d5 = this.f6590i;
        double d6 = this.f6588g;
        double d7 = -this.f6591j;
        double dSqrt = d4 / (((double) 2) * Math.sqrt(d6 * d5));
        double dSqrt2 = Math.sqrt(d6 / d5);
        double dSqrt3 = Math.sqrt(1.0d - (dSqrt * dSqrt)) * dSqrt2;
        double d8 = this.f6595n - this.f6594m;
        double d9 = this.f6598q;
        if (dSqrt < 1.0d) {
            double dExp = Math.exp((-dSqrt) * dSqrt2 * d9);
            double d10 = dSqrt * dSqrt2;
            double d11 = d7 + (d10 * d8);
            double d12 = d9 * dSqrt3;
            dSin2 = this.f6595n - ((((d11 / dSqrt3) * Math.sin(d12)) + (Math.cos(d12) * d8)) * dExp);
            dSin = ((d10 * dExp) * (((Math.sin(d12) * d11) / dSqrt3) + (Math.cos(d12) * d8))) - (((Math.cos(d12) * d11) - ((dSqrt3 * d8) * Math.sin(d12))) * dExp);
        } else {
            double dExp2 = Math.exp((-dSqrt2) * d9);
            double d13 = this.f6595n - (((((dSqrt2 * d8) + d7) * d9) + d8) * dExp2);
            dSin = dExp2 * ((d7 * ((d9 * dSqrt2) - ((double) 1))) + (d9 * d8 * dSqrt2 * dSqrt2));
            dSin2 = d13;
        }
        this.f6593l.c(dSin2);
        this.f6593l.d(dSin);
        if (e() || (this.f6592k && f())) {
            if (this.f6588g > 0.0d) {
                double d14 = this.f6595n;
                this.f6594m = d14;
                this.f6593l.c(d14);
            } else {
                double dA = this.f6593l.a();
                this.f6595n = dA;
                this.f6594m = dA;
            }
            this.f6593l.d(0.0d);
        }
    }

    private final double d(b bVar) {
        return Math.abs(this.f6595n - bVar.a());
    }

    private final boolean e() {
        return Math.abs(this.f6593l.b()) <= this.f6596o && (d(this.f6593l) <= this.f6597p || this.f6588g == 0.0d);
    }

    private final boolean f() {
        return this.f6588g > 0.0d && ((this.f6594m < this.f6595n && this.f6593l.a() > this.f6595n) || (this.f6594m > this.f6595n && this.f6593l.a() < this.f6595n));
    }

    @Override // com.facebook.react.animated.e
    public void a(ReadableMap readableMap) {
        t2.j.f(readableMap, "config");
        this.f6588g = readableMap.getDouble("stiffness");
        this.f6589h = readableMap.getDouble("damping");
        this.f6590i = readableMap.getDouble("mass");
        this.f6591j = this.f6593l.b();
        this.f6595n = readableMap.getDouble("toValue");
        this.f6596o = readableMap.getDouble("restSpeedThreshold");
        this.f6597p = readableMap.getDouble("restDisplacementThreshold");
        this.f6592k = readableMap.getBoolean("overshootClamping");
        int i3 = readableMap.hasKey("iterations") ? readableMap.getInt("iterations") : 1;
        this.f6599r = i3;
        this.f6508a = i3 == 0;
        this.f6600s = 0;
        this.f6598q = 0.0d;
        this.f6587f = false;
    }

    @Override // com.facebook.react.animated.e
    public void b(long j3) {
        w wVar = this.f6509b;
        if (wVar == null) {
            throw new IllegalArgumentException("Animated value should not be null");
        }
        long j4 = j3 / ((long) 1000000);
        if (!this.f6587f) {
            if (this.f6600s == 0) {
                this.f6601t = wVar.f6621f;
                this.f6600s = 1;
            }
            this.f6593l.c(wVar.f6621f);
            this.f6594m = this.f6593l.a();
            this.f6586e = j4;
            this.f6598q = 0.0d;
            this.f6587f = true;
        }
        c((j4 - this.f6586e) / 1000.0d);
        this.f6586e = j4;
        wVar.f6621f = this.f6593l.a();
        if (e()) {
            int i3 = this.f6599r;
            if (i3 != -1 && this.f6600s >= i3) {
                this.f6508a = true;
                return;
            }
            this.f6587f = false;
            wVar.f6621f = this.f6601t;
            this.f6600s++;
        }
    }
}
