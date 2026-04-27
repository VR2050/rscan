package com.facebook.react.uimanager;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class Y {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final Y f7555a = new Y();

    public static class a {

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private static final C0114a f7556f = new C0114a(null);

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public double[] f7557a = new double[4];

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public double[] f7558b = new double[3];

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public double[] f7559c = new double[3];

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public double[] f7560d = new double[3];

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public double[] f7561e = new double[3];

        /* JADX INFO: renamed from: com.facebook.react.uimanager.Y$a$a, reason: collision with other inner class name */
        private static final class C0114a {
            public /* synthetic */ C0114a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            /* JADX INFO: Access modifiers changed from: private */
            public final void b(double[] dArr) {
                int length = dArr.length;
                for (int i3 = 0; i3 < length; i3++) {
                    dArr[i3] = 0.0d;
                }
            }

            private C0114a() {
            }
        }

        public final void a() {
            C0114a c0114a = f7556f;
            c0114a.b(this.f7557a);
            c0114a.b(this.f7558b);
            c0114a.b(this.f7559c);
            c0114a.b(this.f7560d);
            c0114a.b(this.f7561e);
        }
    }

    private Y() {
    }

    public static final void a(double[] dArr, double d3) {
        t2.j.f(dArr, "m");
        dArr[11] = ((double) (-1)) / d3;
    }

    public static final void b(double[] dArr, double d3) {
        t2.j.f(dArr, "m");
        dArr[5] = Math.cos(d3);
        dArr[6] = Math.sin(d3);
        dArr[9] = -Math.sin(d3);
        dArr[10] = Math.cos(d3);
    }

    public static final void c(double[] dArr, double d3) {
        t2.j.f(dArr, "m");
        dArr[0] = Math.cos(d3);
        dArr[2] = -Math.sin(d3);
        dArr[8] = Math.sin(d3);
        dArr[10] = Math.cos(d3);
    }

    public static final void d(double[] dArr, double d3) {
        t2.j.f(dArr, "m");
        dArr[0] = Math.cos(d3);
        dArr[1] = Math.sin(d3);
        dArr[4] = -Math.sin(d3);
        dArr[5] = Math.cos(d3);
    }

    public static final void e(double[] dArr, double d3) {
        t2.j.f(dArr, "m");
        dArr[0] = d3;
    }

    public static final void f(double[] dArr, double d3) {
        t2.j.f(dArr, "m");
        dArr[5] = d3;
    }

    public static final void g(double[] dArr, double d3) {
        t2.j.f(dArr, "m");
        dArr[4] = Math.tan(d3);
    }

    public static final void h(double[] dArr, double d3) {
        t2.j.f(dArr, "m");
        dArr[1] = Math.tan(d3);
    }

    public static final void i(double[] dArr, double d3, double d4) {
        t2.j.f(dArr, "m");
        dArr[12] = d3;
        dArr[13] = d4;
    }

    public static final void j(double[] dArr, double d3, double d4, double d5) {
        t2.j.f(dArr, "m");
        dArr[12] = d3;
        dArr[13] = d4;
        dArr[14] = d5;
    }

    public static final void k(double[] dArr, a aVar) {
        t2.j.f(dArr, "transformMatrix");
        t2.j.f(aVar, "ctx");
        Z0.a.a(dArr.length == 16);
        double[] dArr2 = aVar.f7557a;
        double[] dArr3 = aVar.f7558b;
        double[] dArr4 = aVar.f7559c;
        double[] dArr5 = aVar.f7560d;
        double[] dArr6 = aVar.f7561e;
        if (f7555a.o(dArr[15])) {
            return;
        }
        double[][] dArr7 = new double[4][];
        for (int i3 = 0; i3 < 4; i3++) {
            dArr7[i3] = new double[4];
        }
        double[] dArr8 = new double[16];
        for (int i4 = 0; i4 < 4; i4++) {
            for (int i5 = 0; i5 < 4; i5++) {
                int i6 = (i4 * 4) + i5;
                double d3 = dArr[i6] / dArr[15];
                dArr7[i4][i5] = d3;
                if (i5 == 3) {
                    d3 = 0.0d;
                }
                dArr8[i6] = d3;
            }
        }
        dArr8[15] = 1.0d;
        Y y3 = f7555a;
        if (y3.o(m(dArr8))) {
            return;
        }
        if (y3.o(dArr7[0][3]) && y3.o(dArr7[1][3]) && y3.o(dArr7[2][3])) {
            dArr2[2] = 0.0d;
            dArr2[1] = 0.0d;
            dArr2[0] = 0.0d;
            dArr2[3] = 1.0d;
        } else {
            q(new double[]{dArr7[0][3], dArr7[1][3], dArr7[2][3], dArr7[3][3]}, t(n(dArr8)), dArr2);
        }
        for (int i7 = 0; i7 < 3; i7++) {
            dArr5[i7] = dArr7[3][i7];
        }
        double[][] dArr9 = new double[3][];
        for (int i8 = 0; i8 < 3; i8++) {
            dArr9[i8] = new double[3];
        }
        for (int i9 = 0; i9 < 3; i9++) {
            double[] dArr10 = dArr9[i9];
            double[] dArr11 = dArr7[i9];
            dArr10[0] = dArr11[0];
            dArr10[1] = dArr11[1];
            dArr10[2] = dArr11[2];
        }
        double dX = x(dArr9[0]);
        dArr3[0] = dX;
        double[] dArrY = y(dArr9[0], dX);
        dArr9[0] = dArrY;
        double dW = w(dArrY, dArr9[1]);
        dArr4[0] = dW;
        double[] dArrU = u(dArr9[1], dArr9[0], 1.0d, -dW);
        dArr9[1] = dArrU;
        double dX2 = x(dArrU);
        dArr3[1] = dX2;
        dArr9[1] = y(dArr9[1], dX2);
        dArr4[0] = dArr4[0] / dArr3[1];
        double dW2 = w(dArr9[0], dArr9[2]);
        dArr4[1] = dW2;
        double[] dArrU2 = u(dArr9[2], dArr9[0], 1.0d, -dW2);
        dArr9[2] = dArrU2;
        double dW3 = w(dArr9[1], dArrU2);
        dArr4[2] = dW3;
        double[] dArrU3 = u(dArr9[2], dArr9[1], 1.0d, -dW3);
        dArr9[2] = dArrU3;
        double dX3 = x(dArrU3);
        dArr3[2] = dX3;
        double[] dArrY2 = y(dArr9[2], dX3);
        dArr9[2] = dArrY2;
        double d4 = dArr4[1];
        double d5 = dArr3[2];
        dArr4[1] = d4 / d5;
        dArr4[2] = dArr4[2] / d5;
        if (w(dArr9[0], v(dArr9[1], dArrY2)) < 0.0d) {
            for (int i10 = 0; i10 < 3; i10++) {
                dArr3[i10] = dArr3[i10] * (-1.0d);
                double[] dArr12 = dArr9[i10];
                dArr12[0] = dArr12[0] * (-1.0d);
                dArr12[1] = dArr12[1] * (-1.0d);
                dArr12[2] = dArr12[2] * (-1.0d);
            }
        }
        double[] dArr13 = dArr9[2];
        dArr6[0] = s((-Math.atan2(dArr13[1], dArr13[2])) * 57.29577951308232d);
        double[] dArr14 = dArr9[2];
        double d6 = -dArr14[0];
        double d7 = dArr14[1];
        double d8 = dArr14[2];
        dArr6[1] = s((-Math.atan2(d6, Math.sqrt((d7 * d7) + (d8 * d8)))) * 57.29577951308232d);
        dArr6[2] = s((-Math.atan2(dArr9[1][0], dArr9[0][0])) * 57.29577951308232d);
    }

    public static final double l(double d3) {
        return (d3 * 3.141592653589793d) / ((double) 180);
    }

    public static final double m(double[] dArr) {
        t2.j.f(dArr, "matrix");
        double d3 = dArr[0];
        double d4 = dArr[1];
        double d5 = dArr[2];
        double d6 = dArr[3];
        double d7 = dArr[4];
        double d8 = dArr[5];
        double d9 = dArr[6];
        double d10 = dArr[7];
        double d11 = dArr[8];
        double d12 = dArr[9];
        double d13 = dArr[10];
        double d14 = dArr[11];
        double d15 = dArr[12];
        double d16 = dArr[13];
        double d17 = dArr[14];
        double d18 = dArr[15];
        double d19 = d6 * d9;
        double d20 = d5 * d10;
        double d21 = d6 * d8;
        double d22 = d4 * d10;
        double d23 = d5 * d8;
        double d24 = d4 * d9;
        double d25 = d6 * d7;
        double d26 = d10 * d3;
        double d27 = d5 * d7;
        double d28 = d9 * d3;
        double d29 = d4 * d7;
        double d30 = d3 * d8;
        return ((((((((((((((((((((((((d19 * d12) * d15) - ((d20 * d12) * d15)) - ((d21 * d13) * d15)) + ((d22 * d13) * d15)) + ((d23 * d14) * d15)) - ((d24 * d14) * d15)) - ((d19 * d11) * d16)) + ((d20 * d11) * d16)) + ((d25 * d13) * d16)) - ((d26 * d13) * d16)) - ((d27 * d14) * d16)) + ((d28 * d14) * d16)) + ((d21 * d11) * d17)) - ((d22 * d11) * d17)) - ((d25 * d12) * d17)) + ((d26 * d12) * d17)) + ((d29 * d14) * d17)) - ((d14 * d30) * d17)) - ((d23 * d11) * d18)) + ((d24 * d11) * d18)) + ((d27 * d12) * d18)) - ((d28 * d12) * d18)) - ((d29 * d13) * d18)) + (d30 * d13 * d18);
    }

    public static final double[] n(double[] dArr) {
        t2.j.f(dArr, "matrix");
        double dM = m(dArr);
        if (f7555a.o(dM)) {
            return dArr;
        }
        double d3 = dArr[0];
        double d4 = dArr[1];
        double d5 = dArr[2];
        double d6 = dArr[3];
        double d7 = dArr[4];
        double d8 = dArr[5];
        double d9 = dArr[6];
        double d10 = dArr[7];
        double d11 = dArr[8];
        double d12 = dArr[9];
        double d13 = dArr[10];
        double d14 = dArr[11];
        double d15 = dArr[12];
        double d16 = dArr[13];
        double d17 = dArr[14];
        double d18 = dArr[15];
        double d19 = d9 * d14;
        double d20 = d10 * d13;
        double d21 = d10 * d12;
        double d22 = d8 * d14;
        double d23 = d9 * d12;
        double d24 = d8 * d13;
        double d25 = d6 * d13;
        double d26 = d5 * d14;
        double d27 = d6 * d12;
        double d28 = d4 * d14;
        double d29 = d5 * d12;
        double d30 = d4 * d13;
        double d31 = d5 * d10;
        double d32 = d6 * d9;
        double d33 = d6 * d8;
        double d34 = d4 * d10;
        double d35 = d5 * d8;
        double d36 = d4 * d9;
        double d37 = (d20 * d15) - (d19 * d15);
        double d38 = d10 * d11;
        double d39 = d7 * d14;
        double d40 = d9 * d11;
        double d41 = d7 * d13;
        double d42 = (d26 * d15) - (d25 * d15);
        double d43 = d6 * d11;
        double d44 = d3 * d14;
        double d45 = d5 * d11;
        double d46 = d3 * d13;
        double d47 = d6 * d7;
        double d48 = d10 * d3;
        double d49 = d5 * d7;
        double d50 = d9 * d3;
        double d51 = (((d22 * d15) - (d21 * d15)) + (d38 * d16)) - (d39 * d16);
        double d52 = d8 * d11;
        double d53 = d7 * d12;
        double d54 = (((d27 * d15) - (d28 * d15)) - (d43 * d16)) + (d44 * d16);
        double d55 = d4 * d11;
        double d56 = d3 * d12;
        double d57 = d4 * d7;
        double d58 = d3 * d8;
        return new double[]{((((((d19 * d16) - (d20 * d16)) + (d21 * d17)) - (d22 * d17)) - (d23 * d18)) + (d24 * d18)) / dM, ((((((d25 * d16) - (d26 * d16)) - (d27 * d17)) + (d28 * d17)) + (d29 * d18)) - (d30 * d18)) / dM, ((((((d31 * d16) - (d32 * d16)) + (d33 * d17)) - (d34 * d17)) - (d35 * d18)) + (d36 * d18)) / dM, ((((((d32 * d12) - (d31 * d12)) - (d33 * d13)) + (d34 * d13)) + (d35 * d14)) - (d36 * d14)) / dM, ((((d37 - (d38 * d17)) + (d39 * d17)) + (d40 * d18)) - (d41 * d18)) / dM, ((((d42 + (d43 * d17)) - (d44 * d17)) - (d45 * d18)) + (d46 * d18)) / dM, ((((((d32 * d15) - (d31 * d15)) - (d47 * d17)) + (d48 * d17)) + (d49 * d18)) - (d50 * d18)) / dM, ((((((d31 * d11) - (d32 * d11)) + (d47 * d13)) - (d48 * d13)) - (d49 * d14)) + (d50 * d14)) / dM, ((d51 - (d52 * d18)) + (d53 * d18)) / dM, ((d54 + (d55 * d18)) - (d56 * d18)) / dM, ((((((d34 * d15) - (d33 * d15)) + (d47 * d16)) - (d48 * d16)) - (d57 * d18)) + (d18 * d58)) / dM, ((((((d33 * d11) - (d34 * d11)) - (d47 * d12)) + (d48 * d12)) + (d57 * d14)) - (d14 * d58)) / dM, ((((((d23 * d15) - (d24 * d15)) - (d40 * d16)) + (d41 * d16)) + (d52 * d17)) - (d53 * d17)) / dM, ((((((d30 * d15) - (d29 * d15)) + (d45 * d16)) - (d46 * d16)) - (d55 * d17)) + (d56 * d17)) / dM, ((((((d35 * d15) - (d15 * d36)) - (d49 * d16)) + (d16 * d50)) + (d57 * d17)) - (d17 * d58)) / dM, ((((((d36 * d11) - (d35 * d11)) + (d49 * d12)) - (d50 * d12)) - (d57 * d13)) + (d58 * d13)) / dM};
    }

    private final boolean o(double d3) {
        return !Double.isNaN(d3) && Math.abs(d3) < 1.0E-5d;
    }

    public static final void p(double[] dArr, double[] dArr2, double[] dArr3) {
        t2.j.f(dArr, "out");
        t2.j.f(dArr2, "a");
        t2.j.f(dArr3, "b");
        double d3 = dArr2[0];
        double d4 = dArr2[1];
        double d5 = dArr2[2];
        double d6 = dArr2[3];
        double d7 = dArr2[4];
        double d8 = dArr2[5];
        double d9 = dArr2[6];
        double d10 = dArr2[7];
        double d11 = dArr2[8];
        double d12 = dArr2[9];
        double d13 = dArr2[10];
        double d14 = dArr2[11];
        double d15 = dArr2[12];
        double d16 = dArr2[13];
        double d17 = dArr2[14];
        double d18 = dArr2[15];
        double d19 = dArr3[0];
        double d20 = dArr3[1];
        double d21 = dArr3[2];
        double d22 = dArr3[3];
        dArr[0] = (d19 * d3) + (d20 * d7) + (d21 * d11) + (d22 * d15);
        dArr[1] = (d19 * d4) + (d20 * d8) + (d21 * d12) + (d22 * d16);
        dArr[2] = (d19 * d5) + (d20 * d9) + (d21 * d13) + (d22 * d17);
        dArr[3] = (d19 * d6) + (d20 * d10) + (d21 * d14) + (d22 * d18);
        double d23 = dArr3[4];
        double d24 = dArr3[5];
        double d25 = dArr3[6];
        double d26 = dArr3[7];
        dArr[4] = (d23 * d3) + (d24 * d7) + (d25 * d11) + (d26 * d15);
        dArr[5] = (d23 * d4) + (d24 * d8) + (d25 * d12) + (d26 * d16);
        dArr[6] = (d23 * d5) + (d24 * d9) + (d25 * d13) + (d26 * d17);
        dArr[7] = (d23 * d6) + (d24 * d10) + (d25 * d14) + (d26 * d18);
        double d27 = dArr3[8];
        double d28 = dArr3[9];
        double d29 = dArr3[10];
        double d30 = dArr3[11];
        dArr[8] = (d27 * d3) + (d28 * d7) + (d29 * d11) + (d30 * d15);
        dArr[9] = (d27 * d4) + (d28 * d8) + (d29 * d12) + (d30 * d16);
        dArr[10] = (d27 * d5) + (d28 * d9) + (d29 * d13) + (d30 * d17);
        dArr[11] = (d27 * d6) + (d28 * d10) + (d29 * d14) + (d30 * d18);
        double d31 = dArr3[12];
        double d32 = dArr3[13];
        double d33 = dArr3[14];
        double d34 = dArr3[15];
        dArr[12] = (d3 * d31) + (d7 * d32) + (d11 * d33) + (d15 * d34);
        dArr[13] = (d4 * d31) + (d8 * d32) + (d12 * d33) + (d16 * d34);
        dArr[14] = (d5 * d31) + (d9 * d32) + (d13 * d33) + (d17 * d34);
        dArr[15] = (d31 * d6) + (d32 * d10) + (d33 * d14) + (d34 * d18);
    }

    public static final void q(double[] dArr, double[] dArr2, double[] dArr3) {
        t2.j.f(dArr, "v");
        t2.j.f(dArr2, "m");
        t2.j.f(dArr3, "result");
        double d3 = dArr[0];
        double d4 = dArr[1];
        double d5 = dArr[2];
        double d6 = dArr[3];
        dArr3[0] = (dArr2[0] * d3) + (dArr2[4] * d4) + (dArr2[8] * d5) + (dArr2[12] * d6);
        dArr3[1] = (dArr2[1] * d3) + (dArr2[5] * d4) + (dArr2[9] * d5) + (dArr2[13] * d6);
        dArr3[2] = (dArr2[2] * d3) + (dArr2[6] * d4) + (dArr2[10] * d5) + (dArr2[14] * d6);
        dArr3[3] = (d3 * dArr2[3]) + (d4 * dArr2[7]) + (d5 * dArr2[11]) + (d6 * dArr2[15]);
    }

    public static final void r(double[] dArr) {
        t2.j.f(dArr, "matrix");
        dArr[14] = 0.0d;
        dArr[13] = 0.0d;
        dArr[12] = 0.0d;
        dArr[11] = 0.0d;
        dArr[9] = 0.0d;
        dArr[8] = 0.0d;
        dArr[7] = 0.0d;
        dArr[6] = 0.0d;
        dArr[4] = 0.0d;
        dArr[3] = 0.0d;
        dArr[2] = 0.0d;
        dArr[1] = 0.0d;
        dArr[15] = 1.0d;
        dArr[10] = 1.0d;
        dArr[5] = 1.0d;
        dArr[0] = 1.0d;
    }

    public static final double s(double d3) {
        return Math.round(d3 * 1000.0d) * 0.001d;
    }

    public static final double[] t(double[] dArr) {
        t2.j.f(dArr, "m");
        return new double[]{dArr[0], dArr[4], dArr[8], dArr[12], dArr[1], dArr[5], dArr[9], dArr[13], dArr[2], dArr[6], dArr[10], dArr[14], dArr[3], dArr[7], dArr[11], dArr[15]};
    }

    public static final double[] u(double[] dArr, double[] dArr2, double d3, double d4) {
        t2.j.f(dArr, "a");
        t2.j.f(dArr2, "b");
        return new double[]{(dArr[0] * d3) + (dArr2[0] * d4), (dArr[1] * d3) + (dArr2[1] * d4), (d3 * dArr[2]) + (d4 * dArr2[2])};
    }

    public static final double[] v(double[] dArr, double[] dArr2) {
        t2.j.f(dArr, "a");
        t2.j.f(dArr2, "b");
        double d3 = dArr[1];
        double d4 = dArr2[2];
        double d5 = dArr[2];
        double d6 = dArr2[1];
        double d7 = dArr2[0];
        double d8 = dArr[0];
        return new double[]{(d3 * d4) - (d5 * d6), (d5 * d7) - (d4 * d8), (d8 * d6) - (d3 * d7)};
    }

    public static final double w(double[] dArr, double[] dArr2) {
        t2.j.f(dArr, "a");
        t2.j.f(dArr2, "b");
        return (dArr[0] * dArr2[0]) + (dArr[1] * dArr2[1]) + (dArr[2] * dArr2[2]);
    }

    public static final double x(double[] dArr) {
        t2.j.f(dArr, "a");
        double d3 = dArr[0];
        double d4 = dArr[1];
        double d5 = (d3 * d3) + (d4 * d4);
        double d6 = dArr[2];
        return Math.sqrt(d5 + (d6 * d6));
    }

    public static final double[] y(double[] dArr, double d3) {
        t2.j.f(dArr, "vector");
        double d4 = 1;
        if (f7555a.o(d3)) {
            d3 = x(dArr);
        }
        double d5 = d4 / d3;
        return new double[]{dArr[0] * d5, dArr[1] * d5, dArr[2] * d5};
    }
}
