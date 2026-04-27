package com.facebook.react.uimanager;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: com.facebook.react.uimanager.z0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0483z0 {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f7768e = new a(null);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final int[] f7769f = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f7770a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float[] f7771b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f7772c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f7773d;

    /* JADX INFO: renamed from: com.facebook.react.uimanager.z0$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final float[] b() {
            return new float[]{Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN, Float.NaN};
        }

        private a() {
        }
    }

    public C0483z0(float f3, float[] fArr) {
        t2.j.f(fArr, "spacing");
        this.f7770a = f3;
        this.f7771b = fArr;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x000c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final float a(int r5) {
        /*
            r4 = this;
            r0 = 4
            if (r5 == r0) goto Lc
            r0 = 5
            if (r5 == r0) goto Lc
            switch(r5) {
                case 9: goto Lc;
                case 10: goto Lc;
                case 11: goto Lc;
                default: goto L9;
            }
        L9:
            float r0 = r4.f7770a
            goto Le
        Lc:
            r0 = 2143289344(0x7fc00000, float:NaN)
        Le:
            int r1 = r4.f7772c
            if (r1 != 0) goto L13
            return r0
        L13:
            int[] r2 = com.facebook.react.uimanager.C0483z0.f7769f
            r3 = r2[r5]
            r3 = r3 & r1
            if (r3 == 0) goto L1f
            float[] r0 = r4.f7771b
            r5 = r0[r5]
            return r5
        L1f:
            boolean r3 = r4.f7773d
            if (r3 == 0) goto L42
            r3 = 1
            if (r5 == r3) goto L2b
            r3 = 3
            if (r5 == r3) goto L2b
            r5 = 6
            goto L2c
        L2b:
            r5 = 7
        L2c:
            r3 = r2[r5]
            r3 = r3 & r1
            if (r3 == 0) goto L36
            float[] r0 = r4.f7771b
            r5 = r0[r5]
            return r5
        L36:
            r5 = 8
            r2 = r2[r5]
            r1 = r1 & r2
            if (r1 == 0) goto L42
            float[] r0 = r4.f7771b
            r5 = r0[r5]
            return r5
        L42:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.uimanager.C0483z0.a(int):float");
    }

    public final float b(int i3) {
        return this.f7771b[i3];
    }

    public final boolean c(int i3, float f3) {
        if (L.a(this.f7771b[i3], f3)) {
            return false;
        }
        this.f7771b[i3] = f3;
        int i4 = com.facebook.yoga.g.a(f3) ? (~f7769f[i3]) & this.f7772c : f7769f[i3] | this.f7772c;
        this.f7772c = i4;
        int[] iArr = f7769f;
        this.f7773d = ((iArr[8] & i4) == 0 && (iArr[7] & i4) == 0 && (iArr[6] & i4) == 0 && (i4 & iArr[9]) == 0) ? false : true;
        return true;
    }

    public C0483z0() {
        this(0.0f, f7768e.b());
    }

    public C0483z0(float f3) {
        this(f3, f7768e.b());
    }
}
