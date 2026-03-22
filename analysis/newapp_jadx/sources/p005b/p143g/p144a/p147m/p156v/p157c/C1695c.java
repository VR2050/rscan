package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p147m.C1581m;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1571c;
import p005b.p143g.p144a.p147m.InterfaceC1585q;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;

/* renamed from: b.g.a.m.v.c.c */
/* loaded from: classes.dex */
public class C1695c implements InterfaceC1585q<Bitmap> {

    /* renamed from: a */
    public static final C1581m<Integer> f2473a = C1581m.m825a("com.bumptech.glide.load.resource.bitmap.BitmapEncoder.CompressionQuality", 90);

    /* renamed from: b */
    public static final C1581m<Bitmap.CompressFormat> f2474b = new C1581m<>("com.bumptech.glide.load.resource.bitmap.BitmapEncoder.CompressionFormat", null, C1581m.f1990a);

    /* renamed from: c */
    @Nullable
    public final InterfaceC1612b f2475c;

    public C1695c(@NonNull InterfaceC1612b interfaceC1612b) {
        this.f2475c = interfaceC1612b;
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x005f, code lost:
    
        if (r6 == null) goto L29;
     */
    @Override // p005b.p143g.p144a.p147m.InterfaceC1572d
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean mo822a(@androidx.annotation.NonNull java.lang.Object r9, @androidx.annotation.NonNull java.io.File r10, @androidx.annotation.NonNull p005b.p143g.p144a.p147m.C1582n r11) {
        /*
            r8 = this;
            b.g.a.m.t.w r9 = (p005b.p143g.p144a.p147m.p150t.InterfaceC1655w) r9
            java.lang.String r0 = "BitmapEncoder"
            java.lang.Object r9 = r9.get()
            android.graphics.Bitmap r9 = (android.graphics.Bitmap) r9
            b.g.a.m.m<android.graphics.Bitmap$CompressFormat> r1 = p005b.p143g.p144a.p147m.p156v.p157c.C1695c.f2474b
            java.lang.Object r1 = r11.m827a(r1)
            android.graphics.Bitmap$CompressFormat r1 = (android.graphics.Bitmap.CompressFormat) r1
            if (r1 == 0) goto L15
            goto L20
        L15:
            boolean r1 = r9.hasAlpha()
            if (r1 == 0) goto L1e
            android.graphics.Bitmap$CompressFormat r1 = android.graphics.Bitmap.CompressFormat.PNG
            goto L20
        L1e:
            android.graphics.Bitmap$CompressFormat r1 = android.graphics.Bitmap.CompressFormat.JPEG
        L20:
            r9.getWidth()
            r9.getHeight()
            int r2 = p005b.p143g.p144a.p170s.C1803e.f2759b     // Catch: java.lang.Throwable -> Lb5
            long r2 = android.os.SystemClock.elapsedRealtimeNanos()     // Catch: java.lang.Throwable -> Lb5
            b.g.a.m.m<java.lang.Integer> r4 = p005b.p143g.p144a.p147m.p156v.p157c.C1695c.f2473a     // Catch: java.lang.Throwable -> Lb5
            java.lang.Object r4 = r11.m827a(r4)     // Catch: java.lang.Throwable -> Lb5
            java.lang.Integer r4 = (java.lang.Integer) r4     // Catch: java.lang.Throwable -> Lb5
            int r4 = r4.intValue()     // Catch: java.lang.Throwable -> Lb5
            r5 = 0
            r6 = 0
            java.io.FileOutputStream r7 = new java.io.FileOutputStream     // Catch: java.lang.Throwable -> L59 java.io.IOException -> L5b
            r7.<init>(r10)     // Catch: java.lang.Throwable -> L59 java.io.IOException -> L5b
            b.g.a.m.t.c0.b r10 = r8.f2475c     // Catch: java.lang.Throwable -> L55 java.io.IOException -> L57
            if (r10 == 0) goto L4c
            b.g.a.m.s.c r10 = new b.g.a.m.s.c     // Catch: java.lang.Throwable -> L55 java.io.IOException -> L57
            b.g.a.m.t.c0.b r6 = r8.f2475c     // Catch: java.lang.Throwable -> L55 java.io.IOException -> L57
            r10.<init>(r7, r6)     // Catch: java.lang.Throwable -> L55 java.io.IOException -> L57
            r6 = r10
            goto L4d
        L4c:
            r6 = r7
        L4d:
            r9.compress(r1, r4, r6)     // Catch: java.lang.Throwable -> L59 java.io.IOException -> L5b
            r6.close()     // Catch: java.lang.Throwable -> L59 java.io.IOException -> L5b
            r5 = 1
            goto L61
        L55:
            r9 = move-exception
            goto Laf
        L57:
            r6 = r7
            goto L5b
        L59:
            r9 = move-exception
            goto Lae
        L5b:
            r10 = 3
            android.util.Log.isLoggable(r0, r10)     // Catch: java.lang.Throwable -> L59
            if (r6 == 0) goto L64
        L61:
            r6.close()     // Catch: java.io.IOException -> L64 java.lang.Throwable -> Lb5
        L64:
            r10 = 2
            boolean r10 = android.util.Log.isLoggable(r0, r10)     // Catch: java.lang.Throwable -> Lb5
            if (r10 == 0) goto Lad
            java.lang.StringBuilder r10 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> Lb5
            r10.<init>()     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r0 = "Compressed with type: "
            r10.append(r0)     // Catch: java.lang.Throwable -> Lb5
            r10.append(r1)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r0 = " of size "
            r10.append(r0)     // Catch: java.lang.Throwable -> Lb5
            int r0 = p005b.p143g.p144a.p170s.C1807i.m1147d(r9)     // Catch: java.lang.Throwable -> Lb5
            r10.append(r0)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r0 = " in "
            r10.append(r0)     // Catch: java.lang.Throwable -> Lb5
            double r0 = p005b.p143g.p144a.p170s.C1803e.m1138a(r2)     // Catch: java.lang.Throwable -> Lb5
            r10.append(r0)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r0 = ", options format: "
            r10.append(r0)     // Catch: java.lang.Throwable -> Lb5
            b.g.a.m.m<android.graphics.Bitmap$CompressFormat> r0 = p005b.p143g.p144a.p147m.p156v.p157c.C1695c.f2474b     // Catch: java.lang.Throwable -> Lb5
            java.lang.Object r11 = r11.m827a(r0)     // Catch: java.lang.Throwable -> Lb5
            r10.append(r11)     // Catch: java.lang.Throwable -> Lb5
            java.lang.String r11 = ", hasAlpha: "
            r10.append(r11)     // Catch: java.lang.Throwable -> Lb5
            boolean r9 = r9.hasAlpha()     // Catch: java.lang.Throwable -> Lb5
            r10.append(r9)     // Catch: java.lang.Throwable -> Lb5
            r10.toString()     // Catch: java.lang.Throwable -> Lb5
        Lad:
            return r5
        Lae:
            r7 = r6
        Laf:
            if (r7 == 0) goto Lb4
            r7.close()     // Catch: java.io.IOException -> Lb4 java.lang.Throwable -> Lb5
        Lb4:
            throw r9     // Catch: java.lang.Throwable -> Lb5
        Lb5:
            r9 = move-exception
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p156v.p157c.C1695c.mo822a(java.lang.Object, java.io.File, b.g.a.m.n):boolean");
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1585q
    @NonNull
    /* renamed from: b */
    public EnumC1571c mo831b(@NonNull C1582n c1582n) {
        return EnumC1571c.TRANSFORMED;
    }
}
