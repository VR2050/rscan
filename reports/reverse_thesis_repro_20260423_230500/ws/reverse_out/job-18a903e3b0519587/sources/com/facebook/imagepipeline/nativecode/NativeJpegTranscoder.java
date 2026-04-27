package com.facebook.imagepipeline.nativecode;

import H0.h;
import N0.j;
import X.k;
import android.graphics.ColorSpace;
import java.io.InputStream;
import java.io.OutputStream;

/* JADX INFO: loaded from: classes.dex */
public class NativeJpegTranscoder implements V0.c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f6072a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f6073b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f6074c;

    public NativeJpegTranscoder(boolean z3, int i3, boolean z4, boolean z5) {
        this.f6072a = z3;
        this.f6073b = i3;
        this.f6074c = z4;
        if (z5) {
            g.a();
        }
    }

    public static void e(InputStream inputStream, OutputStream outputStream, int i3, int i4, int i5) {
        g.a();
        k.b(Boolean.valueOf(i4 >= 1));
        k.b(Boolean.valueOf(i4 <= 16));
        k.b(Boolean.valueOf(i5 >= 0));
        k.b(Boolean.valueOf(i5 <= 100));
        k.b(Boolean.valueOf(V0.e.j(i3)));
        k.c((i4 == 8 && i3 == 0) ? false : true, "no transformation requested");
        nativeTranscodeJpeg((InputStream) k.g(inputStream), (OutputStream) k.g(outputStream), i3, i4, i5);
    }

    public static void f(InputStream inputStream, OutputStream outputStream, int i3, int i4, int i5) {
        g.a();
        k.b(Boolean.valueOf(i4 >= 1));
        k.b(Boolean.valueOf(i4 <= 16));
        k.b(Boolean.valueOf(i5 >= 0));
        k.b(Boolean.valueOf(i5 <= 100));
        k.b(Boolean.valueOf(V0.e.i(i3)));
        k.c((i4 == 8 && i3 == 1) ? false : true, "no transformation requested");
        nativeTranscodeJpegWithExifOrientation((InputStream) k.g(inputStream), (OutputStream) k.g(outputStream), i3, i4, i5);
    }

    private static native void nativeTranscodeJpeg(InputStream inputStream, OutputStream outputStream, int i3, int i4, int i5);

    private static native void nativeTranscodeJpegWithExifOrientation(InputStream inputStream, OutputStream outputStream, int i3, int i4, int i5);

    @Override // V0.c
    public boolean a(j jVar, h hVar, H0.g gVar) {
        if (hVar == null) {
            hVar = h.c();
        }
        return V0.e.f(hVar, gVar, jVar, this.f6072a) < 8;
    }

    @Override // V0.c
    public String b() {
        return "NativeJpegTranscoder";
    }

    @Override // V0.c
    public V0.b c(j jVar, OutputStream outputStream, h hVar, H0.g gVar, C0.c cVar, Integer num, ColorSpace colorSpace) {
        if (num == null) {
            num = 85;
        }
        if (hVar == null) {
            hVar = h.c();
        }
        int iB = V0.a.b(hVar, gVar, jVar, this.f6073b);
        try {
            int iF = V0.e.f(hVar, gVar, jVar, this.f6072a);
            int iA = V0.e.a(iB);
            if (this.f6074c) {
                iF = iA;
            }
            InputStream inputStreamP = jVar.P();
            if (V0.e.f2813b.contains(Integer.valueOf(jVar.s0()))) {
                f((InputStream) k.h(inputStreamP, "Cannot transcode from null input stream!"), outputStream, V0.e.d(hVar, jVar), iF, num.intValue());
            } else {
                e((InputStream) k.h(inputStreamP, "Cannot transcode from null input stream!"), outputStream, V0.e.e(hVar, jVar), iF, num.intValue());
            }
            X.b.b(inputStreamP);
            return new V0.b(iB != 1 ? 0 : 1);
        } catch (Throwable th) {
            X.b.b(null);
            throw th;
        }
    }

    @Override // V0.c
    public boolean d(C0.c cVar) {
        return cVar == C0.b.f549b;
    }
}
