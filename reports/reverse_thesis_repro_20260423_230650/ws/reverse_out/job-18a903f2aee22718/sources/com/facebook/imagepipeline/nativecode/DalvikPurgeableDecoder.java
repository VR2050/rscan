package com.facebook.imagepipeline.nativecode;

import H0.i;
import N0.j;
import Q0.C0204g;
import Q0.h;
import X.k;
import X.p;
import a0.InterfaceC0222h;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.ColorSpace;
import android.graphics.Rect;
import android.os.Build;
import b0.AbstractC0311a;
import java.util.Locale;

/* JADX INFO: loaded from: classes.dex */
public abstract class DalvikPurgeableDecoder implements R0.f {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected static final byte[] f6070b;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final C0204g f6071a = h.a();

    private static class OreoUtils {
        private OreoUtils() {
        }

        static void a(BitmapFactory.Options options, ColorSpace colorSpace) {
            if (colorSpace == null) {
                colorSpace = ColorSpace.get(ColorSpace.Named.SRGB);
            }
            options.inPreferredColorSpace = colorSpace;
        }
    }

    static {
        d.a();
        f6070b = new byte[]{-1, -39};
    }

    protected DalvikPurgeableDecoder() {
    }

    public static boolean e(AbstractC0311a abstractC0311a, int i3) {
        InterfaceC0222h interfaceC0222h = (InterfaceC0222h) abstractC0311a.P();
        return i3 >= 2 && interfaceC0222h.g(i3 + (-2)) == -1 && interfaceC0222h.g(i3 - 1) == -39;
    }

    public static BitmapFactory.Options f(int i3, Bitmap.Config config) {
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inDither = true;
        options.inPreferredConfig = config;
        options.inPurgeable = true;
        options.inInputShareable = true;
        options.inSampleSize = i3;
        options.inMutable = true;
        return options;
    }

    private static native void nativePinBitmap(Bitmap bitmap);

    @Override // R0.f
    public AbstractC0311a a(j jVar, Bitmap.Config config, Rect rect, int i3, ColorSpace colorSpace) {
        BitmapFactory.Options optionsF = f(jVar.Z(), config);
        if (Build.VERSION.SDK_INT >= 26) {
            OreoUtils.a(optionsF, colorSpace);
        }
        AbstractC0311a abstractC0311aV = jVar.v();
        k.g(abstractC0311aV);
        try {
            return g(d(abstractC0311aV, i3, optionsF));
        } finally {
            AbstractC0311a.D(abstractC0311aV);
        }
    }

    @Override // R0.f
    public AbstractC0311a b(j jVar, Bitmap.Config config, Rect rect, ColorSpace colorSpace) {
        BitmapFactory.Options optionsF = f(jVar.Z(), config);
        if (Build.VERSION.SDK_INT >= 26) {
            OreoUtils.a(optionsF, colorSpace);
        }
        AbstractC0311a abstractC0311aV = jVar.v();
        k.g(abstractC0311aV);
        try {
            return g(c(abstractC0311aV, optionsF));
        } finally {
            AbstractC0311a.D(abstractC0311aV);
        }
    }

    protected abstract Bitmap c(AbstractC0311a abstractC0311a, BitmapFactory.Options options);

    protected abstract Bitmap d(AbstractC0311a abstractC0311a, int i3, BitmapFactory.Options options);

    public AbstractC0311a g(Bitmap bitmap) {
        k.g(bitmap);
        try {
            nativePinBitmap(bitmap);
            if (this.f6071a.g(bitmap)) {
                return AbstractC0311a.n0(bitmap, this.f6071a.e());
            }
            int iJ = Y0.e.j(bitmap);
            bitmap.recycle();
            throw new i(String.format(Locale.US, "Attempted to pin a bitmap of size %d bytes. The current pool count is %d, the current pool size is %d bytes. The current pool max count is %d, the current pool max size is %d bytes.", Integer.valueOf(iJ), Integer.valueOf(this.f6071a.b()), Long.valueOf(this.f6071a.f()), Integer.valueOf(this.f6071a.c()), Integer.valueOf(this.f6071a.d())));
        } catch (Exception e3) {
            bitmap.recycle();
            throw p.a(e3);
        }
    }
}
