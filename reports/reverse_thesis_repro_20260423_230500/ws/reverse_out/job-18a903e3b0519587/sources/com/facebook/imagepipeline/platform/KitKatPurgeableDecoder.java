package com.facebook.imagepipeline.platform;

import Q0.t;
import X.k;
import a0.InterfaceC0222h;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import b0.AbstractC0311a;
import com.facebook.imagepipeline.nativecode.DalvikPurgeableDecoder;

/* JADX INFO: loaded from: classes.dex */
public class KitKatPurgeableDecoder extends DalvikPurgeableDecoder {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final t f6082c;

    public KitKatPurgeableDecoder(t tVar) {
    }

    private static void h(byte[] bArr, int i3) {
        bArr[i3] = -1;
        bArr[i3 + 1] = -39;
    }

    @Override // com.facebook.imagepipeline.nativecode.DalvikPurgeableDecoder
    protected Bitmap c(AbstractC0311a abstractC0311a, BitmapFactory.Options options) {
        InterfaceC0222h interfaceC0222h = (InterfaceC0222h) abstractC0311a.P();
        int size = interfaceC0222h.size();
        AbstractC0311a abstractC0311aA = this.f6082c.a(size);
        try {
            byte[] bArr = (byte[]) abstractC0311aA.P();
            interfaceC0222h.c(0, bArr, 0, size);
            return (Bitmap) k.h(BitmapFactory.decodeByteArray(bArr, 0, size, options), "BitmapFactory returned null");
        } finally {
            AbstractC0311a.D(abstractC0311aA);
        }
    }

    @Override // com.facebook.imagepipeline.nativecode.DalvikPurgeableDecoder
    protected Bitmap d(AbstractC0311a abstractC0311a, int i3, BitmapFactory.Options options) {
        byte[] bArr = DalvikPurgeableDecoder.e(abstractC0311a, i3) ? null : DalvikPurgeableDecoder.f6070b;
        InterfaceC0222h interfaceC0222h = (InterfaceC0222h) abstractC0311a.P();
        k.b(Boolean.valueOf(i3 <= interfaceC0222h.size()));
        int i4 = i3 + 2;
        AbstractC0311a abstractC0311aA = this.f6082c.a(i4);
        try {
            byte[] bArr2 = (byte[]) abstractC0311aA.P();
            interfaceC0222h.c(0, bArr2, 0, i3);
            if (bArr != null) {
                h(bArr2, i3);
                i3 = i4;
            }
            Bitmap bitmap = (Bitmap) k.h(BitmapFactory.decodeByteArray(bArr2, 0, i3, options), "BitmapFactory returned null");
            AbstractC0311a.D(abstractC0311aA);
            return bitmap;
        } catch (Throwable th) {
            AbstractC0311a.D(abstractC0311aA);
            throw th;
        }
    }
}
