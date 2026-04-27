package com.facebook.imagepipeline.producers;

import a0.InterfaceC0222h;
import a0.InterfaceC0223i;
import android.content.ContentResolver;
import android.content.res.AssetFileDescriptor;
import android.media.ExifInterface;
import android.net.Uri;
import android.util.Pair;
import b0.AbstractC0311a;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class LocalExifThumbnailProducer implements u0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f6155a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0223i f6156b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ContentResolver f6157c;

    private class Api24Utils {
        ExifInterface a(FileDescriptor fileDescriptor) {
            return new ExifInterface(fileDescriptor);
        }

        private Api24Utils() {
        }
    }

    class a extends m0 {

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ T0.b f6159g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(InterfaceC0369n interfaceC0369n, g0 g0Var, e0 e0Var, String str, T0.b bVar) {
            super(interfaceC0369n, g0Var, e0Var, str);
            this.f6159g = bVar;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // V.e
        /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
        public void b(N0.j jVar) {
            N0.j.p(jVar);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.m0
        /* JADX INFO: renamed from: k, reason: merged with bridge method [inline-methods] */
        public Map i(N0.j jVar) {
            return X.g.of("createdThumbnail", Boolean.toString(jVar != null));
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // V.e
        /* JADX INFO: renamed from: l, reason: merged with bridge method [inline-methods] */
        public N0.j c() {
            ExifInterface exifInterfaceG = LocalExifThumbnailProducer.this.g(this.f6159g.v());
            if (exifInterfaceG == null || !exifInterfaceG.hasThumbnail()) {
                return null;
            }
            return LocalExifThumbnailProducer.this.e(LocalExifThumbnailProducer.this.f6156b.c((byte[]) X.k.g(exifInterfaceG.getThumbnail())), exifInterfaceG);
        }
    }

    class b extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ m0 f6161a;

        b(m0 m0Var) {
            this.f6161a = m0Var;
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            this.f6161a.a();
        }
    }

    public LocalExifThumbnailProducer(Executor executor, InterfaceC0223i interfaceC0223i, ContentResolver contentResolver) {
        this.f6155a = executor;
        this.f6156b = interfaceC0223i;
        this.f6157c = contentResolver;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public N0.j e(InterfaceC0222h interfaceC0222h, ExifInterface exifInterface) {
        Pair pairD = Y0.e.d(new a0.j(interfaceC0222h));
        int iH = h(exifInterface);
        int iIntValue = pairD != null ? ((Integer) pairD.first).intValue() : -1;
        int iIntValue2 = pairD != null ? ((Integer) pairD.second).intValue() : -1;
        AbstractC0311a abstractC0311aE0 = AbstractC0311a.e0(interfaceC0222h);
        try {
            N0.j jVar = new N0.j(abstractC0311aE0);
            AbstractC0311a.D(abstractC0311aE0);
            jVar.E0(C0.b.f549b);
            jVar.F0(iH);
            jVar.I0(iIntValue);
            jVar.D0(iIntValue2);
            return jVar;
        } catch (Throwable th) {
            AbstractC0311a.D(abstractC0311aE0);
            throw th;
        }
    }

    private int h(ExifInterface exifInterface) {
        return Y0.h.a(Integer.parseInt((String) X.k.g(exifInterface.getAttribute("Orientation"))));
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        g0 g0VarP = e0Var.P();
        T0.b bVarW = e0Var.W();
        e0Var.n0("local", "exif");
        a aVar = new a(interfaceC0369n, g0VarP, e0Var, "LocalExifThumbnailProducer", bVarW);
        e0Var.Z(new b(aVar));
        this.f6155a.execute(aVar);
    }

    @Override // com.facebook.imagepipeline.producers.u0
    public boolean b(H0.g gVar) {
        return v0.b(512, 512, gVar);
    }

    boolean f(String str) {
        if (str == null) {
            return false;
        }
        File file = new File(str);
        return file.exists() && file.canRead();
    }

    ExifInterface g(Uri uri) {
        String strE = f0.f.e(this.f6157c, uri);
        if (strE == null) {
            return null;
        }
        try {
        } catch (IOException unused) {
        } catch (StackOverflowError unused2) {
            Y.a.i(LocalExifThumbnailProducer.class, "StackOverflowError in ExifInterface constructor");
        }
        if (f(strE)) {
            return new ExifInterface(strE);
        }
        AssetFileDescriptor assetFileDescriptorA = f0.f.a(this.f6157c, uri);
        if (assetFileDescriptorA != null) {
            ExifInterface exifInterfaceA = new Api24Utils().a(assetFileDescriptorA.getFileDescriptor());
            assetFileDescriptorA.close();
            return exifInterfaceA;
        }
        return null;
    }
}
