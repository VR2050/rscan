package com.facebook.imagepipeline.producers;

import android.content.ContentResolver;
import android.graphics.Bitmap;
import android.media.ThumbnailUtils;
import android.os.CancellationSignal;
import android.util.Size;
import b0.AbstractC0311a;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class S implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f6166a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ContentResolver f6167b;

    class a extends m0 {

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ g0 f6168g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ e0 f6169h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ T0.b f6170i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        final /* synthetic */ CancellationSignal f6171j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(InterfaceC0369n interfaceC0369n, g0 g0Var, e0 e0Var, String str, g0 g0Var2, e0 e0Var2, T0.b bVar, CancellationSignal cancellationSignal) {
            super(interfaceC0369n, g0Var, e0Var, str);
            this.f6168g = g0Var2;
            this.f6169h = e0Var2;
            this.f6170i = bVar;
            this.f6171j = cancellationSignal;
        }

        @Override // com.facebook.imagepipeline.producers.m0, V.e
        protected void d() {
            super.d();
            this.f6171j.cancel();
        }

        @Override // com.facebook.imagepipeline.producers.m0, V.e
        protected void e(Exception exc) {
            super.e(exc);
            this.f6168g.e(this.f6169h, "LocalThumbnailBitmapSdk29Producer", false);
            this.f6169h.n0("local", "thumbnail_bitmap");
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // V.e
        /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
        public void b(AbstractC0311a abstractC0311a) {
            AbstractC0311a.D(abstractC0311a);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.m0
        /* JADX INFO: renamed from: k, reason: merged with bridge method [inline-methods] */
        public Map i(AbstractC0311a abstractC0311a) {
            return X.g.of("createdThumbnail", String.valueOf(abstractC0311a != null));
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // V.e
        /* JADX INFO: renamed from: l, reason: merged with bridge method [inline-methods] */
        public AbstractC0311a c() throws IOException {
            String strE;
            Size size = new Size(this.f6170i.n(), this.f6170i.m());
            try {
                strE = S.this.e(this.f6170i);
            } catch (IllegalArgumentException unused) {
                strE = null;
            }
            Bitmap bitmapCreateVideoThumbnail = strE != null ? Z.a.c(Z.a.b(strE)) ? ThumbnailUtils.createVideoThumbnail(new File(strE), size, this.f6171j) : ThumbnailUtils.createImageThumbnail(new File(strE), size, this.f6171j) : null;
            if (bitmapCreateVideoThumbnail == null) {
                bitmapCreateVideoThumbnail = S.this.f6167b.loadThumbnail(this.f6170i.v(), size, this.f6171j);
            }
            if (bitmapCreateVideoThumbnail == null) {
                return null;
            }
            N0.e eVarT = N0.e.T(bitmapCreateVideoThumbnail, F0.d.b(), N0.n.f1902d, 0);
            this.f6169h.A("image_format", "thumbnail");
            eVarT.r(this.f6169h.b());
            return AbstractC0311a.e0(eVarT);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.m0, V.e
        /* JADX INFO: renamed from: m, reason: merged with bridge method [inline-methods] */
        public void f(AbstractC0311a abstractC0311a) {
            super.f(abstractC0311a);
            this.f6168g.e(this.f6169h, "LocalThumbnailBitmapSdk29Producer", abstractC0311a != null);
            this.f6169h.n0("local", "thumbnail_bitmap");
        }
    }

    class b extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ m0 f6173a;

        b(m0 m0Var) {
            this.f6173a = m0Var;
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            this.f6173a.a();
        }
    }

    public S(Executor executor, ContentResolver contentResolver) {
        this.f6166a = executor;
        this.f6167b = contentResolver;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String e(T0.b bVar) {
        return f0.f.e(this.f6167b, bVar.v());
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        g0 g0VarP = e0Var.P();
        T0.b bVarW = e0Var.W();
        e0Var.n0("local", "thumbnail_bitmap");
        a aVar = new a(interfaceC0369n, g0VarP, e0Var, "LocalThumbnailBitmapSdk29Producer", g0VarP, e0Var, bVarW, new CancellationSignal());
        e0Var.Z(new b(aVar));
        this.f6166a.execute(aVar);
    }
}
