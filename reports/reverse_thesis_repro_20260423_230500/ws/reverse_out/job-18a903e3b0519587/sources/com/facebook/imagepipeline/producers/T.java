package com.facebook.imagepipeline.producers;

import android.content.ContentResolver;
import android.graphics.Bitmap;
import android.media.MediaMetadataRetriever;
import android.media.ThumbnailUtils;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import b0.AbstractC0311a;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class T implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f6175a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ContentResolver f6176b;

    class a extends m0 {

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ g0 f6177g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ e0 f6178h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ T0.b f6179i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(InterfaceC0369n interfaceC0369n, g0 g0Var, e0 e0Var, String str, g0 g0Var2, e0 e0Var2, T0.b bVar) {
            super(interfaceC0369n, g0Var, e0Var, str);
            this.f6177g = g0Var2;
            this.f6178h = e0Var2;
            this.f6179i = bVar;
        }

        @Override // com.facebook.imagepipeline.producers.m0, V.e
        protected void e(Exception exc) {
            super.e(exc);
            this.f6177g.e(this.f6178h, "VideoThumbnailProducer", false);
            this.f6178h.n0("local", "video");
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
        public AbstractC0311a c() throws Throwable {
            String strI;
            try {
                strI = T.this.i(this.f6179i);
            } catch (IllegalArgumentException unused) {
                strI = null;
            }
            Bitmap bitmapCreateVideoThumbnail = strI != null ? ThumbnailUtils.createVideoThumbnail(strI, T.g(this.f6179i)) : null;
            if (bitmapCreateVideoThumbnail == null) {
                bitmapCreateVideoThumbnail = T.h(T.this.f6176b, this.f6179i.v());
            }
            if (bitmapCreateVideoThumbnail == null) {
                return null;
            }
            N0.e eVarT = N0.e.T(bitmapCreateVideoThumbnail, F0.d.b(), N0.n.f1902d, 0);
            this.f6178h.A("image_format", "thumbnail");
            eVarT.r(this.f6178h.b());
            return AbstractC0311a.e0(eVarT);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.m0, V.e
        /* JADX INFO: renamed from: m, reason: merged with bridge method [inline-methods] */
        public void f(AbstractC0311a abstractC0311a) {
            super.f(abstractC0311a);
            this.f6177g.e(this.f6178h, "VideoThumbnailProducer", abstractC0311a != null);
            this.f6178h.n0("local", "video");
        }
    }

    class b extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ m0 f6181a;

        b(m0 m0Var) {
            this.f6181a = m0Var;
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            this.f6181a.a();
        }
    }

    public T(Executor executor, ContentResolver contentResolver) {
        this.f6175a = executor;
        this.f6176b = contentResolver;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static int g(T0.b bVar) {
        return (bVar.n() > 96 || bVar.m() > 96) ? 1 : 3;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Bitmap h(ContentResolver contentResolver, Uri uri) throws Throwable {
        MediaMetadataRetriever mediaMetadataRetriever;
        MediaMetadataRetriever mediaMetadataRetriever2 = null;
        try {
            ParcelFileDescriptor parcelFileDescriptorOpenFileDescriptor = contentResolver.openFileDescriptor(uri, "r");
            X.k.g(parcelFileDescriptorOpenFileDescriptor);
            mediaMetadataRetriever = new MediaMetadataRetriever();
            try {
                mediaMetadataRetriever.setDataSource(parcelFileDescriptorOpenFileDescriptor.getFileDescriptor());
                Bitmap frameAtTime = mediaMetadataRetriever.getFrameAtTime(-1L);
                try {
                    mediaMetadataRetriever.release();
                } catch (IOException unused) {
                }
                return frameAtTime;
            } catch (FileNotFoundException unused2) {
                if (mediaMetadataRetriever != null) {
                    try {
                        mediaMetadataRetriever.release();
                    } catch (IOException unused3) {
                    }
                }
                return null;
            } catch (Throwable th) {
                th = th;
                mediaMetadataRetriever2 = mediaMetadataRetriever;
                if (mediaMetadataRetriever2 != null) {
                    try {
                        mediaMetadataRetriever2.release();
                    } catch (IOException unused4) {
                    }
                }
                throw th;
            }
        } catch (FileNotFoundException unused5) {
            mediaMetadataRetriever = null;
        } catch (Throwable th2) {
            th = th2;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String i(T0.b bVar) {
        return f0.f.e(this.f6176b, bVar.v());
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        g0 g0VarP = e0Var.P();
        T0.b bVarW = e0Var.W();
        e0Var.n0("local", "video");
        a aVar = new a(interfaceC0369n, g0VarP, e0Var, "VideoThumbnailProducer", g0VarP, e0Var, bVarW);
        e0Var.Z(new b(aVar));
        this.f6175a.execute(aVar);
    }
}
