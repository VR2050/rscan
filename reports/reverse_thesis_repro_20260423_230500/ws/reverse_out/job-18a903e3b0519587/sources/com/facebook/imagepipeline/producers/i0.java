package com.facebook.imagepipeline.producers;

import a0.InterfaceC0223i;
import android.content.ContentResolver;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class i0 extends L {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final a f6270d = new a(null);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final ContentResolver f6271c;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i0(Executor executor, InterfaceC0223i interfaceC0223i, ContentResolver contentResolver) {
        super(executor, interfaceC0223i);
        t2.j.f(executor, "executor");
        t2.j.f(interfaceC0223i, "pooledByteBufferFactory");
        t2.j.f(contentResolver, "contentResolver");
        this.f6271c = contentResolver;
    }

    @Override // com.facebook.imagepipeline.producers.L
    protected N0.j d(T0.b bVar) throws FileNotFoundException {
        t2.j.f(bVar, "imageRequest");
        InputStream inputStreamOpenInputStream = this.f6271c.openInputStream(bVar.v());
        if (inputStreamOpenInputStream == null) {
            throw new IllegalStateException("ContentResolver returned null InputStream");
        }
        N0.j jVarE = e(inputStreamOpenInputStream, -1);
        t2.j.e(jVarE, "getEncodedImage(...)");
        return jVarE;
    }

    @Override // com.facebook.imagepipeline.producers.L
    protected String f() {
        return "QualifiedResourceFetchProducer";
    }
}
