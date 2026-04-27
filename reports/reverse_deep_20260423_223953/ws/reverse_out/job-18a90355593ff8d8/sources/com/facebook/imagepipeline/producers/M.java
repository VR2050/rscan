package com.facebook.imagepipeline.producers;

import a0.InterfaceC0223i;
import java.io.FileInputStream;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class M extends L {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f6163c = new a(null);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(Executor executor, InterfaceC0223i interfaceC0223i) {
        super(executor, interfaceC0223i);
        t2.j.f(executor, "executor");
        t2.j.f(interfaceC0223i, "pooledByteBufferFactory");
    }

    @Override // com.facebook.imagepipeline.producers.L
    protected N0.j d(T0.b bVar) {
        t2.j.f(bVar, "imageRequest");
        return e(new FileInputStream(bVar.u().toString()), (int) bVar.u().length());
    }

    @Override // com.facebook.imagepipeline.producers.L
    protected String f() {
        return "LocalFileFetchProducer";
    }
}
