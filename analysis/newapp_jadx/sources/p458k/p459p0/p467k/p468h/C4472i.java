package p458k.p459p0.p467k.p468h;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: k.p0.k.h.i */
/* loaded from: classes3.dex */
public final class C4472i extends C4467d {

    /* renamed from: f */
    public static final a f12006f = new a(null);

    /* renamed from: k.p0.k.h.i$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4472i(@NotNull Class<? super SSLSocket> sslSocketClass, @NotNull Class<? super SSLSocketFactory> sslSocketFactoryClass, @NotNull Class<?> paramClass) {
        super(sslSocketClass);
        Intrinsics.checkParameterIsNotNull(sslSocketClass, "sslSocketClass");
        Intrinsics.checkParameterIsNotNull(sslSocketFactoryClass, "sslSocketFactoryClass");
        Intrinsics.checkParameterIsNotNull(paramClass, "paramClass");
    }
}
