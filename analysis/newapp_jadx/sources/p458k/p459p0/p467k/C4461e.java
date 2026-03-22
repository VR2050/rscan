package p458k.p459p0.p467k;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.EnumC4377e0;

/* renamed from: k.p0.k.e */
/* loaded from: classes3.dex */
public class C4461e extends C4463g {

    /* renamed from: d */
    public static final boolean f11981d;

    /* renamed from: e */
    public static final C4461e f11982e = null;

    static {
        Integer integer = Integer.getInteger("java.specification.version");
        f11981d = (integer != null ? integer.intValue() : 8) >= 9;
    }

    @Override // p458k.p459p0.p467k.C4463g
    /* renamed from: e */
    public void mo5233e(@NotNull SSLSocket sslSocket, @Nullable String str, @NotNull List<EnumC4377e0> protocols) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        SSLParameters sslParameters = sslSocket.getSSLParameters();
        Intrinsics.checkParameterIsNotNull(protocols, "protocols");
        ArrayList arrayList = new ArrayList();
        Iterator<T> it = protocols.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Object next = it.next();
            if (((EnumC4377e0) next) != EnumC4377e0.HTTP_1_0) {
                arrayList.add(next);
            }
        }
        ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(((EnumC4377e0) it2.next()).f11430l);
        }
        Intrinsics.checkExpressionValueIsNotNull(sslParameters, "sslParameters");
        Object[] array = arrayList2.toArray(new String[0]);
        if (array == null) {
            throw new TypeCastException("null cannot be cast to non-null type kotlin.Array<T>");
        }
        sslParameters.setApplicationProtocols((String[]) array);
        sslSocket.setSSLParameters(sslParameters);
    }

    @Override // p458k.p459p0.p467k.C4463g
    @Nullable
    /* renamed from: h */
    public String mo5234h(@NotNull SSLSocket sslSocket) {
        Intrinsics.checkParameterIsNotNull(sslSocket, "sslSocket");
        String applicationProtocol = sslSocket.getApplicationProtocol();
        if (applicationProtocol == null || Intrinsics.areEqual(applicationProtocol, "")) {
            return null;
        }
        return applicationProtocol;
    }
}
