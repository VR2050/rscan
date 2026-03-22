package p458k;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: k.t */
/* loaded from: classes3.dex */
public final class C4483t implements InterfaceC4484u {
    @Override // p458k.InterfaceC4484u
    @NotNull
    /* renamed from: a */
    public List<InetAddress> mo5268a(@NotNull String hostname) {
        Intrinsics.checkParameterIsNotNull(hostname, "hostname");
        try {
            InetAddress[] allByName = InetAddress.getAllByName(hostname);
            Intrinsics.checkExpressionValueIsNotNull(allByName, "InetAddress.getAllByName(hostname)");
            return ArraysKt___ArraysKt.toList(allByName);
        } catch (NullPointerException e2) {
            UnknownHostException unknownHostException = new UnknownHostException(C1499a.m637w("Broken system behaviour for dns lookup of ", hostname));
            unknownHostException.initCause(e2);
            throw unknownHostException;
        }
    }
}
