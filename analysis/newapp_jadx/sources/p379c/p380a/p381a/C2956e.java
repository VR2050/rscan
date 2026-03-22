package p379c.p380a.p381a;

import kotlin.coroutines.CoroutineContext;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.InterfaceC3055e0;

/* renamed from: c.a.a.e */
/* loaded from: classes2.dex */
public final class C2956e implements InterfaceC3055e0 {

    /* renamed from: c */
    @NotNull
    public final CoroutineContext f8101c;

    public C2956e(@NotNull CoroutineContext coroutineContext) {
        this.f8101c = coroutineContext;
    }

    @Override // p379c.p380a.InterfaceC3055e0
    @NotNull
    public CoroutineContext getCoroutineContext() {
        return this.f8101c;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("CoroutineScope(coroutineContext=");
        m586H.append(this.f8101c);
        m586H.append(')');
        return m586H.toString();
    }
}
