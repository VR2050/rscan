package p458k.p459p0.p465i;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p474l.C4744f;
import p474l.InterfaceC4746h;

/* renamed from: k.p0.i.r */
/* loaded from: classes3.dex */
public final class C4452r implements InterfaceC4453s {
    @Override // p458k.p459p0.p465i.InterfaceC4453s
    /* renamed from: a */
    public boolean mo5217a(int i2, @NotNull List<C4437c> requestHeaders) {
        Intrinsics.checkParameterIsNotNull(requestHeaders, "requestHeaders");
        return true;
    }

    @Override // p458k.p459p0.p465i.InterfaceC4453s
    /* renamed from: b */
    public boolean mo5218b(int i2, @NotNull List<C4437c> responseHeaders, boolean z) {
        Intrinsics.checkParameterIsNotNull(responseHeaders, "responseHeaders");
        return true;
    }

    @Override // p458k.p459p0.p465i.InterfaceC4453s
    /* renamed from: c */
    public void mo5219c(int i2, @NotNull EnumC4436b errorCode) {
        Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
    }

    @Override // p458k.p459p0.p465i.InterfaceC4453s
    /* renamed from: d */
    public boolean mo5220d(int i2, @NotNull InterfaceC4746h source, int i3, boolean z) {
        Intrinsics.checkParameterIsNotNull(source, "source");
        ((C4744f) source).skip(i3);
        return true;
    }
}
