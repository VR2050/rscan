package p379c.p380a;

import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p379c.p380a.p381a.C2970s;

/* renamed from: c.a.j1 */
/* loaded from: classes2.dex */
public final class C3071j1 {

    /* renamed from: a */
    public static final C2970s f8417a = new C2970s("COMPLETING_ALREADY");

    /* renamed from: b */
    @JvmField
    @NotNull
    public static final C2970s f8418b = new C2970s("COMPLETING_WAITING_CHILDREN");

    /* renamed from: c */
    public static final C2970s f8419c = new C2970s("COMPLETING_RETRY");

    /* renamed from: d */
    public static final C2970s f8420d = new C2970s("TOO_LATE_TO_CANCEL");

    /* renamed from: e */
    public static final C2970s f8421e = new C2970s("SEALED");

    /* renamed from: f */
    public static final C3088p0 f8422f = new C3088p0(false);

    /* renamed from: g */
    public static final C3088p0 f8423g = new C3088p0(true);

    @Nullable
    /* renamed from: a */
    public static final Object m3618a(@Nullable Object obj) {
        InterfaceC3115y0 interfaceC3115y0;
        C3118z0 c3118z0 = (C3118z0) (!(obj instanceof C3118z0) ? null : obj);
        return (c3118z0 == null || (interfaceC3115y0 = c3118z0.f8477a) == null) ? obj : interfaceC3115y0;
    }
}
