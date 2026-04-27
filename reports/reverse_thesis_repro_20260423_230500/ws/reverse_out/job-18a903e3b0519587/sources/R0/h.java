package R0;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final boolean f2631a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final boolean f2632b;

    public h(boolean z3, boolean z4) {
        this.f2631a = z3;
        this.f2632b = z4;
    }

    public final boolean a() {
        return this.f2631a;
    }

    public final boolean b() {
        return this.f2632b;
    }

    public /* synthetic */ h(boolean z3, boolean z4, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? false : z3, (i3 & 2) != 0 ? false : z4);
    }
}
