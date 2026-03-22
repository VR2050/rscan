package com.angcyo.tablayout;

import com.angcyo.tablayout.DslTabLayout;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(m5310d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\n¢\u0006\u0002\b\u0003"}, m5311d2 = {"<anonymous>", "", "Lcom/angcyo/tablayout/DslSelectorConfig;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.w */
/* loaded from: classes.dex */
public final class C1526w extends Lambda implements Function1<DslSelectorConfig, Unit> {

    /* renamed from: c */
    public final /* synthetic */ DslTabLayout f1653c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1526w(DslTabLayout dslTabLayout) {
        super(1);
        this.f1653c = dslTabLayout;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(DslSelectorConfig dslSelectorConfig) {
        DslSelectorConfig install = dslSelectorConfig;
        Intrinsics.checkNotNullParameter(install, "$this$install");
        C1522s c1522s = new C1522s(this.f1653c);
        Objects.requireNonNull(install);
        Intrinsics.checkNotNullParameter(c1522s, "<set-?>");
        install.f1587a = c1522s;
        C1523t c1523t = new C1523t(this.f1653c);
        Intrinsics.checkNotNullParameter(c1523t, "<set-?>");
        install.f1590d = c1523t;
        C1524u c1524u = new C1524u(this.f1653c);
        Intrinsics.checkNotNullParameter(c1524u, "<set-?>");
        install.f1588b = c1524u;
        C1525v c1525v = new C1525v(this.f1653c);
        Intrinsics.checkNotNullParameter(c1525v, "<set-?>");
        install.f1589c = c1525v;
        return Unit.INSTANCE;
    }
}
