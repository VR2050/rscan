package com.drake.statelayout;

import android.view.View;
import com.drake.statelayout.StateLayout;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(m5310d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\n¢\u0006\u0002\b\u0003"}, m5311d2 = {"<anonymous>", "", "Landroid/view/View;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.i.b.d */
/* loaded from: classes.dex */
public final class C1871d extends Lambda implements Function1<View, Unit> {

    /* renamed from: c */
    public final /* synthetic */ StateLayout f2881c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1871d(StateLayout stateLayout) {
        super(1);
        this.f2881c = stateLayout;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(View view) {
        View throttleClick = view;
        Intrinsics.checkNotNullParameter(throttleClick, "$this$throttleClick");
        StateLayout stateLayout = this.f2881c;
        StatusInfo statusInfo = stateLayout.f9019e.get(Status.LOADING);
        StateLayout.m3994g(stateLayout, statusInfo != null ? statusInfo.f2888b : null, false, false, 6);
        return Unit.INSTANCE;
    }
}
