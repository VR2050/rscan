package com.drake.brv.listener;

import android.view.View;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0002\u0018\u00002\u00020\u0001B(\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0017\u0010\u0004\u001a\u0013\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00070\u0005¢\u0006\u0002\b\b¢\u0006\u0002\u0010\tJ\u0010\u0010\u000b\u001a\u00020\u00072\u0006\u0010\f\u001a\u00020\u0006H\u0016R\u001f\u0010\u0004\u001a\u0013\u0012\u0004\u0012\u00020\u0006\u0012\u0004\u0012\u00020\u00070\u0005¢\u0006\u0002\b\bX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\n\u001a\u00020\u0003X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\r"}, m5311d2 = {"Lcom/drake/brv/listener/ThrottleClickListener;", "Landroid/view/View$OnClickListener;", "period", "", "block", "Lkotlin/Function1;", "Landroid/view/View;", "", "Lkotlin/ExtensionFunctionType;", "(JLkotlin/jvm/functions/Function1;)V", "lastTime", "onClick", "v", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.i.a.k.d, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public final class ThrottleClickListener implements View.OnClickListener {

    /* renamed from: c */
    public final long f2867c;

    /* renamed from: e */
    @NotNull
    public Function1<? super View, Unit> f2868e;

    /* renamed from: f */
    public long f2869f;

    public ThrottleClickListener(long j2, @NotNull Function1<? super View, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        this.f2867c = j2;
        this.f2868e = block;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(@NotNull View v) {
        Intrinsics.checkNotNullParameter(v, "v");
        long currentTimeMillis = System.currentTimeMillis();
        if (currentTimeMillis - this.f2869f > this.f2867c) {
            this.f2869f = currentTimeMillis;
            this.f2868e.invoke(v);
        }
    }
}
