package com.drake.statelayout;

import android.view.View;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0000\u0018\u00002\u00020\u0001B2\u0012\b\b\u0002\u0010\u0002\u001a\u00020\u0003\u0012\b\b\u0002\u0010\u0004\u001a\u00020\u0005\u0012\u0017\u0010\u0006\u001a\u0013\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\t0\u0007¢\u0006\u0002\b\n¢\u0006\u0002\u0010\u000bJ\u0010\u0010\r\u001a\u00020\t2\u0006\u0010\u000e\u001a\u00020\bH\u0016R\u001f\u0010\u0006\u001a\u0013\u0012\u0004\u0012\u00020\b\u0012\u0004\u0012\u00020\t0\u0007¢\u0006\u0002\b\nX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u000e\u0010\f\u001a\u00020\u0003X\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u000f"}, m5311d2 = {"Lcom/drake/statelayout/ThrottleClickListener;", "Landroid/view/View$OnClickListener;", "interval", "", "unit", "Ljava/util/concurrent/TimeUnit;", "block", "Lkotlin/Function1;", "Landroid/view/View;", "", "Lkotlin/ExtensionFunctionType;", "(JLjava/util/concurrent/TimeUnit;Lkotlin/jvm/functions/Function1;)V", "lastTime", "onClick", "v", "statelayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.i.b.g, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public final class ThrottleClickListener implements View.OnClickListener {

    /* renamed from: c */
    public final long f2889c;

    /* renamed from: e */
    @NotNull
    public final TimeUnit f2890e;

    /* renamed from: f */
    @NotNull
    public Function1<? super View, Unit> f2891f;

    /* renamed from: g */
    public long f2892g;

    public ThrottleClickListener(long j2, @NotNull TimeUnit unit, @NotNull Function1<? super View, Unit> block) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        Intrinsics.checkNotNullParameter(block, "block");
        this.f2889c = j2;
        this.f2890e = unit;
        this.f2891f = block;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(@NotNull View v) {
        Intrinsics.checkNotNullParameter(v, "v");
        long currentTimeMillis = System.currentTimeMillis();
        if (currentTimeMillis - this.f2892g > this.f2890e.toMillis(this.f2889c)) {
            this.f2892g = currentTimeMillis;
            this.f2891f.invoke(v);
        }
    }
}
