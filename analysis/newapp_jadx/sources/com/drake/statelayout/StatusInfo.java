package com.drake.statelayout;

import android.view.View;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0000\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\b\u0010\u0004\u001a\u0004\u0018\u00010\u0001¢\u0006\u0002\u0010\u0005J\t\u0010\u000e\u001a\u00020\u0003HÆ\u0003J\u000b\u0010\u000f\u001a\u0004\u0018\u00010\u0001HÆ\u0003J\u001f\u0010\u0010\u001a\u00020\u00002\b\b\u0002\u0010\u0002\u001a\u00020\u00032\n\b\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u0001HÆ\u0001J\u0013\u0010\u0011\u001a\u00020\u00122\b\u0010\u0013\u001a\u0004\u0018\u00010\u0001HÖ\u0003J\t\u0010\u0014\u001a\u00020\u0015HÖ\u0001J\t\u0010\u0016\u001a\u00020\u0017HÖ\u0001R\u001c\u0010\u0004\u001a\u0004\u0018\u00010\u0001X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0006\u0010\u0007\"\u0004\b\b\u0010\tR\u001a\u0010\u0002\u001a\u00020\u0003X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\u000b\"\u0004\b\f\u0010\r¨\u0006\u0018"}, m5311d2 = {"Lcom/drake/statelayout/StatusInfo;", "", "view", "Landroid/view/View;", "tag", "(Landroid/view/View;Ljava/lang/Object;)V", "getTag", "()Ljava/lang/Object;", "setTag", "(Ljava/lang/Object;)V", "getView", "()Landroid/view/View;", "setView", "(Landroid/view/View;)V", "component1", "component2", "copy", "equals", "", "other", "hashCode", "", "toString", "", "statelayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.i.b.f, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public final /* data */ class StatusInfo {

    /* renamed from: a */
    @NotNull
    public View f2887a;

    /* renamed from: b */
    @Nullable
    public Object f2888b;

    public StatusInfo(@NotNull View view, @Nullable Object obj) {
        Intrinsics.checkNotNullParameter(view, "view");
        this.f2887a = view;
        this.f2888b = obj;
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof StatusInfo)) {
            return false;
        }
        StatusInfo statusInfo = (StatusInfo) other;
        return Intrinsics.areEqual(this.f2887a, statusInfo.f2887a) && Intrinsics.areEqual(this.f2888b, statusInfo.f2888b);
    }

    public int hashCode() {
        int hashCode = this.f2887a.hashCode() * 31;
        Object obj = this.f2888b;
        return hashCode + (obj == null ? 0 : obj.hashCode());
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("StatusInfo(view=");
        m586H.append(this.f2887a);
        m586H.append(", tag=");
        m586H.append(this.f2888b);
        m586H.append(')');
        return m586H.toString();
    }
}
