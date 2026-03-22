package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\t\n\u0002\u0010\u000b\n\u0002\b\u000b\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\b\u001a\u00020\u0002\u0012\u0006\u0010\t\u001a\u00020\u0005¢\u0006\u0004\b\u0018\u0010\u0019J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0006\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J$\u0010\n\u001a\u00020\u00002\b\b\u0002\u0010\b\u001a\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\u0005HÆ\u0001¢\u0006\u0004\b\n\u0010\u000bJ\u0010\u0010\f\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\f\u0010\u0004J\u0010\u0010\r\u001a\u00020\u0005HÖ\u0001¢\u0006\u0004\b\r\u0010\u0007J\u001a\u0010\u0010\u001a\u00020\u000f2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0010\u0010\u0011R\u0019\u0010\t\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\u0012\u001a\u0004\b\u0013\u0010\u0007R\"\u0010\b\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\b\u0010\u0014\u001a\u0004\b\u0015\u0010\u0004\"\u0004\b\u0016\u0010\u0017¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/StatusConfigBean;", "", "", "component1", "()Ljava/lang/String;", "", "component2", "()I", "txt", "color", "copy", "(Ljava/lang/String;I)Lcom/jbzd/media/movecartoons/bean/response/StatusConfigBean;", "toString", "hashCode", "other", "", "equals", "(Ljava/lang/Object;)Z", "I", "getColor", "Ljava/lang/String;", "getTxt", "setTxt", "(Ljava/lang/String;)V", "<init>", "(Ljava/lang/String;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class StatusConfigBean {
    private final int color;

    @NotNull
    private String txt;

    public StatusConfigBean(@NotNull String txt, int i2) {
        Intrinsics.checkNotNullParameter(txt, "txt");
        this.txt = txt;
        this.color = i2;
    }

    public static /* synthetic */ StatusConfigBean copy$default(StatusConfigBean statusConfigBean, String str, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            str = statusConfigBean.txt;
        }
        if ((i3 & 2) != 0) {
            i2 = statusConfigBean.color;
        }
        return statusConfigBean.copy(str, i2);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getTxt() {
        return this.txt;
    }

    /* renamed from: component2, reason: from getter */
    public final int getColor() {
        return this.color;
    }

    @NotNull
    public final StatusConfigBean copy(@NotNull String txt, int color) {
        Intrinsics.checkNotNullParameter(txt, "txt");
        return new StatusConfigBean(txt, color);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof StatusConfigBean)) {
            return false;
        }
        StatusConfigBean statusConfigBean = (StatusConfigBean) other;
        return Intrinsics.areEqual(this.txt, statusConfigBean.txt) && this.color == statusConfigBean.color;
    }

    public final int getColor() {
        return this.color;
    }

    @NotNull
    public final String getTxt() {
        return this.txt;
    }

    public int hashCode() {
        return (this.txt.hashCode() * 31) + this.color;
    }

    public final void setTxt(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.txt = str;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("StatusConfigBean(txt=");
        m586H.append(this.txt);
        m586H.append(", color=");
        return C1499a.m579A(m586H, this.color, ')');
    }
}
