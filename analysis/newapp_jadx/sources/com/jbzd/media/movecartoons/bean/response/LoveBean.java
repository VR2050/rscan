package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u000b\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\b\u001a\u00020\u0002\u0012\u0006\u0010\t\u001a\u00020\u0005¢\u0006\u0004\b\u0016\u0010\u0017J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0006\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J$\u0010\n\u001a\u00020\u00002\b\b\u0002\u0010\b\u001a\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\u0005HÆ\u0001¢\u0006\u0004\b\n\u0010\u000bJ\u0010\u0010\f\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\f\u0010\u0004J\u0010\u0010\u000e\u001a\u00020\rHÖ\u0001¢\u0006\u0004\b\u000e\u0010\u000fJ\u001a\u0010\u0011\u001a\u00020\u00052\b\u0010\u0010\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0011\u0010\u0012R\u0019\u0010\t\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\u0013\u001a\u0004\b\t\u0010\u0007R\u0019\u0010\b\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\u0014\u001a\u0004\b\u0015\u0010\u0004¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/LoveBean;", "", "", "component1", "()Ljava/lang/String;", "", "component2", "()Z", "love", "is_love", "copy", "(Ljava/lang/String;Z)Lcom/jbzd/media/movecartoons/bean/response/LoveBean;", "toString", "", "hashCode", "()I", "other", "equals", "(Ljava/lang/Object;)Z", "Z", "Ljava/lang/String;", "getLove", "<init>", "(Ljava/lang/String;Z)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class LoveBean {
    private final boolean is_love;

    @NotNull
    private final String love;

    public LoveBean(@NotNull String love, boolean z) {
        Intrinsics.checkNotNullParameter(love, "love");
        this.love = love;
        this.is_love = z;
    }

    public static /* synthetic */ LoveBean copy$default(LoveBean loveBean, String str, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = loveBean.love;
        }
        if ((i2 & 2) != 0) {
            z = loveBean.is_love;
        }
        return loveBean.copy(str, z);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getLove() {
        return this.love;
    }

    /* renamed from: component2, reason: from getter */
    public final boolean getIs_love() {
        return this.is_love;
    }

    @NotNull
    public final LoveBean copy(@NotNull String love, boolean is_love) {
        Intrinsics.checkNotNullParameter(love, "love");
        return new LoveBean(love, is_love);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof LoveBean)) {
            return false;
        }
        LoveBean loveBean = (LoveBean) other;
        return Intrinsics.areEqual(this.love, loveBean.love) && this.is_love == loveBean.is_love;
    }

    @NotNull
    public final String getLove() {
        return this.love;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int hashCode() {
        int hashCode = this.love.hashCode() * 31;
        boolean z = this.is_love;
        int i2 = z;
        if (z != 0) {
            i2 = 1;
        }
        return hashCode + i2;
    }

    public final boolean is_love() {
        return this.is_love;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("LoveBean(love=");
        m586H.append(this.love);
        m586H.append(", is_love=");
        m586H.append(this.is_love);
        m586H.append(')');
        return m586H.toString();
    }
}
