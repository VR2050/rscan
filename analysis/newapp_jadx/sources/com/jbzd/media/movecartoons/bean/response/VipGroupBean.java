package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\u000b\b\u0086\b\u0018\u00002\u00020\u0001B%\u0012\b\b\u0002\u0010\u000b\u001a\u00020\u0002\u0012\b\b\u0002\u0010\f\u001a\u00020\u0005\u0012\b\b\u0002\u0010\r\u001a\u00020\b¢\u0006\u0004\b \u0010!J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0006\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J\u0010\u0010\t\u001a\u00020\bHÆ\u0003¢\u0006\u0004\b\t\u0010\nJ.\u0010\u000e\u001a\u00020\u00002\b\b\u0002\u0010\u000b\u001a\u00020\u00022\b\b\u0002\u0010\f\u001a\u00020\u00052\b\b\u0002\u0010\r\u001a\u00020\bHÆ\u0001¢\u0006\u0004\b\u000e\u0010\u000fJ\u0010\u0010\u0011\u001a\u00020\u0010HÖ\u0001¢\u0006\u0004\b\u0011\u0010\u0012J\u0010\u0010\u0014\u001a\u00020\u0013HÖ\u0001¢\u0006\u0004\b\u0014\u0010\u0015J\u001a\u0010\u0018\u001a\u00020\u00172\b\u0010\u0016\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0018\u0010\u0019R\u0019\u0010\f\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\f\u0010\u001a\u001a\u0004\b\u001b\u0010\u0007R\u0019\u0010\u000b\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\u001c\u001a\u0004\b\u001d\u0010\u0004R\u0019\u0010\r\u001a\u00020\b8\u0006@\u0006¢\u0006\f\n\u0004\b\r\u0010\u001e\u001a\u0004\b\u001f\u0010\n¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/VipGroupBean;", "", "Lcom/jbzd/media/movecartoons/bean/response/Dark;", "component1", "()Lcom/jbzd/media/movecartoons/bean/response/Dark;", "Lcom/jbzd/media/movecartoons/bean/response/Deep;", "component2", "()Lcom/jbzd/media/movecartoons/bean/response/Deep;", "Lcom/jbzd/media/movecartoons/bean/response/Shallow;", "component3", "()Lcom/jbzd/media/movecartoons/bean/response/Shallow;", "dark", "deep", "shallow", "copy", "(Lcom/jbzd/media/movecartoons/bean/response/Dark;Lcom/jbzd/media/movecartoons/bean/response/Deep;Lcom/jbzd/media/movecartoons/bean/response/Shallow;)Lcom/jbzd/media/movecartoons/bean/response/VipGroupBean;", "", "toString", "()Ljava/lang/String;", "", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Lcom/jbzd/media/movecartoons/bean/response/Deep;", "getDeep", "Lcom/jbzd/media/movecartoons/bean/response/Dark;", "getDark", "Lcom/jbzd/media/movecartoons/bean/response/Shallow;", "getShallow", "<init>", "(Lcom/jbzd/media/movecartoons/bean/response/Dark;Lcom/jbzd/media/movecartoons/bean/response/Deep;Lcom/jbzd/media/movecartoons/bean/response/Shallow;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class VipGroupBean {

    @NotNull
    private final Dark dark;

    @NotNull
    private final Deep deep;

    @NotNull
    private final Shallow shallow;

    public VipGroupBean() {
        this(null, null, null, 7, null);
    }

    public VipGroupBean(@NotNull Dark dark, @NotNull Deep deep, @NotNull Shallow shallow) {
        Intrinsics.checkNotNullParameter(dark, "dark");
        Intrinsics.checkNotNullParameter(deep, "deep");
        Intrinsics.checkNotNullParameter(shallow, "shallow");
        this.dark = dark;
        this.deep = deep;
        this.shallow = shallow;
    }

    public static /* synthetic */ VipGroupBean copy$default(VipGroupBean vipGroupBean, Dark dark, Deep deep, Shallow shallow, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            dark = vipGroupBean.dark;
        }
        if ((i2 & 2) != 0) {
            deep = vipGroupBean.deep;
        }
        if ((i2 & 4) != 0) {
            shallow = vipGroupBean.shallow;
        }
        return vipGroupBean.copy(dark, deep, shallow);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final Dark getDark() {
        return this.dark;
    }

    @NotNull
    /* renamed from: component2, reason: from getter */
    public final Deep getDeep() {
        return this.deep;
    }

    @NotNull
    /* renamed from: component3, reason: from getter */
    public final Shallow getShallow() {
        return this.shallow;
    }

    @NotNull
    public final VipGroupBean copy(@NotNull Dark dark, @NotNull Deep deep, @NotNull Shallow shallow) {
        Intrinsics.checkNotNullParameter(dark, "dark");
        Intrinsics.checkNotNullParameter(deep, "deep");
        Intrinsics.checkNotNullParameter(shallow, "shallow");
        return new VipGroupBean(dark, deep, shallow);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof VipGroupBean)) {
            return false;
        }
        VipGroupBean vipGroupBean = (VipGroupBean) other;
        return Intrinsics.areEqual(this.dark, vipGroupBean.dark) && Intrinsics.areEqual(this.deep, vipGroupBean.deep) && Intrinsics.areEqual(this.shallow, vipGroupBean.shallow);
    }

    @NotNull
    public final Dark getDark() {
        return this.dark;
    }

    @NotNull
    public final Deep getDeep() {
        return this.deep;
    }

    @NotNull
    public final Shallow getShallow() {
        return this.shallow;
    }

    public int hashCode() {
        return this.shallow.hashCode() + ((this.deep.hashCode() + (this.dark.hashCode() * 31)) * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("VipGroupBean(dark=");
        m586H.append(this.dark);
        m586H.append(", deep=");
        m586H.append(this.deep);
        m586H.append(", shallow=");
        m586H.append(this.shallow);
        m586H.append(')');
        return m586H.toString();
    }

    public /* synthetic */ VipGroupBean(Dark dark, Deep deep, Shallow shallow, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? new Dark(0, 0, null, 0, null, null, 0, 0, 255, null) : dark, (i2 & 2) != 0 ? new Deep(0, 0, null, 0, null, null, 0, 0, 255, null) : deep, (i2 & 4) != 0 ? new Shallow(0, 0, null, 0, null, null, 0, 0, 255, null) : shallow);
    }
}
