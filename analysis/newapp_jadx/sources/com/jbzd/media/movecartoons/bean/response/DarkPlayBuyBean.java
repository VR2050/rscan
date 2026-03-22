package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\b\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0006\u001a\u00020\u0002\u0012\u0006\u0010\u0007\u001a\u00020\u0002¢\u0006\u0004\b\u0015\u0010\u0016J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J$\u0010\b\u001a\u00020\u00002\b\b\u0002\u0010\u0006\u001a\u00020\u00022\b\b\u0002\u0010\u0007\u001a\u00020\u0002HÆ\u0001¢\u0006\u0004\b\b\u0010\tJ\u0010\u0010\n\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\n\u0010\u0004J\u0010\u0010\f\u001a\u00020\u000bHÖ\u0001¢\u0006\u0004\b\f\u0010\rJ\u001a\u0010\u0010\u001a\u00020\u000f2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0010\u0010\u0011R\u0019\u0010\u0007\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0007\u0010\u0012\u001a\u0004\b\u0013\u0010\u0004R\u0019\u0010\u0006\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0006\u0010\u0012\u001a\u0004\b\u0014\u0010\u0004¨\u0006\u0017"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/DarkPlayBuyBean;", "", "", "component1", "()Ljava/lang/String;", "component2", "order_sn", "price", "copy", "(Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/bean/response/DarkPlayBuyBean;", "toString", "", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getPrice", "getOrder_sn", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class DarkPlayBuyBean {

    @NotNull
    private final String order_sn;

    @NotNull
    private final String price;

    public DarkPlayBuyBean(@NotNull String order_sn, @NotNull String price) {
        Intrinsics.checkNotNullParameter(order_sn, "order_sn");
        Intrinsics.checkNotNullParameter(price, "price");
        this.order_sn = order_sn;
        this.price = price;
    }

    public static /* synthetic */ DarkPlayBuyBean copy$default(DarkPlayBuyBean darkPlayBuyBean, String str, String str2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = darkPlayBuyBean.order_sn;
        }
        if ((i2 & 2) != 0) {
            str2 = darkPlayBuyBean.price;
        }
        return darkPlayBuyBean.copy(str, str2);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getOrder_sn() {
        return this.order_sn;
    }

    @NotNull
    /* renamed from: component2, reason: from getter */
    public final String getPrice() {
        return this.price;
    }

    @NotNull
    public final DarkPlayBuyBean copy(@NotNull String order_sn, @NotNull String price) {
        Intrinsics.checkNotNullParameter(order_sn, "order_sn");
        Intrinsics.checkNotNullParameter(price, "price");
        return new DarkPlayBuyBean(order_sn, price);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof DarkPlayBuyBean)) {
            return false;
        }
        DarkPlayBuyBean darkPlayBuyBean = (DarkPlayBuyBean) other;
        return Intrinsics.areEqual(this.order_sn, darkPlayBuyBean.order_sn) && Intrinsics.areEqual(this.price, darkPlayBuyBean.price);
    }

    @NotNull
    public final String getOrder_sn() {
        return this.order_sn;
    }

    @NotNull
    public final String getPrice() {
        return this.price;
    }

    public int hashCode() {
        return this.price.hashCode() + (this.order_sn.hashCode() * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("DarkPlayBuyBean(order_sn=");
        m586H.append(this.order_sn);
        m586H.append(", price=");
        return C1499a.m581C(m586H, this.price, ')');
    }
}
