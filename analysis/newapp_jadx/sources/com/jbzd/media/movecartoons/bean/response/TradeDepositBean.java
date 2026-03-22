package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\b\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0006\u001a\u00020\u0002\u0012\u0006\u0010\u0007\u001a\u00020\u0002¢\u0006\u0004\b\u0015\u0010\u0016J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J$\u0010\b\u001a\u00020\u00002\b\b\u0002\u0010\u0006\u001a\u00020\u00022\b\b\u0002\u0010\u0007\u001a\u00020\u0002HÆ\u0001¢\u0006\u0004\b\b\u0010\tJ\u0010\u0010\u000b\u001a\u00020\nHÖ\u0001¢\u0006\u0004\b\u000b\u0010\fJ\u0010\u0010\r\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\r\u0010\u0004J\u001a\u0010\u0010\u001a\u00020\u000f2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0010\u0010\u0011R\u0019\u0010\u0006\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0006\u0010\u0012\u001a\u0004\b\u0013\u0010\u0004R\u0019\u0010\u0007\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0007\u0010\u0012\u001a\u0004\b\u0014\u0010\u0004¨\u0006\u0017"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/TradeDepositBean;", "", "", "component1", "()I", "component2", VideoTypeBean.video_type_point, "original_point", "copy", "(II)Lcom/jbzd/media/movecartoons/bean/response/TradeDepositBean;", "", "toString", "()Ljava/lang/String;", "hashCode", "other", "", "equals", "(Ljava/lang/Object;)Z", "I", "getPoint", "getOriginal_point", "<init>", "(II)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class TradeDepositBean {
    private final int original_point;
    private final int point;

    public TradeDepositBean(int i2, int i3) {
        this.point = i2;
        this.original_point = i3;
    }

    public static /* synthetic */ TradeDepositBean copy$default(TradeDepositBean tradeDepositBean, int i2, int i3, int i4, Object obj) {
        if ((i4 & 1) != 0) {
            i2 = tradeDepositBean.point;
        }
        if ((i4 & 2) != 0) {
            i3 = tradeDepositBean.original_point;
        }
        return tradeDepositBean.copy(i2, i3);
    }

    /* renamed from: component1, reason: from getter */
    public final int getPoint() {
        return this.point;
    }

    /* renamed from: component2, reason: from getter */
    public final int getOriginal_point() {
        return this.original_point;
    }

    @NotNull
    public final TradeDepositBean copy(int point, int original_point) {
        return new TradeDepositBean(point, original_point);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof TradeDepositBean)) {
            return false;
        }
        TradeDepositBean tradeDepositBean = (TradeDepositBean) other;
        return this.point == tradeDepositBean.point && this.original_point == tradeDepositBean.original_point;
    }

    public final int getOriginal_point() {
        return this.original_point;
    }

    public final int getPoint() {
        return this.point;
    }

    public int hashCode() {
        return (this.point * 31) + this.original_point;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("TradeDepositBean(point=");
        m586H.append(this.point);
        m586H.append(", original_point=");
        return C1499a.m579A(m586H, this.original_point, ')');
    }
}
