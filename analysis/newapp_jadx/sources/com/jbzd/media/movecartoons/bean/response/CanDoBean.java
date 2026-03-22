package com.jbzd.media.movecartoons.bean.response;

import androidx.core.app.NotificationCompat;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u000b\n\u0002\u0010\u000b\n\u0002\b\f\b\u0086\b\u0018\u00002\u00020\u0001B\u001f\u0012\u0006\u0010\t\u001a\u00020\u0002\u0012\u0006\u0010\n\u001a\u00020\u0005\u0012\u0006\u0010\u000b\u001a\u00020\u0002¢\u0006\u0004\b\u001b\u0010\u001cJ\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0006\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J\u0010\u0010\b\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\b\u0010\u0004J.\u0010\f\u001a\u00020\u00002\b\b\u0002\u0010\t\u001a\u00020\u00022\b\b\u0002\u0010\n\u001a\u00020\u00052\b\b\u0002\u0010\u000b\u001a\u00020\u0002HÆ\u0001¢\u0006\u0004\b\f\u0010\rJ\u0010\u0010\u000e\u001a\u00020\u0005HÖ\u0001¢\u0006\u0004\b\u000e\u0010\u0007J\u0010\u0010\u000f\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\u000f\u0010\u0004J\u001a\u0010\u0012\u001a\u00020\u00112\b\u0010\u0010\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0012\u0010\u0013R\u0019\u0010\u000b\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\u0014\u001a\u0004\b\u0015\u0010\u0004R\"\u0010\t\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\u0014\u001a\u0004\b\u0016\u0010\u0004\"\u0004\b\u0017\u0010\u0018R\u0019\u0010\n\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\n\u0010\u0019\u001a\u0004\b\u001a\u0010\u0007¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/CanDoBean;", "", "", "component1", "()I", "", "component2", "()Ljava/lang/String;", "component3", "trade_id", "action_txt", NotificationCompat.CATEGORY_STATUS, "copy", "(ILjava/lang/String;I)Lcom/jbzd/media/movecartoons/bean/response/CanDoBean;", "toString", "hashCode", "other", "", "equals", "(Ljava/lang/Object;)Z", "I", "getStatus", "getTrade_id", "setTrade_id", "(I)V", "Ljava/lang/String;", "getAction_txt", "<init>", "(ILjava/lang/String;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class CanDoBean {

    @NotNull
    private final String action_txt;
    private final int status;
    private int trade_id;

    public CanDoBean(int i2, @NotNull String action_txt, int i3) {
        Intrinsics.checkNotNullParameter(action_txt, "action_txt");
        this.trade_id = i2;
        this.action_txt = action_txt;
        this.status = i3;
    }

    public static /* synthetic */ CanDoBean copy$default(CanDoBean canDoBean, int i2, String str, int i3, int i4, Object obj) {
        if ((i4 & 1) != 0) {
            i2 = canDoBean.trade_id;
        }
        if ((i4 & 2) != 0) {
            str = canDoBean.action_txt;
        }
        if ((i4 & 4) != 0) {
            i3 = canDoBean.status;
        }
        return canDoBean.copy(i2, str, i3);
    }

    /* renamed from: component1, reason: from getter */
    public final int getTrade_id() {
        return this.trade_id;
    }

    @NotNull
    /* renamed from: component2, reason: from getter */
    public final String getAction_txt() {
        return this.action_txt;
    }

    /* renamed from: component3, reason: from getter */
    public final int getStatus() {
        return this.status;
    }

    @NotNull
    public final CanDoBean copy(int trade_id, @NotNull String action_txt, int status) {
        Intrinsics.checkNotNullParameter(action_txt, "action_txt");
        return new CanDoBean(trade_id, action_txt, status);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CanDoBean)) {
            return false;
        }
        CanDoBean canDoBean = (CanDoBean) other;
        return this.trade_id == canDoBean.trade_id && Intrinsics.areEqual(this.action_txt, canDoBean.action_txt) && this.status == canDoBean.status;
    }

    @NotNull
    public final String getAction_txt() {
        return this.action_txt;
    }

    public final int getStatus() {
        return this.status;
    }

    public final int getTrade_id() {
        return this.trade_id;
    }

    public int hashCode() {
        return C1499a.m598T(this.action_txt, this.trade_id * 31, 31) + this.status;
    }

    public final void setTrade_id(int i2) {
        this.trade_id = i2;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("CanDoBean(trade_id=");
        m586H.append(this.trade_id);
        m586H.append(", action_txt=");
        m586H.append(this.action_txt);
        m586H.append(", status=");
        return C1499a.m579A(m586H, this.status, ')');
    }
}
