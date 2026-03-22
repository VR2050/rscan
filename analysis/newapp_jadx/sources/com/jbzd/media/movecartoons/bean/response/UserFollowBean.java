package com.jbzd.media.movecartoons.bean.response;

import androidx.core.app.NotificationCompat;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\t\n\u0002\u0010\b\n\u0002\b\u0012\b\u0086\b\u0018\u00002\u00020\u0001B%\u0012\b\u0010\t\u001a\u0004\u0018\u00010\u0002\u0012\b\b\u0002\u0010\n\u001a\u00020\u0005\u0012\b\u0010\u000b\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u001f\u0010 J\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0006\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J\u0012\u0010\b\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\b\u0010\u0004J2\u0010\f\u001a\u00020\u00002\n\b\u0002\u0010\t\u001a\u0004\u0018\u00010\u00022\b\b\u0002\u0010\n\u001a\u00020\u00052\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u0002HÆ\u0001¢\u0006\u0004\b\f\u0010\rJ\u0010\u0010\u000e\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\u000e\u0010\u0004J\u0010\u0010\u0010\u001a\u00020\u000fHÖ\u0001¢\u0006\u0004\b\u0010\u0010\u0011J\u001a\u0010\u0013\u001a\u00020\u00052\b\u0010\u0012\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0013\u0010\u0014R$\u0010\t\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\u0015\u001a\u0004\b\u0016\u0010\u0004\"\u0004\b\u0017\u0010\u0018R\"\u0010\n\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u0019\u001a\u0004\b\u001a\u0010\u0007\"\u0004\b\u001b\u0010\u001cR$\u0010\u000b\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u000b\u0010\u0015\u001a\u0004\b\u001d\u0010\u0004\"\u0004\b\u001e\u0010\u0018¨\u0006!"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/UserFollowBean;", "", "", "component1", "()Ljava/lang/String;", "", "component2", "()Z", "component3", NotificationCompat.CATEGORY_STATUS, "data", "time", "copy", "(Ljava/lang/String;ZLjava/lang/String;)Lcom/jbzd/media/movecartoons/bean/response/UserFollowBean;", "toString", "", "hashCode", "()I", "other", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getStatus", "setStatus", "(Ljava/lang/String;)V", "Z", "getData", "setData", "(Z)V", "getTime", "setTime", "<init>", "(Ljava/lang/String;ZLjava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class UserFollowBean {
    private boolean data;

    @Nullable
    private String status;

    @Nullable
    private String time;

    public UserFollowBean(@Nullable String str, boolean z, @Nullable String str2) {
        this.status = str;
        this.data = z;
        this.time = str2;
    }

    public static /* synthetic */ UserFollowBean copy$default(UserFollowBean userFollowBean, String str, boolean z, String str2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = userFollowBean.status;
        }
        if ((i2 & 2) != 0) {
            z = userFollowBean.data;
        }
        if ((i2 & 4) != 0) {
            str2 = userFollowBean.time;
        }
        return userFollowBean.copy(str, z, str2);
    }

    @Nullable
    /* renamed from: component1, reason: from getter */
    public final String getStatus() {
        return this.status;
    }

    /* renamed from: component2, reason: from getter */
    public final boolean getData() {
        return this.data;
    }

    @Nullable
    /* renamed from: component3, reason: from getter */
    public final String getTime() {
        return this.time;
    }

    @NotNull
    public final UserFollowBean copy(@Nullable String status, boolean data, @Nullable String time) {
        return new UserFollowBean(status, data, time);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof UserFollowBean)) {
            return false;
        }
        UserFollowBean userFollowBean = (UserFollowBean) other;
        return Intrinsics.areEqual(this.status, userFollowBean.status) && this.data == userFollowBean.data && Intrinsics.areEqual(this.time, userFollowBean.time);
    }

    public final boolean getData() {
        return this.data;
    }

    @Nullable
    public final String getStatus() {
        return this.status;
    }

    @Nullable
    public final String getTime() {
        return this.time;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int hashCode() {
        String str = this.status;
        int hashCode = (str == null ? 0 : str.hashCode()) * 31;
        boolean z = this.data;
        int i2 = z;
        if (z != 0) {
            i2 = 1;
        }
        int i3 = (hashCode + i2) * 31;
        String str2 = this.time;
        return i3 + (str2 != null ? str2.hashCode() : 0);
    }

    public final void setData(boolean z) {
        this.data = z;
    }

    public final void setStatus(@Nullable String str) {
        this.status = str;
    }

    public final void setTime(@Nullable String str) {
        this.time = str;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("UserFollowBean(status=");
        m586H.append((Object) this.status);
        m586H.append(", data=");
        m586H.append(this.data);
        m586H.append(", time=");
        m586H.append((Object) this.time);
        m586H.append(')');
        return m586H.toString();
    }

    public /* synthetic */ UserFollowBean(String str, boolean z, String str2, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, (i2 & 2) != 0 ? false : z, str2);
    }
}
