package com.jbzd.media.movecartoons.bean.event;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\n\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\t\b\u0086\b\u0018\u00002\u00020\u0001B+\u0012\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010\t\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0018\u0010\u0019J\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0012\u0010\u0005\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J\u0012\u0010\u0006\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0004J4\u0010\n\u001a\u00020\u00002\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\t\u001a\u0004\u0018\u00010\u0002HÆ\u0001¢\u0006\u0004\b\n\u0010\u000bJ\u0010\u0010\f\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\f\u0010\u0004J\u0010\u0010\u000e\u001a\u00020\rHÖ\u0001¢\u0006\u0004\b\u000e\u0010\u000fJ\u001a\u0010\u0012\u001a\u00020\u00112\b\u0010\u0010\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0012\u0010\u0013R\u001b\u0010\b\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\u0014\u001a\u0004\b\u0015\u0010\u0004R\u001b\u0010\u0007\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0007\u0010\u0014\u001a\u0004\b\u0016\u0010\u0004R\u001b\u0010\t\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\u0014\u001a\u0004\b\u0017\u0010\u0004¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/event/EventUpdate;", "", "", "component1", "()Ljava/lang/String;", "component2", "component3", "orderBy", "videoType", "keyword", "copy", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/bean/event/EventUpdate;", "toString", "", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getVideoType", "getOrderBy", "getKeyword", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class EventUpdate {

    @Nullable
    private final String keyword;

    @Nullable
    private final String orderBy;

    @Nullable
    private final String videoType;

    public EventUpdate() {
        this(null, null, null, 7, null);
    }

    public EventUpdate(@Nullable String str, @Nullable String str2, @Nullable String str3) {
        this.orderBy = str;
        this.videoType = str2;
        this.keyword = str3;
    }

    public static /* synthetic */ EventUpdate copy$default(EventUpdate eventUpdate, String str, String str2, String str3, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = eventUpdate.orderBy;
        }
        if ((i2 & 2) != 0) {
            str2 = eventUpdate.videoType;
        }
        if ((i2 & 4) != 0) {
            str3 = eventUpdate.keyword;
        }
        return eventUpdate.copy(str, str2, str3);
    }

    @Nullable
    /* renamed from: component1, reason: from getter */
    public final String getOrderBy() {
        return this.orderBy;
    }

    @Nullable
    /* renamed from: component2, reason: from getter */
    public final String getVideoType() {
        return this.videoType;
    }

    @Nullable
    /* renamed from: component3, reason: from getter */
    public final String getKeyword() {
        return this.keyword;
    }

    @NotNull
    public final EventUpdate copy(@Nullable String orderBy, @Nullable String videoType, @Nullable String keyword) {
        return new EventUpdate(orderBy, videoType, keyword);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof EventUpdate)) {
            return false;
        }
        EventUpdate eventUpdate = (EventUpdate) other;
        return Intrinsics.areEqual(this.orderBy, eventUpdate.orderBy) && Intrinsics.areEqual(this.videoType, eventUpdate.videoType) && Intrinsics.areEqual(this.keyword, eventUpdate.keyword);
    }

    @Nullable
    public final String getKeyword() {
        return this.keyword;
    }

    @Nullable
    public final String getOrderBy() {
        return this.orderBy;
    }

    @Nullable
    public final String getVideoType() {
        return this.videoType;
    }

    public int hashCode() {
        String str = this.orderBy;
        int hashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.videoType;
        int hashCode2 = (hashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.keyword;
        return hashCode2 + (str3 != null ? str3.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("EventUpdate(orderBy=");
        m586H.append((Object) this.orderBy);
        m586H.append(", videoType=");
        m586H.append((Object) this.videoType);
        m586H.append(", keyword=");
        m586H.append((Object) this.keyword);
        m586H.append(')');
        return m586H.toString();
    }

    public /* synthetic */ EventUpdate(String str, String str2, String str3, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? null : str, (i2 & 2) != 0 ? null : str2, (i2 & 4) != 0 ? null : str3);
    }
}
