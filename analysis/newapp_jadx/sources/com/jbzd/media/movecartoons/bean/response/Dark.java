package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0014\n\u0002\u0010\u000b\n\u0002\b\u000e\b\u0086\b\u0018\u00002\u00020\u0001BW\u0012\b\b\u0002\u0010\u000e\u001a\u00020\u0002\u0012\b\b\u0002\u0010\u000f\u001a\u00020\u0002\u0012\b\b\u0002\u0010\u0010\u001a\u00020\u0006\u0012\b\b\u0002\u0010\u0011\u001a\u00020\u0002\u0012\b\b\u0002\u0010\u0012\u001a\u00020\u0006\u0012\b\b\u0002\u0010\u0013\u001a\u00020\u0006\u0012\b\b\u0002\u0010\u0014\u001a\u00020\u0002\u0012\b\b\u0002\u0010\u0015\u001a\u00020\u0002¢\u0006\u0004\b'\u0010(J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J\u0010\u0010\u0007\u001a\u00020\u0006HÆ\u0003¢\u0006\u0004\b\u0007\u0010\bJ\u0010\u0010\t\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\t\u0010\u0004J\u0010\u0010\n\u001a\u00020\u0006HÆ\u0003¢\u0006\u0004\b\n\u0010\bJ\u0010\u0010\u000b\u001a\u00020\u0006HÆ\u0003¢\u0006\u0004\b\u000b\u0010\bJ\u0010\u0010\f\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\f\u0010\u0004J\u0010\u0010\r\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\r\u0010\u0004J`\u0010\u0016\u001a\u00020\u00002\b\b\u0002\u0010\u000e\u001a\u00020\u00022\b\b\u0002\u0010\u000f\u001a\u00020\u00022\b\b\u0002\u0010\u0010\u001a\u00020\u00062\b\b\u0002\u0010\u0011\u001a\u00020\u00022\b\b\u0002\u0010\u0012\u001a\u00020\u00062\b\b\u0002\u0010\u0013\u001a\u00020\u00062\b\b\u0002\u0010\u0014\u001a\u00020\u00022\b\b\u0002\u0010\u0015\u001a\u00020\u0002HÆ\u0001¢\u0006\u0004\b\u0016\u0010\u0017J\u0010\u0010\u0018\u001a\u00020\u0006HÖ\u0001¢\u0006\u0004\b\u0018\u0010\bJ\u0010\u0010\u0019\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\u0019\u0010\u0004J\u001a\u0010\u001c\u001a\u00020\u001b2\b\u0010\u001a\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u001c\u0010\u001dR\u0019\u0010\u0012\u001a\u00020\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\u0012\u0010\u001e\u001a\u0004\b\u0012\u0010\bR\u0019\u0010\u0015\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0015\u0010\u001f\u001a\u0004\b \u0010\u0004R\u0019\u0010\u000e\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000e\u0010\u001f\u001a\u0004\b!\u0010\u0004R\u0019\u0010\u0010\u001a\u00020\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u001e\u001a\u0004\b\"\u0010\bR\u0019\u0010\u0014\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0014\u0010\u001f\u001a\u0004\b#\u0010\u0004R\u0019\u0010\u0013\u001a\u00020\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\u0013\u0010\u001e\u001a\u0004\b$\u0010\bR\u0019\u0010\u0011\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0011\u0010\u001f\u001a\u0004\b%\u0010\u0004R\u0019\u0010\u000f\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000f\u0010\u001f\u001a\u0004\b&\u0010\u0004¨\u0006)"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/Dark;", "", "", "component1", "()I", "component2", "", "component3", "()Ljava/lang/String;", "component4", "component5", "component6", "component7", "component8", "group_end_time", "group_id", "group_name", "group_rate", "is_vip", "validity_period", "cache_num", "used_num", "copy", "(IILjava/lang/String;ILjava/lang/String;Ljava/lang/String;II)Lcom/jbzd/media/movecartoons/bean/response/Dark;", "toString", "hashCode", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "I", "getUsed_num", "getGroup_end_time", "getGroup_name", "getCache_num", "getValidity_period", "getGroup_rate", "getGroup_id", "<init>", "(IILjava/lang/String;ILjava/lang/String;Ljava/lang/String;II)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class Dark {
    private final int cache_num;
    private final int group_end_time;
    private final int group_id;

    @NotNull
    private final String group_name;
    private final int group_rate;

    @NotNull
    private final String is_vip;
    private final int used_num;

    @NotNull
    private final String validity_period;

    public Dark() {
        this(0, 0, null, 0, null, null, 0, 0, 255, null);
    }

    public Dark(int i2, int i3, @NotNull String group_name, int i4, @NotNull String is_vip, @NotNull String validity_period, int i5, int i6) {
        Intrinsics.checkNotNullParameter(group_name, "group_name");
        Intrinsics.checkNotNullParameter(is_vip, "is_vip");
        Intrinsics.checkNotNullParameter(validity_period, "validity_period");
        this.group_end_time = i2;
        this.group_id = i3;
        this.group_name = group_name;
        this.group_rate = i4;
        this.is_vip = is_vip;
        this.validity_period = validity_period;
        this.cache_num = i5;
        this.used_num = i6;
    }

    /* renamed from: component1, reason: from getter */
    public final int getGroup_end_time() {
        return this.group_end_time;
    }

    /* renamed from: component2, reason: from getter */
    public final int getGroup_id() {
        return this.group_id;
    }

    @NotNull
    /* renamed from: component3, reason: from getter */
    public final String getGroup_name() {
        return this.group_name;
    }

    /* renamed from: component4, reason: from getter */
    public final int getGroup_rate() {
        return this.group_rate;
    }

    @NotNull
    /* renamed from: component5, reason: from getter */
    public final String getIs_vip() {
        return this.is_vip;
    }

    @NotNull
    /* renamed from: component6, reason: from getter */
    public final String getValidity_period() {
        return this.validity_period;
    }

    /* renamed from: component7, reason: from getter */
    public final int getCache_num() {
        return this.cache_num;
    }

    /* renamed from: component8, reason: from getter */
    public final int getUsed_num() {
        return this.used_num;
    }

    @NotNull
    public final Dark copy(int group_end_time, int group_id, @NotNull String group_name, int group_rate, @NotNull String is_vip, @NotNull String validity_period, int cache_num, int used_num) {
        Intrinsics.checkNotNullParameter(group_name, "group_name");
        Intrinsics.checkNotNullParameter(is_vip, "is_vip");
        Intrinsics.checkNotNullParameter(validity_period, "validity_period");
        return new Dark(group_end_time, group_id, group_name, group_rate, is_vip, validity_period, cache_num, used_num);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Dark)) {
            return false;
        }
        Dark dark = (Dark) other;
        return this.group_end_time == dark.group_end_time && this.group_id == dark.group_id && Intrinsics.areEqual(this.group_name, dark.group_name) && this.group_rate == dark.group_rate && Intrinsics.areEqual(this.is_vip, dark.is_vip) && Intrinsics.areEqual(this.validity_period, dark.validity_period) && this.cache_num == dark.cache_num && this.used_num == dark.used_num;
    }

    public final int getCache_num() {
        return this.cache_num;
    }

    public final int getGroup_end_time() {
        return this.group_end_time;
    }

    public final int getGroup_id() {
        return this.group_id;
    }

    @NotNull
    public final String getGroup_name() {
        return this.group_name;
    }

    public final int getGroup_rate() {
        return this.group_rate;
    }

    public final int getUsed_num() {
        return this.used_num;
    }

    @NotNull
    public final String getValidity_period() {
        return this.validity_period;
    }

    public int hashCode() {
        return ((C1499a.m598T(this.validity_period, C1499a.m598T(this.is_vip, (C1499a.m598T(this.group_name, ((this.group_end_time * 31) + this.group_id) * 31, 31) + this.group_rate) * 31, 31), 31) + this.cache_num) * 31) + this.used_num;
    }

    @NotNull
    public final String is_vip() {
        return this.is_vip;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Dark(group_end_time=");
        m586H.append(this.group_end_time);
        m586H.append(", group_id=");
        m586H.append(this.group_id);
        m586H.append(", group_name=");
        m586H.append(this.group_name);
        m586H.append(", group_rate=");
        m586H.append(this.group_rate);
        m586H.append(", is_vip=");
        m586H.append(this.is_vip);
        m586H.append(", validity_period=");
        m586H.append(this.validity_period);
        m586H.append(", cache_num=");
        m586H.append(this.cache_num);
        m586H.append(", used_num=");
        return C1499a.m579A(m586H, this.used_num, ')');
    }

    public /* synthetic */ Dark(int i2, int i3, String str, int i4, String str2, String str3, int i5, int i6, int i7, DefaultConstructorMarker defaultConstructorMarker) {
        this((i7 & 1) != 0 ? 0 : i2, (i7 & 2) != 0 ? 0 : i3, (i7 & 4) != 0 ? "" : str, (i7 & 8) != 0 ? 0 : i4, (i7 & 16) != 0 ? "" : str2, (i7 & 32) == 0 ? str3 : "", (i7 & 64) != 0 ? 0 : i5, (i7 & 128) == 0 ? i6 : 0);
    }
}
