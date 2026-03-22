package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u000b\n\u0002\u0010\u000b\n\u0002\b\u000b\b\u0086\b\u0018\u00002\u00020\u0001B5\u0012\n\b\u0002\u0010\n\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010\f\u001a\u0004\u0018\u00010\u0002\u0012\b\b\u0002\u0010\r\u001a\u00020\u0007¢\u0006\u0004\b\u001c\u0010\u001dJ\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0012\u0010\u0005\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J\u0012\u0010\u0006\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0004J\u0010\u0010\b\u001a\u00020\u0007HÆ\u0003¢\u0006\u0004\b\b\u0010\tJ>\u0010\u000e\u001a\u00020\u00002\n\b\u0002\u0010\n\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\f\u001a\u0004\u0018\u00010\u00022\b\b\u0002\u0010\r\u001a\u00020\u0007HÆ\u0001¢\u0006\u0004\b\u000e\u0010\u000fJ\u0010\u0010\u0010\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\u0010\u0010\u0004J\u0010\u0010\u0011\u001a\u00020\u0007HÖ\u0001¢\u0006\u0004\b\u0011\u0010\tJ\u001a\u0010\u0014\u001a\u00020\u00132\b\u0010\u0012\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0014\u0010\u0015R\u001b\u0010\f\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\f\u0010\u0016\u001a\u0004\b\u0017\u0010\u0004R\u001b\u0010\n\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\n\u0010\u0016\u001a\u0004\b\u0018\u0010\u0004R\u001b\u0010\u000b\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\u0016\u001a\u0004\b\u0019\u0010\u0004R\u0019\u0010\r\u001a\u00020\u00078\u0006@\u0006¢\u0006\f\n\u0004\b\r\u0010\u001a\u001a\u0004\b\u001b\u0010\t¨\u0006\u001e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/DarkPlayTagBean;", "", "", "component1", "()Ljava/lang/String;", "component2", "component3", "", "component4", "()I", "id", "name", "img", "watch_limit", "copy", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lcom/jbzd/media/movecartoons/bean/response/DarkPlayTagBean;", "toString", "hashCode", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getImg", "getId", "getName", "I", "getWatch_limit", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class DarkPlayTagBean {

    @Nullable
    private final String id;

    @Nullable
    private final String img;

    @Nullable
    private final String name;
    private final int watch_limit;

    public DarkPlayTagBean() {
        this(null, null, null, 0, 15, null);
    }

    public DarkPlayTagBean(@Nullable String str, @Nullable String str2, @Nullable String str3, int i2) {
        this.id = str;
        this.name = str2;
        this.img = str3;
        this.watch_limit = i2;
    }

    public static /* synthetic */ DarkPlayTagBean copy$default(DarkPlayTagBean darkPlayTagBean, String str, String str2, String str3, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            str = darkPlayTagBean.id;
        }
        if ((i3 & 2) != 0) {
            str2 = darkPlayTagBean.name;
        }
        if ((i3 & 4) != 0) {
            str3 = darkPlayTagBean.img;
        }
        if ((i3 & 8) != 0) {
            i2 = darkPlayTagBean.watch_limit;
        }
        return darkPlayTagBean.copy(str, str2, str3, i2);
    }

    @Nullable
    /* renamed from: component1, reason: from getter */
    public final String getId() {
        return this.id;
    }

    @Nullable
    /* renamed from: component2, reason: from getter */
    public final String getName() {
        return this.name;
    }

    @Nullable
    /* renamed from: component3, reason: from getter */
    public final String getImg() {
        return this.img;
    }

    /* renamed from: component4, reason: from getter */
    public final int getWatch_limit() {
        return this.watch_limit;
    }

    @NotNull
    public final DarkPlayTagBean copy(@Nullable String id, @Nullable String name, @Nullable String img, int watch_limit) {
        return new DarkPlayTagBean(id, name, img, watch_limit);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof DarkPlayTagBean)) {
            return false;
        }
        DarkPlayTagBean darkPlayTagBean = (DarkPlayTagBean) other;
        return Intrinsics.areEqual(this.id, darkPlayTagBean.id) && Intrinsics.areEqual(this.name, darkPlayTagBean.name) && Intrinsics.areEqual(this.img, darkPlayTagBean.img) && this.watch_limit == darkPlayTagBean.watch_limit;
    }

    @Nullable
    public final String getId() {
        return this.id;
    }

    @Nullable
    public final String getImg() {
        return this.img;
    }

    @Nullable
    public final String getName() {
        return this.name;
    }

    public final int getWatch_limit() {
        return this.watch_limit;
    }

    public int hashCode() {
        String str = this.id;
        int hashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.name;
        int hashCode2 = (hashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.img;
        return ((hashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31) + this.watch_limit;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("DarkPlayTagBean(id=");
        m586H.append((Object) this.id);
        m586H.append(", name=");
        m586H.append((Object) this.name);
        m586H.append(", img=");
        m586H.append((Object) this.img);
        m586H.append(", watch_limit=");
        return C1499a.m579A(m586H, this.watch_limit, ')');
    }

    public /* synthetic */ DarkPlayTagBean(String str, String str2, String str3, int i2, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? "" : str, (i3 & 2) != 0 ? "" : str2, (i3 & 4) != 0 ? "" : str3, (i3 & 8) != 0 ? 0 : i2);
    }
}
