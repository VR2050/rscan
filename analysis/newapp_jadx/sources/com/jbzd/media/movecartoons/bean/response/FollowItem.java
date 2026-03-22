package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0019\n\u0002\u0010\b\n\u0002\b\u0013\b\u0086\b\u0018\u00002\u00020\u0001B[\u0012\u0006\u0010\u0012\u001a\u00020\u0005\u0012\u0006\u0010\u0013\u001a\u00020\u0005\u0012\u0006\u0010\u0014\u001a\u00020\u0005\u0012\u0006\u0010\u0015\u001a\u00020\u0005\u0012\u0006\u0010\u0016\u001a\u00020\u0005\u0012\u0006\u0010\u0017\u001a\u00020\u0005\u0012\u0006\u0010\u0018\u001a\u00020\u0005\u0012\u0006\u0010\u0019\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u001a\u001a\u00020\u0005\u0012\b\b\u0002\u0010\u001b\u001a\u00020\u0005¢\u0006\u0004\b0\u00101J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\r\u0010\u0006\u001a\u00020\u0005¢\u0006\u0004\b\u0006\u0010\u0007J\u0010\u0010\b\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\b\u0010\u0007J\u0010\u0010\t\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\t\u0010\u0007J\u0010\u0010\n\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\n\u0010\u0007J\u0010\u0010\u000b\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u000b\u0010\u0007J\u0010\u0010\f\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\f\u0010\u0007J\u0010\u0010\r\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\r\u0010\u0007J\u0010\u0010\u000e\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u000e\u0010\u0007J\u0010\u0010\u000f\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u000f\u0010\u0007J\u0010\u0010\u0010\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0010\u0010\u0007J\u0010\u0010\u0011\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0011\u0010\u0007Jt\u0010\u001c\u001a\u00020\u00002\b\b\u0002\u0010\u0012\u001a\u00020\u00052\b\b\u0002\u0010\u0013\u001a\u00020\u00052\b\b\u0002\u0010\u0014\u001a\u00020\u00052\b\b\u0002\u0010\u0015\u001a\u00020\u00052\b\b\u0002\u0010\u0016\u001a\u00020\u00052\b\b\u0002\u0010\u0017\u001a\u00020\u00052\b\b\u0002\u0010\u0018\u001a\u00020\u00052\b\b\u0002\u0010\u0019\u001a\u00020\u00052\b\b\u0002\u0010\u001a\u001a\u00020\u00052\b\b\u0002\u0010\u001b\u001a\u00020\u0005HÆ\u0001¢\u0006\u0004\b\u001c\u0010\u001dJ\u0010\u0010\u001e\u001a\u00020\u0005HÖ\u0001¢\u0006\u0004\b\u001e\u0010\u0007J\u0010\u0010 \u001a\u00020\u001fHÖ\u0001¢\u0006\u0004\b \u0010!J\u001a\u0010#\u001a\u00020\u00022\b\u0010\"\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b#\u0010$R\u0019\u0010\u0016\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0016\u0010%\u001a\u0004\b\u0016\u0010\u0007R\u0019\u0010\u0017\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0017\u0010%\u001a\u0004\b&\u0010\u0007R\u0019\u0010\u0019\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0019\u0010%\u001a\u0004\b'\u0010\u0007R\u0019\u0010\u0018\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0018\u0010%\u001a\u0004\b(\u0010\u0007R\u0019\u0010\u001b\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u001b\u0010%\u001a\u0004\b\u001b\u0010\u0007R\"\u0010\u001a\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001a\u0010%\u001a\u0004\b)\u0010\u0007\"\u0004\b*\u0010+R\u0019\u0010\u0014\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0014\u0010%\u001a\u0004\b,\u0010\u0007R\u0019\u0010\u0012\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0012\u0010%\u001a\u0004\b-\u0010\u0007R\u0019\u0010\u0013\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0013\u0010%\u001a\u0004\b.\u0010\u0007R\u0019\u0010\u0015\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\u0015\u0010%\u001a\u0004\b/\u0010\u0007¨\u00062"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/FollowItem;", "", "", "isFollow", "()Z", "", "isFollowShow", "()Ljava/lang/String;", "component1", "component2", "component3", "component4", "component5", "component6", "component7", "component8", "component9", "component10", "user_id", "nickname", "img", "sex", "is_vip", "sing", BloggerOrderBean.order_fans, "follow", "has_follow", "is_followed", "copy", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/bean/response/FollowItem;", "toString", "", "hashCode", "()I", "other", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getSing", "getFollow", "getFans", "getHas_follow", "setHas_follow", "(Ljava/lang/String;)V", "getImg", "getUser_id", "getNickname", "getSex", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class FollowItem {

    @NotNull
    private final String fans;

    @NotNull
    private final String follow;

    @NotNull
    private String has_follow;

    @NotNull
    private final String img;

    @NotNull
    private final String is_followed;

    @NotNull
    private final String is_vip;

    @NotNull
    private final String nickname;

    @NotNull
    private final String sex;

    @NotNull
    private final String sing;

    @NotNull
    private final String user_id;

    public FollowItem(@NotNull String user_id, @NotNull String nickname, @NotNull String img, @NotNull String sex, @NotNull String is_vip, @NotNull String sing, @NotNull String fans, @NotNull String follow, @NotNull String has_follow, @NotNull String is_followed) {
        Intrinsics.checkNotNullParameter(user_id, "user_id");
        Intrinsics.checkNotNullParameter(nickname, "nickname");
        Intrinsics.checkNotNullParameter(img, "img");
        Intrinsics.checkNotNullParameter(sex, "sex");
        Intrinsics.checkNotNullParameter(is_vip, "is_vip");
        Intrinsics.checkNotNullParameter(sing, "sing");
        Intrinsics.checkNotNullParameter(fans, "fans");
        Intrinsics.checkNotNullParameter(follow, "follow");
        Intrinsics.checkNotNullParameter(has_follow, "has_follow");
        Intrinsics.checkNotNullParameter(is_followed, "is_followed");
        this.user_id = user_id;
        this.nickname = nickname;
        this.img = img;
        this.sex = sex;
        this.is_vip = is_vip;
        this.sing = sing;
        this.fans = fans;
        this.follow = follow;
        this.has_follow = has_follow;
        this.is_followed = is_followed;
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getUser_id() {
        return this.user_id;
    }

    @NotNull
    /* renamed from: component10, reason: from getter */
    public final String getIs_followed() {
        return this.is_followed;
    }

    @NotNull
    /* renamed from: component2, reason: from getter */
    public final String getNickname() {
        return this.nickname;
    }

    @NotNull
    /* renamed from: component3, reason: from getter */
    public final String getImg() {
        return this.img;
    }

    @NotNull
    /* renamed from: component4, reason: from getter */
    public final String getSex() {
        return this.sex;
    }

    @NotNull
    /* renamed from: component5, reason: from getter */
    public final String getIs_vip() {
        return this.is_vip;
    }

    @NotNull
    /* renamed from: component6, reason: from getter */
    public final String getSing() {
        return this.sing;
    }

    @NotNull
    /* renamed from: component7, reason: from getter */
    public final String getFans() {
        return this.fans;
    }

    @NotNull
    /* renamed from: component8, reason: from getter */
    public final String getFollow() {
        return this.follow;
    }

    @NotNull
    /* renamed from: component9, reason: from getter */
    public final String getHas_follow() {
        return this.has_follow;
    }

    @NotNull
    public final FollowItem copy(@NotNull String user_id, @NotNull String nickname, @NotNull String img, @NotNull String sex, @NotNull String is_vip, @NotNull String sing, @NotNull String fans, @NotNull String follow, @NotNull String has_follow, @NotNull String is_followed) {
        Intrinsics.checkNotNullParameter(user_id, "user_id");
        Intrinsics.checkNotNullParameter(nickname, "nickname");
        Intrinsics.checkNotNullParameter(img, "img");
        Intrinsics.checkNotNullParameter(sex, "sex");
        Intrinsics.checkNotNullParameter(is_vip, "is_vip");
        Intrinsics.checkNotNullParameter(sing, "sing");
        Intrinsics.checkNotNullParameter(fans, "fans");
        Intrinsics.checkNotNullParameter(follow, "follow");
        Intrinsics.checkNotNullParameter(has_follow, "has_follow");
        Intrinsics.checkNotNullParameter(is_followed, "is_followed");
        return new FollowItem(user_id, nickname, img, sex, is_vip, sing, fans, follow, has_follow, is_followed);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof FollowItem)) {
            return false;
        }
        FollowItem followItem = (FollowItem) other;
        return Intrinsics.areEqual(this.user_id, followItem.user_id) && Intrinsics.areEqual(this.nickname, followItem.nickname) && Intrinsics.areEqual(this.img, followItem.img) && Intrinsics.areEqual(this.sex, followItem.sex) && Intrinsics.areEqual(this.is_vip, followItem.is_vip) && Intrinsics.areEqual(this.sing, followItem.sing) && Intrinsics.areEqual(this.fans, followItem.fans) && Intrinsics.areEqual(this.follow, followItem.follow) && Intrinsics.areEqual(this.has_follow, followItem.has_follow) && Intrinsics.areEqual(this.is_followed, followItem.is_followed);
    }

    @NotNull
    public final String getFans() {
        return this.fans;
    }

    @NotNull
    public final String getFollow() {
        return this.follow;
    }

    @NotNull
    public final String getHas_follow() {
        return this.has_follow;
    }

    @NotNull
    public final String getImg() {
        return this.img;
    }

    @NotNull
    public final String getNickname() {
        return this.nickname;
    }

    @NotNull
    public final String getSex() {
        return this.sex;
    }

    @NotNull
    public final String getSing() {
        return this.sing;
    }

    @NotNull
    public final String getUser_id() {
        return this.user_id;
    }

    public int hashCode() {
        return this.is_followed.hashCode() + C1499a.m598T(this.has_follow, C1499a.m598T(this.follow, C1499a.m598T(this.fans, C1499a.m598T(this.sing, C1499a.m598T(this.is_vip, C1499a.m598T(this.sex, C1499a.m598T(this.img, C1499a.m598T(this.nickname, this.user_id.hashCode() * 31, 31), 31), 31), 31), 31), 31), 31), 31);
    }

    public final boolean isFollow() {
        return Intrinsics.areEqual("y", this.is_followed);
    }

    @NotNull
    public final String isFollowShow() {
        return Intrinsics.areEqual(this.is_followed, "y") ? "已关注" : "+关注";
    }

    @NotNull
    public final String is_followed() {
        return this.is_followed;
    }

    @NotNull
    public final String is_vip() {
        return this.is_vip;
    }

    public final void setHas_follow(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.has_follow = str;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("FollowItem(user_id=");
        m586H.append(this.user_id);
        m586H.append(", nickname=");
        m586H.append(this.nickname);
        m586H.append(", img=");
        m586H.append(this.img);
        m586H.append(", sex=");
        m586H.append(this.sex);
        m586H.append(", is_vip=");
        m586H.append(this.is_vip);
        m586H.append(", sing=");
        m586H.append(this.sing);
        m586H.append(", fans=");
        m586H.append(this.fans);
        m586H.append(", follow=");
        m586H.append(this.follow);
        m586H.append(", has_follow=");
        m586H.append(this.has_follow);
        m586H.append(", is_followed=");
        return C1499a.m581C(m586H, this.is_followed, ')');
    }

    public /* synthetic */ FollowItem(String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, String str9, String str10, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, str3, str4, str5, str6, str7, str8, (i2 & 256) != 0 ? "n" : str9, (i2 & 512) != 0 ? "y" : str10);
    }
}
