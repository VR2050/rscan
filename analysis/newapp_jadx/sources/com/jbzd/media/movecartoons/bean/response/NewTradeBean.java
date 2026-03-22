package com.jbzd.media.movecartoons.bean.response;

import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\r\n\u0002\u0010\u000b\n\u0002\b\u000e\b\u0086\b\u0018\u00002\u00020\u0001Bg\u0012\u0006\u0010\u000f\u001a\u00020\u0002\u0012\u0016\u0010\u0010\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u0006\u0012\u0016\u0010\u0011\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u0006\u0012\u0016\u0010\u0012\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u0006\u0012\u0006\u0010\u0013\u001a\u00020\u0002\u0012\u0006\u0010\u0014\u001a\u00020\f¢\u0006\u0004\b&\u0010'J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J \u0010\u0007\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u0006HÆ\u0003¢\u0006\u0004\b\u0007\u0010\bJ \u0010\t\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u0006HÆ\u0003¢\u0006\u0004\b\t\u0010\bJ \u0010\n\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u0006HÆ\u0003¢\u0006\u0004\b\n\u0010\bJ\u0010\u0010\u000b\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u000b\u0010\u0004J\u0010\u0010\r\u001a\u00020\fHÆ\u0003¢\u0006\u0004\b\r\u0010\u000eJ|\u0010\u0015\u001a\u00020\u00002\b\b\u0002\u0010\u000f\u001a\u00020\u00022\u0018\b\u0002\u0010\u0010\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u00062\u0018\b\u0002\u0010\u0011\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u00062\u0018\b\u0002\u0010\u0012\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u00062\b\b\u0002\u0010\u0013\u001a\u00020\u00022\b\b\u0002\u0010\u0014\u001a\u00020\fHÆ\u0001¢\u0006\u0004\b\u0015\u0010\u0016J\u0010\u0010\u0017\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\u0017\u0010\u0004J\u0010\u0010\u0018\u001a\u00020\fHÖ\u0001¢\u0006\u0004\b\u0018\u0010\u000eJ\u001a\u0010\u001b\u001a\u00020\u001a2\b\u0010\u0019\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u001b\u0010\u001cR)\u0010\u0010\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u001d\u001a\u0004\b\u001e\u0010\bR)\u0010\u0011\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\u0011\u0010\u001d\u001a\u0004\b\u001f\u0010\bR\u0019\u0010\u0013\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0013\u0010 \u001a\u0004\b!\u0010\u0004R\u0019\u0010\u000f\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000f\u0010 \u001a\u0004\b\"\u0010\u0004R\u0019\u0010\u0014\u001a\u00020\f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0014\u0010#\u001a\u0004\b$\u0010\u000eR)\u0010\u0012\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0005j\b\u0012\u0004\u0012\u00020\u0002`\u00068\u0006@\u0006¢\u0006\f\n\u0004\b\u0012\u0010\u001d\u001a\u0004\b%\u0010\b¨\u0006("}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/NewTradeBean;", "", "", "component1", "()Ljava/lang/String;", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "component2", "()Ljava/util/ArrayList;", "component3", "component4", "component5", "", "component6", "()I", "content", "topics", "img", "video", "type", "deposit", "copy", "(Ljava/lang/String;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/lang/String;I)Lcom/jbzd/media/movecartoons/bean/response/NewTradeBean;", "toString", "hashCode", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/util/ArrayList;", "getTopics", "getImg", "Ljava/lang/String;", "getType", "getContent", "I", "getDeposit", "getVideo", "<init>", "(Ljava/lang/String;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/lang/String;I)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class NewTradeBean {

    @NotNull
    private final String content;
    private final int deposit;

    @NotNull
    private final ArrayList<String> img;

    @NotNull
    private final ArrayList<String> topics;

    @NotNull
    private final String type;

    @NotNull
    private final ArrayList<String> video;

    public NewTradeBean(@NotNull String content, @NotNull ArrayList<String> topics, @NotNull ArrayList<String> img, @NotNull ArrayList<String> video, @NotNull String type, int i2) {
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(topics, "topics");
        Intrinsics.checkNotNullParameter(img, "img");
        Intrinsics.checkNotNullParameter(video, "video");
        Intrinsics.checkNotNullParameter(type, "type");
        this.content = content;
        this.topics = topics;
        this.img = img;
        this.video = video;
        this.type = type;
        this.deposit = i2;
    }

    public static /* synthetic */ NewTradeBean copy$default(NewTradeBean newTradeBean, String str, ArrayList arrayList, ArrayList arrayList2, ArrayList arrayList3, String str2, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            str = newTradeBean.content;
        }
        if ((i3 & 2) != 0) {
            arrayList = newTradeBean.topics;
        }
        ArrayList arrayList4 = arrayList;
        if ((i3 & 4) != 0) {
            arrayList2 = newTradeBean.img;
        }
        ArrayList arrayList5 = arrayList2;
        if ((i3 & 8) != 0) {
            arrayList3 = newTradeBean.video;
        }
        ArrayList arrayList6 = arrayList3;
        if ((i3 & 16) != 0) {
            str2 = newTradeBean.type;
        }
        String str3 = str2;
        if ((i3 & 32) != 0) {
            i2 = newTradeBean.deposit;
        }
        return newTradeBean.copy(str, arrayList4, arrayList5, arrayList6, str3, i2);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getContent() {
        return this.content;
    }

    @NotNull
    public final ArrayList<String> component2() {
        return this.topics;
    }

    @NotNull
    public final ArrayList<String> component3() {
        return this.img;
    }

    @NotNull
    public final ArrayList<String> component4() {
        return this.video;
    }

    @NotNull
    /* renamed from: component5, reason: from getter */
    public final String getType() {
        return this.type;
    }

    /* renamed from: component6, reason: from getter */
    public final int getDeposit() {
        return this.deposit;
    }

    @NotNull
    public final NewTradeBean copy(@NotNull String content, @NotNull ArrayList<String> topics, @NotNull ArrayList<String> img, @NotNull ArrayList<String> video, @NotNull String type, int deposit) {
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(topics, "topics");
        Intrinsics.checkNotNullParameter(img, "img");
        Intrinsics.checkNotNullParameter(video, "video");
        Intrinsics.checkNotNullParameter(type, "type");
        return new NewTradeBean(content, topics, img, video, type, deposit);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof NewTradeBean)) {
            return false;
        }
        NewTradeBean newTradeBean = (NewTradeBean) other;
        return Intrinsics.areEqual(this.content, newTradeBean.content) && Intrinsics.areEqual(this.topics, newTradeBean.topics) && Intrinsics.areEqual(this.img, newTradeBean.img) && Intrinsics.areEqual(this.video, newTradeBean.video) && Intrinsics.areEqual(this.type, newTradeBean.type) && this.deposit == newTradeBean.deposit;
    }

    @NotNull
    public final String getContent() {
        return this.content;
    }

    public final int getDeposit() {
        return this.deposit;
    }

    @NotNull
    public final ArrayList<String> getImg() {
        return this.img;
    }

    @NotNull
    public final ArrayList<String> getTopics() {
        return this.topics;
    }

    @NotNull
    public final String getType() {
        return this.type;
    }

    @NotNull
    public final ArrayList<String> getVideo() {
        return this.video;
    }

    public int hashCode() {
        return C1499a.m598T(this.type, (this.video.hashCode() + ((this.img.hashCode() + ((this.topics.hashCode() + (this.content.hashCode() * 31)) * 31)) * 31)) * 31, 31) + this.deposit;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("NewTradeBean(content=");
        m586H.append(this.content);
        m586H.append(", topics=");
        m586H.append(this.topics);
        m586H.append(", img=");
        m586H.append(this.img);
        m586H.append(", video=");
        m586H.append(this.video);
        m586H.append(", type=");
        m586H.append(this.type);
        m586H.append(", deposit=");
        return C1499a.m579A(m586H, this.deposit, ')');
    }
}
