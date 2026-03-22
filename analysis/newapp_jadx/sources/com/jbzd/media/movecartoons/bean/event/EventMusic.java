package com.jbzd.media.movecartoons.bean.event;

import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0010\u000b\n\u0002\b\u000b\b\u0086\b\u0018\u00002\u00020\u0001B+\u0012\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010\f\u001a\u0004\u0018\u00010\u0005\u0012\n\b\u0002\u0010\r\u001a\u0004\u0018\u00010\b¢\u0006\u0004\b\u001d\u0010\u001eJ\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0012\u0010\u0006\u001a\u0004\u0018\u00010\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J\u0012\u0010\t\u001a\u0004\u0018\u00010\bHÆ\u0003¢\u0006\u0004\b\t\u0010\nJ4\u0010\u000e\u001a\u00020\u00002\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\f\u001a\u0004\u0018\u00010\u00052\n\b\u0002\u0010\r\u001a\u0004\u0018\u00010\bHÆ\u0001¢\u0006\u0004\b\u000e\u0010\u000fJ\u0010\u0010\u0010\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\u0010\u0010\u0004J\u0010\u0010\u0011\u001a\u00020\u0005HÖ\u0001¢\u0006\u0004\b\u0011\u0010\u0012J\u001a\u0010\u0015\u001a\u00020\u00142\b\u0010\u0013\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0015\u0010\u0016R\u001b\u0010\u000b\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\u0017\u001a\u0004\b\u0018\u0010\u0004R\u001b\u0010\r\u001a\u0004\u0018\u00010\b8\u0006@\u0006¢\u0006\f\n\u0004\b\r\u0010\u0019\u001a\u0004\b\u001a\u0010\nR\u001b\u0010\f\u001a\u0004\u0018\u00010\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\f\u0010\u001b\u001a\u0004\b\u001c\u0010\u0007¨\u0006\u001f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/event/EventMusic;", "", "", "component1", "()Ljava/lang/String;", "", "component2", "()Ljava/lang/Integer;", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapter;", "component3", "()Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapter;", "type", "pos", "chapterListBean", "copy", "(Ljava/lang/String;Ljava/lang/Integer;Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapter;)Lcom/jbzd/media/movecartoons/bean/event/EventMusic;", "toString", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getType", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapter;", "getChapterListBean", "Ljava/lang/Integer;", "getPos", "<init>", "(Ljava/lang/String;Ljava/lang/Integer;Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapter;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class EventMusic {

    @Nullable
    private final NovelChapter chapterListBean;

    @Nullable
    private final Integer pos;

    @Nullable
    private final String type;

    public EventMusic() {
        this(null, null, null, 7, null);
    }

    public EventMusic(@Nullable String str, @Nullable Integer num, @Nullable NovelChapter novelChapter) {
        this.type = str;
        this.pos = num;
        this.chapterListBean = novelChapter;
    }

    public static /* synthetic */ EventMusic copy$default(EventMusic eventMusic, String str, Integer num, NovelChapter novelChapter, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = eventMusic.type;
        }
        if ((i2 & 2) != 0) {
            num = eventMusic.pos;
        }
        if ((i2 & 4) != 0) {
            novelChapter = eventMusic.chapterListBean;
        }
        return eventMusic.copy(str, num, novelChapter);
    }

    @Nullable
    /* renamed from: component1, reason: from getter */
    public final String getType() {
        return this.type;
    }

    @Nullable
    /* renamed from: component2, reason: from getter */
    public final Integer getPos() {
        return this.pos;
    }

    @Nullable
    /* renamed from: component3, reason: from getter */
    public final NovelChapter getChapterListBean() {
        return this.chapterListBean;
    }

    @NotNull
    public final EventMusic copy(@Nullable String type, @Nullable Integer pos, @Nullable NovelChapter chapterListBean) {
        return new EventMusic(type, pos, chapterListBean);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof EventMusic)) {
            return false;
        }
        EventMusic eventMusic = (EventMusic) other;
        return Intrinsics.areEqual(this.type, eventMusic.type) && Intrinsics.areEqual(this.pos, eventMusic.pos) && Intrinsics.areEqual(this.chapterListBean, eventMusic.chapterListBean);
    }

    @Nullable
    public final NovelChapter getChapterListBean() {
        return this.chapterListBean;
    }

    @Nullable
    public final Integer getPos() {
        return this.pos;
    }

    @Nullable
    public final String getType() {
        return this.type;
    }

    public int hashCode() {
        String str = this.type;
        int hashCode = (str == null ? 0 : str.hashCode()) * 31;
        Integer num = this.pos;
        int hashCode2 = (hashCode + (num == null ? 0 : num.hashCode())) * 31;
        NovelChapter novelChapter = this.chapterListBean;
        return hashCode2 + (novelChapter != null ? novelChapter.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("EventMusic(type=");
        m586H.append((Object) this.type);
        m586H.append(", pos=");
        m586H.append(this.pos);
        m586H.append(", chapterListBean=");
        m586H.append(this.chapterListBean);
        m586H.append(')');
        return m586H.toString();
    }

    public /* synthetic */ EventMusic(String str, Integer num, NovelChapter novelChapter, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? null : str, (i2 & 2) != 0 ? null : num, (i2 & 4) != 0 ? null : novelChapter);
    }
}
