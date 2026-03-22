package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\u0012\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0019\u0010\u001aR\"\u0010\u0003\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0003\u0010\u0004\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR$\u0010\n\u001a\u0004\u0018\u00010\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR$\u0010\u0010\u001a\u0004\u0018\u00010\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0010\u0010\u000b\u001a\u0004\b\u0011\u0010\r\"\u0004\b\u0012\u0010\u000fR$\u0010\u0013\u001a\u0004\u0018\u00010\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0013\u0010\u000b\u001a\u0004\b\u0014\u0010\r\"\u0004\b\u0015\u0010\u000fR$\u0010\u0016\u001a\u0004\u0018\u00010\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0016\u0010\u000b\u001a\u0004\b\u0017\u0010\r\"\u0004\b\u0018\u0010\u000f¨\u0006\u001b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/VideoCollectionBean;", "", "", "type", "I", "getType", "()I", "setType", "(I)V", "", "img", "Ljava/lang/String;", "getImg", "()Ljava/lang/String;", "setImg", "(Ljava/lang/String;)V", "id", "getId", "setId", "name", "getName", "setName", "duration", "getDuration", "setDuration", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class VideoCollectionBean {

    @Nullable
    private String duration;

    @Nullable
    private String id;

    @Nullable
    private String img;

    @Nullable
    private String name;
    private int type;

    @Nullable
    public final String getDuration() {
        return this.duration;
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

    public final int getType() {
        return this.type;
    }

    public final void setDuration(@Nullable String str) {
        this.duration = str;
    }

    public final void setId(@Nullable String str) {
        this.id = str;
    }

    public final void setImg(@Nullable String str) {
        this.img = str;
    }

    public final void setName(@Nullable String str) {
        this.name = str;
    }

    public final void setType(int i2) {
        this.type = i2;
    }
}
