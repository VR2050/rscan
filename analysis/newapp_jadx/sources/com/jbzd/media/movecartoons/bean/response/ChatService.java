package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\t\n\u0002\u0010\b\n\u0002\b\r\b\u0086\b\u0018\u00002\u00020\u0001B5\u0012\n\b\u0002\u0010\n\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u0002\u0012\n\b\u0002\u0010\f\u001a\u0004\u0018\u00010\u0002\u0012\b\b\u0002\u0010\r\u001a\u00020\u0007¢\u0006\u0004\b\u001c\u0010\u001dJ\u0012\u0010\u0003\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0012\u0010\u0005\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J\u0012\u0010\u0006\u001a\u0004\u0018\u00010\u0002HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0004J\u0010\u0010\b\u001a\u00020\u0007HÆ\u0003¢\u0006\u0004\b\b\u0010\tJ>\u0010\u000e\u001a\u00020\u00002\n\b\u0002\u0010\n\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\u000b\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\f\u001a\u0004\u0018\u00010\u00022\b\b\u0002\u0010\r\u001a\u00020\u0007HÆ\u0001¢\u0006\u0004\b\u000e\u0010\u000fJ\u0010\u0010\u0010\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\u0010\u0010\u0004J\u0010\u0010\u0012\u001a\u00020\u0011HÖ\u0001¢\u0006\u0004\b\u0012\u0010\u0013J\u001a\u0010\u0015\u001a\u00020\u00072\b\u0010\u0014\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0015\u0010\u0016R\u001b\u0010\u000b\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\u0017\u001a\u0004\b\u0018\u0010\u0004R\u0019\u0010\r\u001a\u00020\u00078\u0006@\u0006¢\u0006\f\n\u0004\b\r\u0010\u0019\u001a\u0004\b\r\u0010\tR\u001b\u0010\f\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\f\u0010\u0017\u001a\u0004\b\u001a\u0010\u0004R\u001b\u0010\n\u001a\u0004\u0018\u00010\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\n\u0010\u0017\u001a\u0004\b\u001b\u0010\u0004¨\u0006\u001e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/ChatService;", "", "", "component1", "()Ljava/lang/String;", "component2", "component3", "", "component4", "()Z", "id", "name", "price", "is_required", "copy", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Lcom/jbzd/media/movecartoons/bean/response/ChatService;", "toString", "", "hashCode", "()I", "other", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getName", "Z", "getPrice", "getId", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class ChatService {

    @Nullable
    private final String id;
    private final boolean is_required;

    @Nullable
    private final String name;

    @Nullable
    private final String price;

    public ChatService() {
        this(null, null, null, false, 15, null);
    }

    public ChatService(@Nullable String str, @Nullable String str2, @Nullable String str3, boolean z) {
        this.id = str;
        this.name = str2;
        this.price = str3;
        this.is_required = z;
    }

    public static /* synthetic */ ChatService copy$default(ChatService chatService, String str, String str2, String str3, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = chatService.id;
        }
        if ((i2 & 2) != 0) {
            str2 = chatService.name;
        }
        if ((i2 & 4) != 0) {
            str3 = chatService.price;
        }
        if ((i2 & 8) != 0) {
            z = chatService.is_required;
        }
        return chatService.copy(str, str2, str3, z);
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
    public final String getPrice() {
        return this.price;
    }

    /* renamed from: component4, reason: from getter */
    public final boolean getIs_required() {
        return this.is_required;
    }

    @NotNull
    public final ChatService copy(@Nullable String id, @Nullable String name, @Nullable String price, boolean is_required) {
        return new ChatService(id, name, price, is_required);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof ChatService)) {
            return false;
        }
        ChatService chatService = (ChatService) other;
        return Intrinsics.areEqual(this.id, chatService.id) && Intrinsics.areEqual(this.name, chatService.name) && Intrinsics.areEqual(this.price, chatService.price) && this.is_required == chatService.is_required;
    }

    @Nullable
    public final String getId() {
        return this.id;
    }

    @Nullable
    public final String getName() {
        return this.name;
    }

    @Nullable
    public final String getPrice() {
        return this.price;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int hashCode() {
        String str = this.id;
        int hashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.name;
        int hashCode2 = (hashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.price;
        int hashCode3 = (hashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31;
        boolean z = this.is_required;
        int i2 = z;
        if (z != 0) {
            i2 = 1;
        }
        return hashCode3 + i2;
    }

    public final boolean is_required() {
        return this.is_required;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("ChatService(id=");
        m586H.append((Object) this.id);
        m586H.append(", name=");
        m586H.append((Object) this.name);
        m586H.append(", price=");
        m586H.append((Object) this.price);
        m586H.append(", is_required=");
        m586H.append(this.is_required);
        m586H.append(')');
        return m586H.toString();
    }

    public /* synthetic */ ChatService(String str, String str2, String str3, boolean z, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? "" : str, (i2 & 2) != 0 ? "" : str2, (i2 & 4) != 0 ? "" : str3, (i2 & 8) != 0 ? false : z);
    }
}
