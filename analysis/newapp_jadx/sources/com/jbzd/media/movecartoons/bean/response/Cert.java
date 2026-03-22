package com.jbzd.media.movecartoons.bean.response;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\b\b\u0086\b\u0018\u00002\u00020\u0001B\u001b\u0012\b\b\u0002\u0010\u0006\u001a\u00020\u0002\u0012\b\b\u0002\u0010\u0007\u001a\u00020\u0002¢\u0006\u0004\b\u0015\u0010\u0016J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0005\u0010\u0004J$\u0010\b\u001a\u00020\u00002\b\b\u0002\u0010\u0006\u001a\u00020\u00022\b\b\u0002\u0010\u0007\u001a\u00020\u0002HÆ\u0001¢\u0006\u0004\b\b\u0010\tJ\u0010\u0010\n\u001a\u00020\u0002HÖ\u0001¢\u0006\u0004\b\n\u0010\u0004J\u0010\u0010\f\u001a\u00020\u000bHÖ\u0001¢\u0006\u0004\b\f\u0010\rJ\u001a\u0010\u0010\u001a\u00020\u000f2\b\u0010\u000e\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0010\u0010\u0011R\u0019\u0010\u0006\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0006\u0010\u0012\u001a\u0004\b\u0013\u0010\u0004R\u0019\u0010\u0007\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0007\u0010\u0012\u001a\u0004\b\u0014\u0010\u0004¨\u0006\u0017"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/bean/response/Cert;", "", "", "component1", "()Ljava/lang/String;", "component2", "label", "desc", "copy", "(Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/bean/response/Cert;", "toString", "", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "Ljava/lang/String;", "getLabel", "getDesc", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class Cert {

    @NotNull
    private final String desc;

    @NotNull
    private final String label;

    /* JADX WARN: Multi-variable type inference failed */
    public Cert() {
        this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
    }

    public Cert(@NotNull String label, @NotNull String desc) {
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(desc, "desc");
        this.label = label;
        this.desc = desc;
    }

    public static /* synthetic */ Cert copy$default(Cert cert, String str, String str2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            str = cert.label;
        }
        if ((i2 & 2) != 0) {
            str2 = cert.desc;
        }
        return cert.copy(str, str2);
    }

    @NotNull
    /* renamed from: component1, reason: from getter */
    public final String getLabel() {
        return this.label;
    }

    @NotNull
    /* renamed from: component2, reason: from getter */
    public final String getDesc() {
        return this.desc;
    }

    @NotNull
    public final Cert copy(@NotNull String label, @NotNull String desc) {
        Intrinsics.checkNotNullParameter(label, "label");
        Intrinsics.checkNotNullParameter(desc, "desc");
        return new Cert(label, desc);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Cert)) {
            return false;
        }
        Cert cert = (Cert) other;
        return Intrinsics.areEqual(this.label, cert.label) && Intrinsics.areEqual(this.desc, cert.desc);
    }

    @NotNull
    public final String getDesc() {
        return this.desc;
    }

    @NotNull
    public final String getLabel() {
        return this.label;
    }

    public int hashCode() {
        return this.desc.hashCode() + (this.label.hashCode() * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Cert(label=");
        m586H.append(this.label);
        m586H.append(", desc=");
        return C1499a.m581C(m586H, this.desc, ')');
    }

    public /* synthetic */ Cert(String str, String str2, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? "" : str, (i2 & 2) != 0 ? "" : str2);
    }
}
