package p429g.p430a.p431a.p432a;

import kotlin.jvm.internal.Intrinsics;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: g.a.a.a.a */
/* loaded from: classes2.dex */
public final class C4326a {

    /* renamed from: a */
    public int f11172a;

    /* renamed from: b */
    public int f11173b;

    /* renamed from: c */
    @NotNull
    public final String f11174c;

    /* renamed from: d */
    @NotNull
    public final String f11175d;

    /* renamed from: e */
    @NotNull
    public final AbstractC4331f f11176e;

    public C4326a(int i2, int i3, @NotNull String originalText, @NotNull String transformedText, @NotNull AbstractC4331f mode) {
        Intrinsics.checkNotNullParameter(originalText, "originalText");
        Intrinsics.checkNotNullParameter(transformedText, "transformedText");
        Intrinsics.checkNotNullParameter(mode, "mode");
        this.f11172a = i2;
        this.f11173b = i3;
        this.f11174c = originalText;
        this.f11175d = transformedText;
        this.f11176e = mode;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4326a)) {
            return false;
        }
        C4326a c4326a = (C4326a) obj;
        return this.f11172a == c4326a.f11172a && this.f11173b == c4326a.f11173b && Intrinsics.areEqual(this.f11174c, c4326a.f11174c) && Intrinsics.areEqual(this.f11175d, c4326a.f11175d) && Intrinsics.areEqual(this.f11176e, c4326a.f11176e);
    }

    public int hashCode() {
        int i2 = ((this.f11172a * 31) + this.f11173b) * 31;
        String str = this.f11174c;
        int hashCode = (i2 + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f11175d;
        int hashCode2 = (hashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        AbstractC4331f abstractC4331f = this.f11176e;
        return hashCode2 + (abstractC4331f != null ? abstractC4331f.hashCode() : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("AutoLinkItem(startPoint=");
        m586H.append(this.f11172a);
        m586H.append(", endPoint=");
        m586H.append(this.f11173b);
        m586H.append(", originalText=");
        m586H.append(this.f11174c);
        m586H.append(", transformedText=");
        m586H.append(this.f11175d);
        m586H.append(", mode=");
        m586H.append(this.f11176e);
        m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m586H.toString();
    }
}
