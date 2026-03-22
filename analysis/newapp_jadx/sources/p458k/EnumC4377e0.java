package p458k;

import org.jetbrains.annotations.NotNull;

/* renamed from: k.e0 */
/* loaded from: classes3.dex */
public enum EnumC4377e0 {
    HTTP_1_0("http/1.0"),
    HTTP_1_1("http/1.1"),
    SPDY_3("spdy/3.1"),
    HTTP_2("h2"),
    H2_PRIOR_KNOWLEDGE("h2_prior_knowledge"),
    QUIC("quic");


    /* renamed from: k */
    public static final a f11429k = new Object(null) { // from class: k.e0.a
    };

    /* renamed from: l */
    public final String f11430l;

    EnumC4377e0(String str) {
        this.f11430l = str;
    }

    @Override // java.lang.Enum
    @NotNull
    public String toString() {
        return this.f11430l;
    }
}
