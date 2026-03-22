package p458k;

import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.conscrypt.NativeCrypto;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: k.o0 */
/* loaded from: classes3.dex */
public enum EnumC4397o0 {
    TLS_1_3(NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3),
    TLS_1_2("TLSv1.2"),
    TLS_1_1("TLSv1.1"),
    TLS_1_0("TLSv1"),
    SSL_3_0(NativeCrypto.OBSOLETE_PROTOCOL_SSLV3);


    /* renamed from: j */
    public static final a f11537j = new a(null);

    /* renamed from: k */
    @NotNull
    public final String f11538k;

    /* renamed from: k.o0$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
        @JvmStatic
        @NotNull
        /* renamed from: a */
        public final EnumC4397o0 m5012a(@NotNull String javaName) {
            Intrinsics.checkParameterIsNotNull(javaName, "javaName");
            int hashCode = javaName.hashCode();
            if (hashCode != 79201641) {
                if (hashCode != 79923350) {
                    switch (hashCode) {
                        case -503070503:
                            if (javaName.equals("TLSv1.1")) {
                                return EnumC4397o0.TLS_1_1;
                            }
                            break;
                        case -503070502:
                            if (javaName.equals("TLSv1.2")) {
                                return EnumC4397o0.TLS_1_2;
                            }
                            break;
                        case -503070501:
                            if (javaName.equals(NativeCrypto.SUPPORTED_PROTOCOL_TLSV1_3)) {
                                return EnumC4397o0.TLS_1_3;
                            }
                            break;
                    }
                } else if (javaName.equals("TLSv1")) {
                    return EnumC4397o0.TLS_1_0;
                }
            } else if (javaName.equals(NativeCrypto.OBSOLETE_PROTOCOL_SSLV3)) {
                return EnumC4397o0.SSL_3_0;
            }
            throw new IllegalArgumentException(C1499a.m637w("Unexpected TLS version: ", javaName));
        }
    }

    EnumC4397o0(String str) {
        this.f11538k = str;
    }
}
