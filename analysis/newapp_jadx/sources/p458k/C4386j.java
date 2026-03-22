package p458k;

import com.alibaba.fastjson.asm.Opcodes;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.TypeCastException;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.conscrypt.NativeCrypto;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: k.j */
/* loaded from: classes3.dex */
public final class C4386j {

    /* renamed from: a */
    @NotNull
    public static final Comparator<String> f11463a;

    /* renamed from: b */
    public static final Map<String, C4386j> f11464b;

    /* renamed from: c */
    @JvmField
    @NotNull
    public static final C4386j f11465c;

    /* renamed from: d */
    @JvmField
    @NotNull
    public static final C4386j f11466d;

    /* renamed from: e */
    @JvmField
    @NotNull
    public static final C4386j f11467e;

    /* renamed from: f */
    @JvmField
    @NotNull
    public static final C4386j f11468f;

    /* renamed from: g */
    @JvmField
    @NotNull
    public static final C4386j f11469g;

    /* renamed from: h */
    @JvmField
    @NotNull
    public static final C4386j f11470h;

    /* renamed from: i */
    @JvmField
    @NotNull
    public static final C4386j f11471i;

    /* renamed from: j */
    @JvmField
    @NotNull
    public static final C4386j f11472j;

    /* renamed from: k */
    @JvmField
    @NotNull
    public static final C4386j f11473k;

    /* renamed from: l */
    @JvmField
    @NotNull
    public static final C4386j f11474l;

    /* renamed from: m */
    @JvmField
    @NotNull
    public static final C4386j f11475m;

    /* renamed from: n */
    @JvmField
    @NotNull
    public static final C4386j f11476n;

    /* renamed from: o */
    @JvmField
    @NotNull
    public static final C4386j f11477o;

    /* renamed from: p */
    @JvmField
    @NotNull
    public static final C4386j f11478p;

    /* renamed from: q */
    @JvmField
    @NotNull
    public static final C4386j f11479q;

    /* renamed from: r */
    @JvmField
    @NotNull
    public static final C4386j f11480r;

    /* renamed from: s */
    public static final b f11481s;

    /* renamed from: t */
    @NotNull
    public final String f11482t;

    /* renamed from: k.j$a */
    public static final class a implements Comparator<String> {
        /* JADX WARN: Code restructure failed: missing block: B:9:0x002c, code lost:
        
            return 1;
         */
        @Override // java.util.Comparator
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public int compare(java.lang.String r7, java.lang.String r8) {
            /*
                r6 = this;
                java.lang.String r7 = (java.lang.String) r7
                java.lang.String r8 = (java.lang.String) r8
                java.lang.String r0 = "a"
                kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r7, r0)
                java.lang.String r0 = "b"
                kotlin.jvm.internal.Intrinsics.checkParameterIsNotNull(r8, r0)
                int r0 = r7.length()
                int r1 = r8.length()
                int r0 = java.lang.Math.min(r0, r1)
                r1 = 4
            L1b:
                r2 = -1
                r3 = 1
                if (r1 >= r0) goto L31
                char r4 = r7.charAt(r1)
                char r5 = r8.charAt(r1)
                if (r4 == r5) goto L2e
                if (r4 >= r5) goto L2c
                goto L3f
            L2c:
                r2 = 1
                goto L3f
            L2e:
                int r1 = r1 + 1
                goto L1b
            L31:
                int r7 = r7.length()
                int r8 = r8.length()
                if (r7 == r8) goto L3e
                if (r7 >= r8) goto L2c
                goto L3f
            L3e:
                r2 = 0
            L3f:
                return r2
            */
            throw new UnsupportedOperationException("Method not decompiled: p458k.C4386j.a.compare(java.lang.Object, java.lang.Object):int");
        }
    }

    /* renamed from: k.j$b */
    public static final class b {
        public b(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: a */
        public static final C4386j m4983a(b bVar, String str, int i2) {
            C4386j c4386j = new C4386j(str, null);
            C4386j.f11464b.put(str, c4386j);
            return c4386j;
        }

        @JvmStatic
        @NotNull
        /* renamed from: b */
        public final synchronized C4386j m4984b(@NotNull String javaName) {
            C4386j c4386j;
            Intrinsics.checkParameterIsNotNull(javaName, "javaName");
            Map<String, C4386j> map = C4386j.f11464b;
            c4386j = map.get(javaName);
            if (c4386j == null) {
                c4386j = map.get(m4985c(javaName));
                if (c4386j == null) {
                    c4386j = new C4386j(javaName, null);
                }
                map.put(javaName, c4386j);
            }
            return c4386j;
        }

        /* renamed from: c */
        public final String m4985c(String str) {
            if (StringsKt__StringsJVMKt.startsWith$default(str, "TLS_", false, 2, null)) {
                StringBuilder m586H = C1499a.m586H("SSL_");
                if (str == null) {
                    throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
                }
                String substring = str.substring(4);
                Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.String).substring(startIndex)");
                m586H.append(substring);
                return m586H.toString();
            }
            if (!StringsKt__StringsJVMKt.startsWith$default(str, "SSL_", false, 2, null)) {
                return str;
            }
            StringBuilder m586H2 = C1499a.m586H("TLS_");
            if (str == null) {
                throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
            }
            String substring2 = str.substring(4);
            Intrinsics.checkExpressionValueIsNotNull(substring2, "(this as java.lang.String).substring(startIndex)");
            m586H2.append(substring2);
            return m586H2.toString();
        }
    }

    static {
        b bVar = new b(null);
        f11481s = bVar;
        f11463a = new a();
        f11464b = new LinkedHashMap();
        b.m4983a(bVar, "SSL_RSA_WITH_NULL_MD5", 1);
        b.m4983a(bVar, "SSL_RSA_WITH_NULL_SHA", 2);
        b.m4983a(bVar, "SSL_RSA_EXPORT_WITH_RC4_40_MD5", 3);
        b.m4983a(bVar, "SSL_RSA_WITH_RC4_128_MD5", 4);
        b.m4983a(bVar, "SSL_RSA_WITH_RC4_128_SHA", 5);
        b.m4983a(bVar, "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", 8);
        b.m4983a(bVar, "SSL_RSA_WITH_DES_CBC_SHA", 9);
        f11465c = b.m4983a(bVar, "SSL_RSA_WITH_3DES_EDE_CBC_SHA", 10);
        b.m4983a(bVar, "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", 17);
        b.m4983a(bVar, "SSL_DHE_DSS_WITH_DES_CBC_SHA", 18);
        b.m4983a(bVar, "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 19);
        b.m4983a(bVar, "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", 20);
        b.m4983a(bVar, "SSL_DHE_RSA_WITH_DES_CBC_SHA", 21);
        b.m4983a(bVar, "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 22);
        b.m4983a(bVar, "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5", 23);
        b.m4983a(bVar, "SSL_DH_anon_WITH_RC4_128_MD5", 24);
        b.m4983a(bVar, "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA", 25);
        b.m4983a(bVar, "SSL_DH_anon_WITH_DES_CBC_SHA", 26);
        b.m4983a(bVar, "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA", 27);
        b.m4983a(bVar, "TLS_KRB5_WITH_DES_CBC_SHA", 30);
        b.m4983a(bVar, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", 31);
        b.m4983a(bVar, "TLS_KRB5_WITH_RC4_128_SHA", 32);
        b.m4983a(bVar, "TLS_KRB5_WITH_DES_CBC_MD5", 34);
        b.m4983a(bVar, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", 35);
        b.m4983a(bVar, "TLS_KRB5_WITH_RC4_128_MD5", 36);
        b.m4983a(bVar, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", 38);
        b.m4983a(bVar, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", 40);
        b.m4983a(bVar, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", 41);
        b.m4983a(bVar, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", 43);
        f11466d = b.m4983a(bVar, "TLS_RSA_WITH_AES_128_CBC_SHA", 47);
        b.m4983a(bVar, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 50);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 51);
        b.m4983a(bVar, "TLS_DH_anon_WITH_AES_128_CBC_SHA", 52);
        f11467e = b.m4983a(bVar, "TLS_RSA_WITH_AES_256_CBC_SHA", 53);
        b.m4983a(bVar, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 56);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 57);
        b.m4983a(bVar, "TLS_DH_anon_WITH_AES_256_CBC_SHA", 58);
        b.m4983a(bVar, "TLS_RSA_WITH_NULL_SHA256", 59);
        b.m4983a(bVar, "TLS_RSA_WITH_AES_128_CBC_SHA256", 60);
        b.m4983a(bVar, "TLS_RSA_WITH_AES_256_CBC_SHA256", 61);
        b.m4983a(bVar, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", 64);
        b.m4983a(bVar, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 65);
        b.m4983a(bVar, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", 68);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 69);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 103);
        b.m4983a(bVar, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 106);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 107);
        b.m4983a(bVar, "TLS_DH_anon_WITH_AES_128_CBC_SHA256", 108);
        b.m4983a(bVar, "TLS_DH_anon_WITH_AES_256_CBC_SHA256", 109);
        b.m4983a(bVar, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 132);
        b.m4983a(bVar, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", 135);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", 136);
        b.m4983a(bVar, "TLS_PSK_WITH_RC4_128_SHA", 138);
        b.m4983a(bVar, "TLS_PSK_WITH_3DES_EDE_CBC_SHA", 139);
        b.m4983a(bVar, "TLS_PSK_WITH_AES_128_CBC_SHA", 140);
        b.m4983a(bVar, "TLS_PSK_WITH_AES_256_CBC_SHA", 141);
        b.m4983a(bVar, "TLS_RSA_WITH_SEED_CBC_SHA", 150);
        f11468f = b.m4983a(bVar, "TLS_RSA_WITH_AES_128_GCM_SHA256", 156);
        f11469g = b.m4983a(bVar, "TLS_RSA_WITH_AES_256_GCM_SHA384", 157);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", Opcodes.IFLE);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", Opcodes.IF_ICMPEQ);
        b.m4983a(bVar, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", Opcodes.IF_ICMPGE);
        b.m4983a(bVar, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", Opcodes.IF_ICMPGT);
        b.m4983a(bVar, "TLS_DH_anon_WITH_AES_128_GCM_SHA256", 166);
        b.m4983a(bVar, "TLS_DH_anon_WITH_AES_256_GCM_SHA384", Opcodes.GOTO);
        b.m4983a(bVar, NativeCrypto.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, 255);
        b.m4983a(bVar, "TLS_FALLBACK_SCSV", 22016);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_NULL_SHA", 49153);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", 49154);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", 49155);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 49156);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", 49157);
        b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 49158);
        b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 49159);
        b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 49160);
        b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 49161);
        b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 49162);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_NULL_SHA", 49163);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_RC4_128_SHA", 49164);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", 49165);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", 49166);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", 49167);
        b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_NULL_SHA", 49168);
        b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 49169);
        b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 49170);
        f11470h = b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 49171);
        f11471i = b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 49172);
        b.m4983a(bVar, "TLS_ECDH_anon_WITH_NULL_SHA", 49173);
        b.m4983a(bVar, "TLS_ECDH_anon_WITH_RC4_128_SHA", 49174);
        b.m4983a(bVar, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", 49175);
        b.m4983a(bVar, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 49176);
        b.m4983a(bVar, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", 49177);
        b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 49187);
        b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 49188);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 49189);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", 49190);
        b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 49191);
        b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 49192);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 49193);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", 49194);
        f11472j = b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 49195);
        f11473k = b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 49196);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 49197);
        b.m4983a(bVar, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", 49198);
        f11474l = b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 49199);
        f11475m = b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 49200);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", 49201);
        b.m4983a(bVar, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", 49202);
        b.m4983a(bVar, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", 49205);
        b.m4983a(bVar, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", 49206);
        f11476n = b.m4983a(bVar, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 52392);
        f11477o = b.m4983a(bVar, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 52393);
        b.m4983a(bVar, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 52394);
        b.m4983a(bVar, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", 52396);
        f11478p = b.m4983a(bVar, "TLS_AES_128_GCM_SHA256", 4865);
        f11479q = b.m4983a(bVar, "TLS_AES_256_GCM_SHA384", 4866);
        f11480r = b.m4983a(bVar, "TLS_CHACHA20_POLY1305_SHA256", 4867);
        b.m4983a(bVar, "TLS_AES_128_CCM_SHA256", 4868);
        b.m4983a(bVar, "TLS_AES_128_CCM_8_SHA256", 4869);
    }

    public C4386j(String str, DefaultConstructorMarker defaultConstructorMarker) {
        this.f11482t = str;
    }

    @NotNull
    public String toString() {
        return this.f11482t;
    }
}
