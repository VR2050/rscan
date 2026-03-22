package p005b.p113c0.p114a.p124i;

import java.util.Locale;

/* renamed from: b.c0.a.i.b */
/* loaded from: classes2.dex */
public enum EnumC1456b {
    GET("GET"),
    HEAD("HEAD"),
    POST("POST"),
    PUT("PUT"),
    PATCH("PATCH"),
    DELETE("DELETE"),
    OPTIONS("OPTIONS"),
    TRACE("TRACE");


    /* renamed from: m */
    public String f1418m;

    EnumC1456b(String str) {
        this.f1418m = str;
    }

    /* renamed from: b */
    public static EnumC1456b m520b(String str) {
        String upperCase;
        upperCase = str.toUpperCase(Locale.ENGLISH);
        upperCase.hashCode();
        switch (upperCase) {
            case "OPTIONS":
                return OPTIONS;
            case "GET":
                return GET;
            case "PUT":
                return PUT;
            case "HEAD":
                return HEAD;
            case "POST":
                return POST;
            case "PATCH":
                return PATCH;
            case "TRACE":
                return TRACE;
            case "DELETE":
                return DELETE;
            default:
                throw new UnsupportedOperationException(String.format("The value %1$s is not supported.", upperCase));
        }
    }

    /* renamed from: a */
    public boolean m521a() {
        int ordinal = ordinal();
        return ordinal == 2 || ordinal == 3 || ordinal == 4 || ordinal == 5;
    }

    @Override // java.lang.Enum
    public String toString() {
        return this.f1418m;
    }
}
