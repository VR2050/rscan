package com.facebook.hermes.intl;

import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public abstract class g {

    public enum a {
        BOOLEAN,
        STRING
    }

    public static Object a(String str, Object obj, Object obj2, Object obj3, Object obj4) throws A0.e {
        if (A0.d.n(obj)) {
            return obj4;
        }
        if (!A0.d.k(obj)) {
            throw new A0.e(str + " value is invalid.");
        }
        double dF = A0.d.f(obj);
        if (!Double.isNaN(dF) && dF <= A0.d.f(obj3) && dF >= A0.d.f(obj2)) {
            return obj;
        }
        throw new A0.e(str + " value is invalid.");
    }

    public static Object b(Object obj, String str, Object obj2, Object obj3, Object obj4) {
        return a(str, A0.d.a(obj, str), obj2, obj3, obj4);
    }

    public static Object c(Object obj, String str, a aVar, Object obj2, Object obj3) throws A0.e {
        Object objA = A0.d.a(obj, str);
        if (A0.d.n(objA)) {
            return obj3;
        }
        if (A0.d.j(objA)) {
            objA = "";
        }
        if (aVar == a.BOOLEAN && !A0.d.i(objA)) {
            throw new A0.e("Boolean option expected but not found");
        }
        if (aVar == a.STRING && !A0.d.m(objA)) {
            throw new A0.e("String option expected but not found");
        }
        if (A0.d.n(obj2) || Arrays.asList((Object[]) obj2).contains(objA)) {
            return objA;
        }
        throw new A0.e("String option expected but not found");
    }

    public static Enum d(Class cls, Object obj) {
        if (A0.d.n(obj)) {
            return Enum.valueOf(cls, "UNDEFINED");
        }
        if (A0.d.j(obj)) {
            return null;
        }
        String strH = A0.d.h(obj);
        if (strH.equals("2-digit")) {
            return Enum.valueOf(cls, "DIGIT2");
        }
        for (Enum r3 : (Enum[]) cls.getEnumConstants()) {
            if (r3.name().compareToIgnoreCase(strH) == 0) {
                return r3;
            }
        }
        return null;
    }
}
