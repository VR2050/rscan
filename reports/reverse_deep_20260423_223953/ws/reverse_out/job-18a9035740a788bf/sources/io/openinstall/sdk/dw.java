package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class dw {
    public static String a(String str) {
        try {
            return new String(bt.c().a(str), bu.c);
        } catch (Exception e) {
            return str;
        }
    }

    public static String b(String str) {
        try {
            return new String(bt.d().a(str), bu.c);
        } catch (Exception e) {
            return str;
        }
    }

    public static String c(String str) {
        try {
            return new String(bt.a().a(str.getBytes(bu.c)), bu.c);
        } catch (Exception e) {
            return str;
        }
    }
}
