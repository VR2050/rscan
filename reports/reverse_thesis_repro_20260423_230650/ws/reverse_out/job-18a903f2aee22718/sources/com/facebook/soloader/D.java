package com.facebook.soloader;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* JADX INFO: loaded from: classes.dex */
public abstract class D {
    private static boolean a(String str) {
        Matcher matcher = Pattern.compile("\\P{ASCII}+").matcher(str);
        if (!matcher.find()) {
            return false;
        }
        p.g("SoLoader", "Library name is corrupted, contains non-ASCII characters " + matcher.group());
        return true;
    }

    public static C b(String str, UnsatisfiedLinkError unsatisfiedLinkError) {
        C c3;
        if (unsatisfiedLinkError.getMessage() != null && unsatisfiedLinkError.getMessage().contains("ELF")) {
            p.a("SoLoader", "Corrupted lib file detected");
            c3 = new z(str, unsatisfiedLinkError.toString());
        } else if (a(str)) {
            p.a("SoLoader", "Corrupted lib name detected");
            c3 = new A(str, "corrupted lib name: " + unsatisfiedLinkError.toString());
        } else {
            c3 = new C(str, unsatisfiedLinkError.toString());
        }
        c3.initCause(unsatisfiedLinkError);
        return c3;
    }
}
