package com.facebook.react.views.text;

import java.text.BreakIterator;
import java.util.Locale;

/* JADX INFO: loaded from: classes.dex */
public abstract class u {

    public /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f8185a;

        static {
            int[] iArr = new int[t.values().length];
            try {
                iArr[t.f8179d.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[t.f8180e.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[t.f8181f.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            f8185a = iArr;
        }
    }

    public static final String a(String str, t tVar) {
        t2.j.f(str, "<this>");
        int i3 = tVar == null ? -1 : a.f8185a[tVar.ordinal()];
        if (i3 == 1) {
            Locale locale = Locale.getDefault();
            t2.j.e(locale, "getDefault(...)");
            String upperCase = str.toUpperCase(locale);
            t2.j.e(upperCase, "toUpperCase(...)");
            return upperCase;
        }
        if (i3 == 2) {
            Locale locale2 = Locale.getDefault();
            t2.j.e(locale2, "getDefault(...)");
            String lowerCase = str.toLowerCase(locale2);
            t2.j.e(lowerCase, "toLowerCase(...)");
            return lowerCase;
        }
        if (i3 != 3) {
            return str;
        }
        BreakIterator wordInstance = BreakIterator.getWordInstance();
        wordInstance.setText(str);
        StringBuilder sb = new StringBuilder(str.length());
        int iFirst = wordInstance.first();
        int next = wordInstance.next();
        while (true) {
            int i4 = next;
            int i5 = iFirst;
            iFirst = i4;
            if (iFirst == -1) {
                String string = sb.toString();
                t2.j.c(string);
                return string;
            }
            String strSubstring = str.substring(i5, iFirst);
            t2.j.e(strSubstring, "substring(...)");
            if (strSubstring.length() > 0) {
                char upperCase2 = Character.toUpperCase(strSubstring.charAt(0));
                String strSubstring2 = strSubstring.substring(1);
                t2.j.e(strSubstring2, "substring(...)");
                strSubstring = upperCase2 + strSubstring2;
            }
            sb.append(strSubstring);
            next = wordInstance.next();
        }
    }
}
