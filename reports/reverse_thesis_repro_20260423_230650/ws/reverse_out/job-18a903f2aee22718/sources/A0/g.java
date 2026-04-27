package A0;

import android.icu.util.ULocale;
import android.text.TextUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
public class g implements b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private ULocale f23a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private ULocale.Builder f24b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f25c;

    private g(ULocale uLocale) {
        this.f24b = null;
        this.f25c = false;
        this.f23a = uLocale;
    }

    public static b i() {
        return new g(ULocale.getDefault(ULocale.Category.FORMAT));
    }

    public static b j(String str) {
        return new g(str);
    }

    public static b k(ULocale uLocale) {
        return new g(uLocale);
    }

    private void l() throws e {
        if (this.f25c) {
            try {
                this.f23a = this.f24b.build();
                this.f25c = false;
            } catch (RuntimeException e3) {
                throw new e(e3.getMessage());
            }
        }
    }

    @Override // A0.b
    public String a() {
        return h().toLanguageTag();
    }

    @Override // A0.b
    public HashMap b() throws e {
        l();
        HashMap map = new HashMap();
        Iterator<String> keywords = this.f23a.getKeywords();
        if (keywords != null) {
            while (keywords.hasNext()) {
                String next = keywords.next();
                map.put(i.b(next), this.f23a.getKeywordValue(next));
            }
        }
        return map;
    }

    @Override // A0.b
    public ArrayList c(String str) throws e {
        l();
        String strA = i.a(str);
        ArrayList arrayList = new ArrayList();
        String keywordValue = this.f23a.getKeywordValue(strA);
        if (keywordValue != null && !keywordValue.isEmpty()) {
            Collections.addAll(arrayList, keywordValue.split("-|_"));
        }
        return arrayList;
    }

    @Override // A0.b
    public b e() throws e {
        l();
        return new g(this.f23a);
    }

    @Override // A0.b
    public String f() {
        return d().toLanguageTag();
    }

    @Override // A0.b
    public void g(String str, ArrayList arrayList) throws e {
        l();
        if (this.f24b == null) {
            this.f24b = new ULocale.Builder().setLocale(this.f23a);
        }
        try {
            this.f24b.setUnicodeLocaleKeyword(str, TextUtils.join("-", arrayList));
            this.f25c = true;
        } catch (RuntimeException e3) {
            throw new e(e3.getMessage());
        }
    }

    @Override // A0.b
    /* JADX INFO: renamed from: m, reason: merged with bridge method [inline-methods] */
    public ULocale h() throws e {
        l();
        return this.f23a;
    }

    @Override // A0.b
    /* JADX INFO: renamed from: n, reason: merged with bridge method [inline-methods] */
    public ULocale d() throws e {
        l();
        ULocale.Builder builder = new ULocale.Builder();
        builder.setLocale(this.f23a);
        builder.clearExtensions();
        return builder.build();
    }

    private g(String str) throws e {
        this.f23a = null;
        this.f24b = null;
        this.f25c = false;
        ULocale.Builder builder = new ULocale.Builder();
        this.f24b = builder;
        try {
            builder.setLanguageTag(str);
            this.f25c = true;
        } catch (RuntimeException e3) {
            throw new e(e3.getMessage());
        }
    }
}
