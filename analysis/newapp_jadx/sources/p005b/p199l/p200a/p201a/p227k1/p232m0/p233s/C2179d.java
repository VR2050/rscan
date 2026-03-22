package p005b.p199l.p200a.p201a.p227k1.p232m0.p233s;

import android.net.Uri;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/* renamed from: b.l.a.a.k1.m0.s.d */
/* loaded from: classes.dex */
public final class C2179d extends AbstractC2181f {

    /* renamed from: d */
    public static final C2179d f5039d = new C2179d("", Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), null, Collections.emptyList(), false, Collections.emptyMap(), Collections.emptyList());

    /* renamed from: e */
    public final List<Uri> f5040e;

    /* renamed from: f */
    public final List<b> f5041f;

    /* renamed from: g */
    public final List<a> f5042g;

    /* renamed from: h */
    public final List<a> f5043h;

    /* renamed from: i */
    public final List<a> f5044i;

    /* renamed from: j */
    public final List<a> f5045j;

    /* renamed from: k */
    @Nullable
    public final Format f5046k;

    /* renamed from: l */
    @Nullable
    public final List<Format> f5047l;

    /* renamed from: m */
    public final Map<String, String> f5048m;

    /* renamed from: n */
    public final List<DrmInitData> f5049n;

    /* renamed from: b.l.a.a.k1.m0.s.d$a */
    public static final class a {

        /* renamed from: a */
        @Nullable
        public final Uri f5050a;

        /* renamed from: b */
        public final Format f5051b;

        /* renamed from: c */
        public final String f5052c;

        public a(@Nullable Uri uri, Format format, String str, String str2) {
            this.f5050a = uri;
            this.f5051b = format;
            this.f5052c = str2;
        }
    }

    /* renamed from: b.l.a.a.k1.m0.s.d$b */
    public static final class b {

        /* renamed from: a */
        public final Uri f5053a;

        /* renamed from: b */
        public final Format f5054b;

        /* renamed from: c */
        @Nullable
        public final String f5055c;

        /* renamed from: d */
        @Nullable
        public final String f5056d;

        /* renamed from: e */
        @Nullable
        public final String f5057e;

        /* renamed from: f */
        @Nullable
        public final String f5058f;

        public b(Uri uri, Format format, @Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable String str4) {
            this.f5053a = uri;
            this.f5054b = format;
            this.f5055c = str;
            this.f5056d = str2;
            this.f5057e = str3;
            this.f5058f = str4;
        }
    }

    public C2179d(String str, List<String> list, List<b> list2, List<a> list3, List<a> list4, List<a> list5, List<a> list6, @Nullable Format format, @Nullable List<Format> list7, boolean z, Map<String, String> map, List<DrmInitData> list8) {
        super(str, list, z);
        ArrayList arrayList = new ArrayList();
        for (int i2 = 0; i2 < list2.size(); i2++) {
            Uri uri = list2.get(i2).f5053a;
            if (!arrayList.contains(uri)) {
                arrayList.add(uri);
            }
        }
        m1977a(list3, arrayList);
        m1977a(list4, arrayList);
        m1977a(list5, arrayList);
        m1977a(list6, arrayList);
        this.f5040e = Collections.unmodifiableList(arrayList);
        this.f5041f = Collections.unmodifiableList(list2);
        this.f5042g = Collections.unmodifiableList(list3);
        this.f5043h = Collections.unmodifiableList(list4);
        this.f5044i = Collections.unmodifiableList(list5);
        this.f5045j = Collections.unmodifiableList(list6);
        this.f5046k = format;
        this.f5047l = list7 != null ? Collections.unmodifiableList(list7) : null;
        this.f5048m = Collections.unmodifiableMap(map);
        this.f5049n = Collections.unmodifiableList(list8);
    }

    /* renamed from: a */
    public static void m1977a(List<a> list, List<Uri> list2) {
        for (int i2 = 0; i2 < list.size(); i2++) {
            Uri uri = list.get(i2).f5050a;
            if (uri != null && !list2.contains(uri)) {
                list2.add(uri);
            }
        }
    }
}
