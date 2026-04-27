package androidx.activity.result;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import b.AbstractC0308a;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/* JADX INFO: loaded from: classes.dex */
public abstract class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Random f3009a = new Random();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Map f3010b = new HashMap();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final Map f3011c = new HashMap();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Map f3012d = new HashMap();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    ArrayList f3013e = new ArrayList();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    final transient Map f3014f = new HashMap();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    final Map f3015g = new HashMap();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    final Bundle f3016h = new Bundle();

    class a extends c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ String f3017a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ AbstractC0308a f3018b;

        a(String str, AbstractC0308a abstractC0308a) {
            this.f3017a = str;
            this.f3018b = abstractC0308a;
        }

        @Override // androidx.activity.result.c
        public void a() {
            e.this.i(this.f3017a);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final androidx.activity.result.b f3020a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final AbstractC0308a f3021b;

        b(androidx.activity.result.b bVar, AbstractC0308a abstractC0308a) {
            this.f3020a = bVar;
            this.f3021b = abstractC0308a;
        }
    }

    private void a(int i3, String str) {
        this.f3010b.put(Integer.valueOf(i3), str);
        this.f3011c.put(str, Integer.valueOf(i3));
    }

    private void c(String str, int i3, Intent intent, b bVar) {
        if (bVar == null || bVar.f3020a == null || !this.f3013e.contains(str)) {
            this.f3015g.remove(str);
            this.f3016h.putParcelable(str, new androidx.activity.result.a(i3, intent));
        } else {
            bVar.f3020a.a(bVar.f3021b.a(i3, intent));
            this.f3013e.remove(str);
        }
    }

    private int d() {
        int iNextInt = this.f3009a.nextInt(2147418112);
        while (true) {
            int i3 = iNextInt + 65536;
            if (!this.f3010b.containsKey(Integer.valueOf(i3))) {
                return i3;
            }
            iNextInt = this.f3009a.nextInt(2147418112);
        }
    }

    private void h(String str) {
        if (((Integer) this.f3011c.get(str)) != null) {
            return;
        }
        a(d(), str);
    }

    public final boolean b(int i3, int i4, Intent intent) {
        String str = (String) this.f3010b.get(Integer.valueOf(i3));
        if (str == null) {
            return false;
        }
        c(str, i4, intent, (b) this.f3014f.get(str));
        return true;
    }

    public final void e(Bundle bundle) {
        if (bundle == null) {
            return;
        }
        ArrayList<Integer> integerArrayList = bundle.getIntegerArrayList("KEY_COMPONENT_ACTIVITY_REGISTERED_RCS");
        ArrayList<String> stringArrayList = bundle.getStringArrayList("KEY_COMPONENT_ACTIVITY_REGISTERED_KEYS");
        if (stringArrayList == null || integerArrayList == null) {
            return;
        }
        this.f3013e = bundle.getStringArrayList("KEY_COMPONENT_ACTIVITY_LAUNCHED_KEYS");
        this.f3009a = (Random) bundle.getSerializable("KEY_COMPONENT_ACTIVITY_RANDOM_OBJECT");
        this.f3016h.putAll(bundle.getBundle("KEY_COMPONENT_ACTIVITY_PENDING_RESULT"));
        for (int i3 = 0; i3 < stringArrayList.size(); i3++) {
            String str = stringArrayList.get(i3);
            if (this.f3011c.containsKey(str)) {
                Integer num = (Integer) this.f3011c.remove(str);
                if (!this.f3016h.containsKey(str)) {
                    this.f3010b.remove(num);
                }
            }
            a(integerArrayList.get(i3).intValue(), stringArrayList.get(i3));
        }
    }

    public final void f(Bundle bundle) {
        bundle.putIntegerArrayList("KEY_COMPONENT_ACTIVITY_REGISTERED_RCS", new ArrayList<>(this.f3011c.values()));
        bundle.putStringArrayList("KEY_COMPONENT_ACTIVITY_REGISTERED_KEYS", new ArrayList<>(this.f3011c.keySet()));
        bundle.putStringArrayList("KEY_COMPONENT_ACTIVITY_LAUNCHED_KEYS", new ArrayList<>(this.f3013e));
        bundle.putBundle("KEY_COMPONENT_ACTIVITY_PENDING_RESULT", (Bundle) this.f3016h.clone());
        bundle.putSerializable("KEY_COMPONENT_ACTIVITY_RANDOM_OBJECT", this.f3009a);
    }

    public final c g(String str, AbstractC0308a abstractC0308a, androidx.activity.result.b bVar) {
        h(str);
        this.f3014f.put(str, new b(bVar, abstractC0308a));
        if (this.f3015g.containsKey(str)) {
            Object obj = this.f3015g.get(str);
            this.f3015g.remove(str);
            bVar.a(obj);
        }
        androidx.activity.result.a aVar = (androidx.activity.result.a) this.f3016h.getParcelable(str);
        if (aVar != null) {
            this.f3016h.remove(str);
            bVar.a(abstractC0308a.a(aVar.b(), aVar.a()));
        }
        return new a(str, abstractC0308a);
    }

    final void i(String str) {
        Integer num;
        if (!this.f3013e.contains(str) && (num = (Integer) this.f3011c.remove(str)) != null) {
            this.f3010b.remove(num);
        }
        this.f3014f.remove(str);
        if (this.f3015g.containsKey(str)) {
            Log.w("ActivityResultRegistry", "Dropping pending result for request " + str + ": " + this.f3015g.get(str));
            this.f3015g.remove(str);
        }
        if (this.f3016h.containsKey(str)) {
            Log.w("ActivityResultRegistry", "Dropping pending result for request " + str + ": " + this.f3016h.getParcelable(str));
            this.f3016h.remove(str);
        }
        d.a(this.f3012d.get(str));
    }
}
