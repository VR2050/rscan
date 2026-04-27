package androidx.core.app;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import java.util.ArrayList;
import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
public final class n implements Iterable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ArrayList f4256b = new ArrayList();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Context f4257c;

    public interface a {
        Intent o();
    }

    private n(Context context) {
        this.f4257c = context;
    }

    public static n e(Context context) {
        return new n(context);
    }

    public n a(Intent intent) {
        this.f4256b.add(intent);
        return this;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public n b(Activity activity) {
        Intent intentO = activity instanceof a ? ((a) activity).o() : null;
        if (intentO == null) {
            intentO = h.a(activity);
        }
        if (intentO != null) {
            ComponentName component = intentO.getComponent();
            if (component == null) {
                component = intentO.resolveActivity(this.f4257c.getPackageManager());
            }
            c(component);
            a(intentO);
        }
        return this;
    }

    public n c(ComponentName componentName) {
        int size = this.f4256b.size();
        try {
            Intent intentB = h.b(this.f4257c, componentName);
            while (intentB != null) {
                this.f4256b.add(size, intentB);
                intentB = h.b(this.f4257c, intentB.getComponent());
            }
            return this;
        } catch (PackageManager.NameNotFoundException e3) {
            Log.e("TaskStackBuilder", "Bad ComponentName while traversing activity parent metadata");
            throw new IllegalArgumentException(e3);
        }
    }

    public void f() {
        h(null);
    }

    public void h(Bundle bundle) {
        if (this.f4256b.isEmpty()) {
            throw new IllegalStateException("No intents added to TaskStackBuilder; cannot startActivities");
        }
        Intent[] intentArr = (Intent[]) this.f4256b.toArray(new Intent[0]);
        intentArr[0] = new Intent(intentArr[0]).addFlags(268484608);
        if (androidx.core.content.a.g(this.f4257c, intentArr, bundle)) {
            return;
        }
        Intent intent = new Intent(intentArr[intentArr.length - 1]);
        intent.addFlags(268435456);
        this.f4257c.startActivity(intent);
    }

    @Override // java.lang.Iterable
    public Iterator iterator() {
        return this.f4256b.iterator();
    }
}
