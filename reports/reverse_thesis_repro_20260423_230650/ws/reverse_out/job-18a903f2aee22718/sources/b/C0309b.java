package b;

import android.content.Intent;
import i2.AbstractC0580h;
import i2.AbstractC0586n;
import i2.D;
import java.util.ArrayList;
import java.util.Map;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: b.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0309b extends AbstractC0308a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f5387a = new a(null);

    /* JADX INFO: renamed from: b.b$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    @Override // b.AbstractC0308a
    /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
    public Map a(int i3, Intent intent) {
        if (i3 != -1) {
            return D.f();
        }
        if (intent == null) {
            return D.f();
        }
        String[] stringArrayExtra = intent.getStringArrayExtra("androidx.activity.result.contract.extra.PERMISSIONS");
        int[] intArrayExtra = intent.getIntArrayExtra("androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS");
        if (intArrayExtra == null || stringArrayExtra == null) {
            return D.f();
        }
        ArrayList arrayList = new ArrayList(intArrayExtra.length);
        for (int i4 : intArrayExtra) {
            arrayList.add(Boolean.valueOf(i4 == 0));
        }
        return D.m(AbstractC0586n.X(AbstractC0580h.m(stringArrayExtra), arrayList));
    }
}
