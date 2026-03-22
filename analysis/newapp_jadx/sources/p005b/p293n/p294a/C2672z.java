package p005b.p293n.p294a;

import android.app.AlarmManager;
import android.content.Context;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

/* renamed from: b.n.a.z */
/* loaded from: classes2.dex */
public class C2672z extends C2671y {
    @RequiresApi(31)
    /* renamed from: c */
    public static boolean m3164c(@NonNull Context context) {
        return ((AlarmManager) context.getSystemService(AlarmManager.class)).canScheduleExactAlarms();
    }
}
