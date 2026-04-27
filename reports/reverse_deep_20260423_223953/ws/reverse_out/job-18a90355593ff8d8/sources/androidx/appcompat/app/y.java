package androidx.appcompat.app;

import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import android.util.Log;
import java.util.Calendar;

/* JADX INFO: loaded from: classes.dex */
class y {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static y f3275d;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f3276a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final LocationManager f3277b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final a f3278c = new a();

    private static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        boolean f3279a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        long f3280b;

        a() {
        }
    }

    y(Context context, LocationManager locationManager) {
        this.f3276a = context;
        this.f3277b = locationManager;
    }

    static y a(Context context) {
        if (f3275d == null) {
            Context applicationContext = context.getApplicationContext();
            f3275d = new y(applicationContext, (LocationManager) applicationContext.getSystemService("location"));
        }
        return f3275d;
    }

    private Location b() {
        Location locationC = androidx.core.content.e.b(this.f3276a, "android.permission.ACCESS_COARSE_LOCATION") == 0 ? c("network") : null;
        Location locationC2 = androidx.core.content.e.b(this.f3276a, "android.permission.ACCESS_FINE_LOCATION") == 0 ? c("gps") : null;
        return (locationC2 == null || locationC == null) ? locationC2 != null ? locationC2 : locationC : locationC2.getTime() > locationC.getTime() ? locationC2 : locationC;
    }

    private Location c(String str) {
        try {
            if (this.f3277b.isProviderEnabled(str)) {
                return this.f3277b.getLastKnownLocation(str);
            }
            return null;
        } catch (Exception e3) {
            Log.d("TwilightManager", "Failed to get last known location", e3);
            return null;
        }
    }

    private boolean e() {
        return this.f3278c.f3280b > System.currentTimeMillis();
    }

    private void f(Location location) {
        long j3;
        a aVar = this.f3278c;
        long jCurrentTimeMillis = System.currentTimeMillis();
        x xVarB = x.b();
        xVarB.a(jCurrentTimeMillis - 86400000, location.getLatitude(), location.getLongitude());
        xVarB.a(jCurrentTimeMillis, location.getLatitude(), location.getLongitude());
        boolean z3 = xVarB.f3274c == 1;
        long j4 = xVarB.f3273b;
        long j5 = xVarB.f3272a;
        xVarB.a(jCurrentTimeMillis + 86400000, location.getLatitude(), location.getLongitude());
        long j6 = xVarB.f3273b;
        if (j4 == -1 || j5 == -1) {
            j3 = jCurrentTimeMillis + 43200000;
        } else {
            if (jCurrentTimeMillis <= j5) {
                j6 = jCurrentTimeMillis > j4 ? j5 : j4;
            }
            j3 = j6 + 60000;
        }
        aVar.f3279a = z3;
        aVar.f3280b = j3;
    }

    boolean d() {
        a aVar = this.f3278c;
        if (e()) {
            return aVar.f3279a;
        }
        Location locationB = b();
        if (locationB != null) {
            f(locationB);
            return aVar.f3279a;
        }
        Log.i("TwilightManager", "Could not get last known location. This is probably because the app does not have any location permissions. Falling back to hardcoded sunrise/sunset values.");
        int i3 = Calendar.getInstance().get(11);
        return i3 < 6 || i3 >= 22;
    }
}
